"""Analise avancada: consultas nfdump com filtro manual sobre os arquivos nfcapd guardados.

Sintaxe de filtro = nfdump (ip/net/port/proto/flags/as/if/bytes/packets/duration...), mais atalhos
do provedor, expandidos a partir da configuracao:

  @rede  @src_rede  @dst_rede        blocos publicos (IPv4 e IPv6)
  @pools @src_pools @dst_pools       pools CGNAT
  @assinantes @src_assinantes @dst_assinantes   rede privada pre-NAT
  @infra                             infraestrutura (roteadores, coletor...)

O filtro vai para o nfdump como UM argumento (sem shell); o nfdump valida a sintaxe.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import fcntl
import io
from ipaddress import ip_address
import os
from pathlib import Path
import re
import subprocess
import time

NFDUMP = os.environ.get("ORBYMON_NFDUMP", "/usr/bin/nfdump")
MAX_EXPR = 4000
MAX_WINDOW = timedelta(hours=24)
MAX_WINDOW_FLOWS = timedelta(hours=6)
SERIES_POINTS = 60
TIME_BUDGET = 45.0

MODES = {   # nome: (rotulo, argumento -s do nfdump ou None para fluxos brutos)
    "dstip": ("IP de destino", "dstip"),
    "srcip": ("IP de origem", "srcip"),
    "ip": ("IP (origem ou destino)", "ip"),
    "dstport": ("Porta de destino", "dstport"),
    "srcport": ("Porta de origem", "srcport"),
    "proto": ("Protocolo", "proto"),
    "srcas": ("AS de origem", "srcas"),
    "dstas": ("AS de destino", "dstas"),
    "inif": ("Interface de entrada", "inif"),
    "outif": ("Interface de saída", "outif"),
    "record": ("Conversas (origem, destino, portas)", "record"),
    "flows": ("Fluxos individuais (maiores)", None),
}
ORDERS = ("bytes", "packets", "flows", "bps", "pps", "bpp")
SERVICES = {20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp", 69: "tftp",
            80: "http", 110: "pop3", 111: "rpcbind", 123: "ntp", 137: "netbios", 143: "imap", 161: "snmp",
            179: "bgp", 389: "ldap/cldap", 443: "https", 445: "smb", 465: "smtps", 500: "ike", 514: "syslog",
            587: "submission", 853: "dns-tls", 993: "imaps", 995: "pop3s", 1194: "openvpn", 1433: "mssql",
            1723: "pptp", 1900: "ssdp", 2323: "telnet-alt", 3306: "mysql", 3389: "rdp", 3478: "stun",
            3702: "ws-discovery", 4500: "ipsec-nat", 5060: "sip", 5353: "mdns", 5900: "vnc", 6379: "redis",
            8080: "http-alt", 8291: "winbox", 8443: "https-alt", 10001: "ubiquiti", 11211: "memcached",
            19: "chargen", 27017: "mongodb"}


class QueryError(ValueError):
    pass


# ------------------------------------------------------------------ atalhos do provedor
def macros(cfg, profile):
    groups = {
        "rede": list(profile["protected_cidrs"]) + list(cfg.get("ipv6_protected_cidrs", [])),
        "pools": list(profile["cgnat_pools"]),
        "assinantes": list(profile.get("inside_private_cidrs", [])),
        "infra": list(cfg.get("extra_infrastructure_cidrs", [])),
    }
    out = {}
    for name, nets in groups.items():
        for prefix, word in (("", "net"), ("src_", "src net"), ("dst_", "dst net")):
            out[prefix + name] = "(" + " or ".join("%s %s" % (word, n) for n in nets) + ")" if nets else None
    return out


def expand(expr: str, table: dict) -> str:
    expr = (expr or "").strip()
    if not expr:
        raise QueryError("informe um filtro (use 'any' para todo o tráfego)")
    if len(expr) > MAX_EXPR or re.search(r"[\x00-\x08\x0a-\x1f\x7f`$\\;|<>]", expr):
        raise QueryError("filtro com caracteres não permitidos ou longo demais")

    def repl(m):
        name = m.group(1).lower()
        if name not in table:
            raise QueryError("atalho desconhecido: @%s (use %s)" % (name, ", ".join("@" + k for k in sorted(table))))
        if table[name] is None:
            raise QueryError("@%s está vazio na configuração (página Rede)" % name)
        return table[name]
    expr = re.sub(r"\bproto\s+(icmpv6|ipv6-icmp)\b", "proto 58", expr, flags=re.I)   # nome usado no OrbyMon
    return re.sub(r"@([A-Za-z_]+)", repl, expr)


# ------------------------------------------------------------------ arquivos
def select_files(flow_dir, start: datetime, end: datetime, slack=60):
    """Arquivos nfcapd fechados dentro de [start, end] (pela data de modificacao = fim do intervalo)."""
    t0 = start.replace(tzinfo=timezone.utc).timestamp()
    t1 = end.replace(tzinfo=timezone.utc).timestamp() + slack
    files = []
    with os.scandir(flow_dir) as it:
        for e in it:
            if e.name.startswith("nfcapd.20") and e.name[7:].isdigit() and e.is_file():
                m = e.stat().st_mtime
                if t0 <= m <= t1:
                    files.append(e.name)
    return sorted(files)


def chunks(items, n):
    if not items:
        return []
    size = max(1, -(-len(items) // n))
    return [items[i:i + size] for i in range(0, len(items), size)]


# ------------------------------------------------------------------ execucao
@dataclass
class Result:
    mode: str
    order: str
    expr: str
    expanded: str
    start: datetime
    end: datetime
    files: int
    columns: list = field(default_factory=list)
    rows: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    series: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    elapsed: float = 0.0


def _run(args, timeout):
    env = {"TZ": "UTC", "PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    try:
        cp = subprocess.run(["nice", "-n", "10", NFDUMP] + args, capture_output=True, text=True,
                            timeout=max(1.0, timeout), env=env)
    except subprocess.TimeoutExpired:
        raise QueryError("consulta passou do tempo limite: reduza o período ou deixe o filtro mais específico")
    except FileNotFoundError:
        raise QueryError("nfdump não encontrado em %s" % NFDUMP)
    if cp.returncode != 0:
        msg = (cp.stderr or cp.stdout).strip().splitlines()
        raise QueryError("nfdump: " + (msg[0] if msg else "erro %d" % cp.returncode)[:300])
    return cp.stdout


def _csv_blocks(text):
    """Separa a saida CSV do nfdump em (linhas_de_dados, resumo)."""
    data, summary = [], {}
    lines = [l for l in text.splitlines() if l.strip() and l.strip() != "No matching flows"]
    if "Summary" in lines:
        i = lines.index("Summary")
        if i + 2 < len(lines) + 1 and len(lines) > i + 2:
            keys, vals = lines[i + 1].split(","), lines[i + 2].split(",")
            summary = dict(zip(keys, vals))
        lines = lines[:i]
    if lines:
        data = list(csv.DictReader(io.StringIO("\n".join(lines))))
    return data, summary


def _num(row, *keys):
    for k in keys:
        v = row.get(k)
        if v not in (None, ""):
            try:
                return float(v.strip())
            except ValueError:
                pass
    return 0.0


def run(expr, start, end, mode, order, limit, flow_dir, table, lock_path=None, budget=TIME_BUDGET):
    if mode not in MODES:
        raise QueryError("tipo de análise inválido")
    if order not in ORDERS:
        raise QueryError("ordenação inválida")
    limit = int(limit)
    if not 1 <= limit <= 500:
        raise QueryError("quantidade entre 1 e 500")
    if end <= start:
        raise QueryError("o fim do período deve ser depois do início")
    max_window = MAX_WINDOW_FLOWS if mode == "flows" else MAX_WINDOW
    if end - start > max_window:
        raise QueryError("período máximo: %d h para este tipo de análise" % (max_window.total_seconds() // 3600))
    expanded = expand(expr, table)
    flow_dir = Path(flow_dir)
    files = select_files(flow_dir, start, end)
    res = Result(mode, order, expr, expanded, start, end, len(files))
    if not files:
        res.notes.append("Nenhum arquivo de fluxo no período (retenção ou coletor parado).")
        return res
    lock = None
    if lock_path:
        lock = open(lock_path, "a")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            lock.close()
            raise QueryError("outra análise está em andamento; tente em alguns segundos")
    t0 = time.monotonic()
    try:
        rng = ["-R", "%s/%s:%s" % (flow_dir, files[0], files[-1])]
        left = lambda: budget - (time.monotonic() - t0)
        if mode == "flows":
            out = _run(rng + ["-o", "csv", "-O", order if order in ("bytes", "packets", "flows") else "bytes",
                              "-c", str(limit), expanded], left())
            rows, res.summary = _csv_blocks(out)
            res.columns = ["Início", "Origem", "Porta orig.", "Destino", "Porta dest.", "Proto", "Flags",
                           "Pacotes", "Bytes", "Entrada", "Saída", "AS orig.", "AS dest."]
            for r in rows[:limit]:
                res.rows.append({"Início": r.get("ts", ""), "Origem": r.get("sa", ""), "Porta orig.": r.get("sp", ""),
                                 "Destino": r.get("da", ""), "Porta dest.": r.get("dp", ""), "Proto": r.get("pr", "").lower(),
                                 "Flags": r.get("flg", "").replace(".", ""), "Pacotes": _num(r, "ipkt"),
                                 "Bytes": _num(r, "ibyt"), "Entrada": r.get("in", ""), "Saída": r.get("out", ""),
                                 "AS orig.": r.get("sas", ""), "AS dest.": r.get("das", "")})
        else:
            stat = MODES[mode][1]
            out = _run(rng + ["-o", "csv", "-s", "%s/%s" % (stat, order), "-n", str(limit), expanded], left())
            rows, res.summary = _csv_blocks(out)
            if mode == "record":
                res.columns = ["Origem", "Porta orig.", "Destino", "Porta dest.", "Proto", "Flags",
                               "Pacotes", "Bytes", "Entrada", "Saída"]
                for r in rows[:limit]:
                    res.rows.append({"Origem": r.get("sa", ""), "Porta orig.": r.get("sp", ""), "Destino": r.get("da", ""),
                                     "Porta dest.": r.get("dp", ""), "Proto": r.get("pr", "").lower(),
                                     "Flags": r.get("flg", "").replace(".", ""), "Pacotes": _num(r, "ipkt"),
                                     "Bytes": _num(r, "ibyt"), "Entrada": r.get("in", ""), "Saída": r.get("out", "")})
            else:
                res.columns = [MODES[mode][0], "Fluxos", "% fluxos", "Pacotes", "% pacotes", "Bytes", "% bytes",
                               "pps", "bps", "bytes/pacote"]
                for r in rows[:limit]:
                    res.rows.append({MODES[mode][0]: r.get("val", "").strip(), "Fluxos": _num(r, "fl"),
                                     "% fluxos": _num(r, "flP"), "Pacotes": _num(r, "pkt", "ipkt"),
                                     "% pacotes": _num(r, "pktP", "ipktP"), "Bytes": _num(r, "byt", "ibyt"),
                                     "% bytes": _num(r, "bytP", "ibytP"), "pps": _num(r, "pps", "ipps"),
                                     "bps": _num(r, "bps", "ibps"), "bytes/pacote": _num(r, "bpp", "ibpp")})
        # serie temporal: total do filtro em ate SERIES_POINTS fatias
        for part in chunks(files, SERIES_POINTS):
            if left() < 3:
                res.notes.append("Gráfico parcial: tempo limite atingido.")
                break
            out = _run(["-R", "%s/%s:%s" % (flow_dir, part[0], part[-1]), "-o", "csv", "-s", "proto/bytes",
                        "-n", "0", expanded], left())
            _, summ = _csv_blocks(out)
            p0 = (flow_dir / part[0]).stat().st_mtime - 30
            p1 = (flow_dir / part[-1]).stat().st_mtime
            secs = max(30.0, p1 - p0)
            res.series.append({"t": datetime.fromtimestamp(p1, timezone.utc).replace(tzinfo=None),
                               "bps": _num(summ, "bytes") * 8 / secs, "pps": _num(summ, "packets") / secs,
                               "flows": _num(summ, "flows")})
    finally:
        if lock:
            fcntl.flock(lock, fcntl.LOCK_UN)
            lock.close()
    res.elapsed = time.monotonic() - t0
    return res


# ------------------------------------------------------------------ apresentacao
def annotate(res, scopes=None, ifnames=None):
    """Acrescenta rotulos (tipo do IP, nome da interface, servico da porta) as linhas."""
    ifnames = ifnames or {}
    for row in res.rows:
        tags = {}
        for col, val in row.items():
            if not isinstance(val, str) or not val:
                continue
            if col in ("Entrada", "Saída", "Interface de entrada", "Interface de saída") and val.isdigit():
                name = ifnames.get(int(val))
                if name:
                    tags[col] = name
            elif col.startswith("Porta") and val.isdigit():
                svc = SERVICES.get(int(val))
                if svc:
                    tags[col] = svc
            elif scopes is not None and col in ("Origem", "Destino", "IP de destino", "IP de origem",
                                                 "IP (origem ou destino)"):
                try:
                    ip_address(val)
                except ValueError:
                    continue
                scope, pool, _ = scopes.classify(val)
                label = {"cgnat_pool": "pool " + pool, "dedicated": "dedicado", "cgnat_private": "assinante",
                         "infra": "infra"}.get(scope)
                if label:
                    tags[col] = label
        row["_tags"] = tags
    return res


def svg_series(series, key="bps", width=900, height=180):
    """Grafico de linha em SVG (sem JavaScript) para a pagina."""
    pts = [s[key] for s in series]
    if len(pts) < 2:
        return ""
    top = max(pts) or 1.0
    step = width / (len(pts) - 1)
    coords = " ".join("%.1f,%.1f" % (i * step, height - 10 - (v / top) * (height - 30)) for i, v in enumerate(pts))
    area = "0,%d %s %.1f,%d" % (height - 10, coords, (len(pts) - 1) * step, height - 10)
    label = human(top, "bps" if key == "bps" else "pps")
    first, last = series[0]["t"].strftime("%H:%M"), series[-1]["t"].strftime("%H:%M")
    return ('<svg class="chart" viewBox="0 0 %d %d" role="img" aria-label="Tráfego do filtro no período">'
            '<polygon points="%s" class="area"/><polyline points="%s" class="line"/>'
            '<text x="4" y="14" class="lbl">pico %s</text>'
            '<text x="4" y="%d" class="lbl">%s UTC</text><text x="%d" y="%d" class="lbl" text-anchor="end">%s UTC</text>'
            '</svg>') % (width, height, area, coords, label, height - 1, first, width - 4, height - 1, last)


def human(v, unit):
    v = float(v or 0)
    for factor, prefix in ((1e9, "G"), (1e6, "M"), (1e3, "k")):
        if abs(v) >= factor:
            return "%.2f %s%s" % (v / factor, prefix, unit)
    return "%.0f %s" % (v, unit)
