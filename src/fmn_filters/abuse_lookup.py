"""Investigacao de denuncias de abuso (etapa 2): IP publico + horario (+ porta) -> assinante.

Fontes, da mais forte para a mais fraca:
  1. log NAT do A10 (nat-events-AAAAMMDDHH.tsv[.gz], sem amostragem, guardado N dias): com a PORTA
     de origem citada na denuncia o assinante e identificado com certeza; sem a porta, lista quem
     usou aquele IP publico no horario (ate ~32 assinantes por IP);
  2. fluxos de saida (orby_flow_minute, 2 dias, NetFlow amostrado 1:2048): quem falou com o destino
     ou a porta da denuncia;
  3. eventos de ataque originados (orby_attack_events).

Tambem extrai IP/horario/porta de um e-mail de abuso colado (fail2ban, iptables, X-ARF, Apache...).

CLI: python -m fmn_filters.abuse_lookup --config /etc/orbymon/bidir.json --ip 45.238.170.70 \
       --time "2026-10-30 14:05:00" --tz America/Sao_Paulo [--port 51234] [--remote 1.2.3.4] [--remote-port 22]
     python -m fmn_filters.abuse_lookup --config ... --email denuncia.txt --tz UTC
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import gzip
from ipaddress import ip_address
import os
from pathlib import Path
import re
import sys
from zoneinfo import ZoneInfo

NAT_DIR = "/var/log/orbymon/a10nat"
MONTHS = {m: i for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}
MONTHS.update({"fev": 2, "abr": 4, "mai": 5, "ago": 8, "set": 9, "out": 10, "dez": 12})
MAX_REPORTS = 30
TCP_SERVICES = {21, 22, 23, 25, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443}


# ------------------------------------------------------------------ log NAT
def nat_files(directory, start: datetime, end: datetime):
    """Arquivos horarios que cobrem [start, end] (UTC ingenuo). Devolve (existentes, horas_faltando)."""
    directory = Path(directory)
    hour = start.replace(minute=0, second=0, microsecond=0)
    found, missing = [], []
    while hour <= end:
        stem = "nat-events-%s.tsv" % hour.strftime("%Y%m%d%H")
        for name in (stem, stem + ".gz"):
            if (directory / name).exists():
                found.append(directory / name)
                break
        else:
            missing.append(hour)
        hour += timedelta(hours=1)
    return found, missing


def _open(path: Path):
    return gzip.open(path, "rt", encoding="utf-8", errors="replace") if path.suffix == ".gz" else \
        path.open("r", encoding="utf-8", errors="replace")


@dataclass
class Mapping:
    inside_ip: str
    inside_port: int
    protocol: str
    public_ip: str
    public_port: int
    start: float | None          # None = alocacao antes do periodo lido
    end: float | None            # None = ainda ativo / liberacao depois do periodo lido

    def covers(self, ts: float, slack=0.0):
        return (self.start is None or self.start <= ts + slack) and (self.end is None or self.end >= ts - slack)


def nat_mappings(directory, public_ip, start: datetime, end: datetime, port=None, protocol=None,
                 lookback=timedelta(hours=6), lookahead=timedelta(hours=2)):
    """Mapeamentos (assinante <-> IP:porta publicos) ativos em algum momento de [start, end].

    Le de start-lookback ate end+lookahead para achar a alocacao e a liberacao de cada porta.
    """
    files, missing = nat_files(directory, start - lookback, end + lookahead)
    needle = "\t%s\t%d\t" % (public_ip, port) if port is not None else "\t%s\t" % public_ip
    events = {}
    for path in files:
        with _open(path) as fh:
            for line in fh:
                if needle not in line:
                    continue
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 7 or parts[5] != public_ip:
                    continue
                proto = parts[2]
                if protocol and proto != protocol:
                    continue
                try:
                    events.setdefault((proto, int(parts[6])), []).append(
                        (float(parts[0]), parts[1], parts[3], int(parts[4])))
                except ValueError:
                    continue
    t0, t1 = start.replace(tzinfo=timezone.utc).timestamp(), end.replace(tzinfo=timezone.utc).timestamp()
    out = []
    for (proto, pub_port), evs in events.items():
        evs.sort()
        open_ = None
        for ts, kind, inside, in_port in evs:
            if kind == "a":
                if open_:
                    out.append(Mapping(open_[1], open_[2], proto, public_ip, pub_port, open_[0], ts))
                open_ = (ts, inside, in_port)
            else:
                if open_ and open_[1] == inside:
                    out.append(Mapping(inside, in_port, proto, public_ip, pub_port, open_[0], ts))
                    open_ = None
                else:                                   # liberacao sem alocacao vista (antes do periodo lido)
                    out.append(Mapping(inside, in_port, proto, public_ip, pub_port, None, ts))
        if open_:
            out.append(Mapping(open_[1], open_[2], proto, public_ip, pub_port, open_[0], None))
    hits = [m for m in out if (m.start is None or m.start <= t1) and (m.end is None or m.end >= t0)]
    hits.sort(key=lambda m: (m.start or 0))
    missing_in_window = [h for h in missing if start - timedelta(hours=1) < h <= end]
    return hits, missing_in_window, len(files)


def summarize_by_subscriber(mappings):
    by = {}
    for m in mappings:
        s = by.setdefault(m.inside_ip, {"ip": m.inside_ip, "portas": 0, "protocolos": set(), "inicio": None, "fim": None})
        s["portas"] += 1
        s["protocolos"].add(m.protocol)
        if m.start is not None:
            s["inicio"] = m.start if s["inicio"] is None else min(s["inicio"], m.start)
        if m.end is not None:
            s["fim"] = m.end if s["fim"] is None else max(s["fim"], m.end)
    rows = sorted(by.values(), key=lambda s: -s["portas"])
    for s in rows:
        s["protocolos"] = ",".join(sorted(s["protocolos"]))
    return rows


# ------------------------------------------------------------------ banco
def flow_evidence(cur, source, ip, scope, start, end, remote=None, remote_port=None, limit=40):
    where = ["source=%s", "direction='out'", "bucket_utc BETWEEN %s AND %s"]
    params = [source, start.replace(second=0) - timedelta(minutes=1), end + timedelta(minutes=1)]
    if scope == "cgnat_private":
        where.append("subscriber_ip=%s")
    else:
        where.append("local_ip=%s")
    params.append(ip)
    if remote:
        where.append("remote_ip=%s")
        params.append(remote)
    if remote_port is not None:
        where.append("remote_port=%s")
        params.append(remote_port)
    cur.execute("SELECT subscriber_ip,local_ip,remote_ip,remote_port,protocol,SUM(flows),SUM(packets),SUM(bytes),"
                "MIN(bucket_utc),MAX(bucket_utc) FROM orby_flow_minute WHERE " + " AND ".join(where) +
                " GROUP BY subscriber_ip,local_ip,remote_ip,remote_port,protocol ORDER BY SUM(packets) DESC LIMIT %s",
                params + [limit])
    return [{"assinante": r[0], "ip_publico": r[1], "remoto": r[2], "porta_remota": r[3], "protocolo": r[4],
             "fluxos": int(r[5] or 0), "pacotes": float(r[6] or 0), "bytes": float(r[7] or 0),
             "de": r[8], "ate": r[9]} for r in cur.fetchall()]


def event_evidence(cur, ip, start, end, limit=30):
    cur.execute("SELECT event_time,rule_name,severity,direction,local_ip,subscriber_ip,protocol,remote_port,pps,mbps "
                "FROM orby_attack_events WHERE (local_ip=%s OR subscriber_ip=%s) AND event_time BETWEEN %s AND %s "
                "ORDER BY event_time LIMIT %s", (ip, ip, start - timedelta(hours=1), end + timedelta(hours=1), limit))
    return [{"hora": r[0], "regra": r[1], "severidade": r[2], "sentido": r[3], "ip_publico": r[4],
             "assinante": r[5], "protocolo": r[6], "porta_remota": r[7], "pps": r[8], "mbps": r[9]}
            for r in cur.fetchall()]


def flow_retention(cur, source):
    cur.execute("SELECT MIN(bucket_utc) FROM orby_flow_minute WHERE source=%s", (source,))
    row = cur.fetchone()
    return row[0] if row else None


# ------------------------------------------------------------------ investigacao
@dataclass
class Query:
    ip: str
    when: datetime                 # UTC ingenuo
    window_min: int = 10
    port: int | None = None        # porta de ORIGEM publica citada na denuncia
    protocol: str | None = None
    remote: str | None = None
    remote_port: int | None = None
    line: str = ""                 # trecho da denuncia (quando extraido de e-mail)


@dataclass
class Result:
    query: Query
    scope: str
    pool: str
    verdict: str
    confidence: str                # alta | media | baixa | nenhuma
    subscribers: list = field(default_factory=list)
    mappings: list = field(default_factory=list)
    flows: list = field(default_factory=list)
    events: list = field(default_factory=list)
    notes: list = field(default_factory=list)


def investigate(q: Query, scopes, source="huawei", db=None, nat_dir=NAT_DIR, max_mappings=200):
    scope, pool, _ = scopes.classify(q.ip)
    r = Result(q, scope, pool, "", "nenhuma")
    start, end = q.when - timedelta(minutes=q.window_min), q.when + timedelta(minutes=q.window_min)
    ts = q.when.replace(tzinfo=timezone.utc).timestamp()
    if scope == "external":
        r.verdict = "%s não pertence aos blocos deste provedor." % q.ip
        return r
    cur = db.cursor() if db is not None else None
    if scope == "cgnat_pool":
        maps, missing, nfiles = nat_mappings(nat_dir, q.ip, start, end, q.port, q.protocol)
        if missing:
            r.notes.append("Log NAT ausente para %s UTC (fora da retenção ou receptor parado)." %
                           ", ".join(h.strftime("%d/%m %Hh") for h in missing[:6]))
        if nfiles == 0:
            r.notes.append("Nenhum arquivo de log NAT encontrado para o período em %s." % nat_dir)
        r.mappings = maps[:max_mappings]
        if q.port is not None:
            proto = q.protocol or ("tcp" if q.remote_port in TCP_SERVICES else None)
            if proto:
                maps = [m for m in maps if m.protocol == proto]       # ex.: denuncia de SSH -> so TCP
                r.mappings = maps[:max_mappings]
            exact = [m for m in maps if m.covers(ts)]
            near = [m for m in maps if m not in exact]
            subs = sorted({m.inside_ip for m in exact})
            if len(subs) == 1:
                r.verdict = "Assinante identificado: %s (porta pública %s:%d no horário da denúncia)." % (subs[0], q.ip, q.port)
                r.confidence = "alta"
            elif len(subs) > 1:
                r.verdict = "A porta %d foi usada por %d assinantes no mesmo instante (verifique o protocolo): %s." % (
                    q.port, len(subs), ", ".join(subs))
                r.confidence = "media"
            elif near:
                subs = sorted({m.inside_ip for m in near})
                r.verdict = ("Nenhum mapeamento cobre exatamente o horário; perto dele a porta %d foi usada por %s. "
                             "Confira o fuso horário da denúncia." % (q.port, ", ".join(subs)))
                r.confidence = "media" if len(subs) == 1 else "baixa"
            else:
                r.verdict = "Nenhum uso da porta %d no IP %s na janela de ±%d min." % (q.port, q.ip, q.window_min)
            r.subscribers = [{"ip": s, "portas": sum(1 for m in maps if m.inside_ip == s)} for s in subs]
        else:
            r.subscribers = summarize_by_subscriber([m for m in maps if m.covers(ts, q.window_min * 60)])
            if r.subscribers:
                r.verdict = ("%d assinante(s) usaram %s na janela de ±%d min. Sem a porta de origem não dá para "
                             "afirmar qual; peça a porta ao denunciante ou veja os fluxos abaixo." % (
                                 len(r.subscribers), q.ip, q.window_min))
                r.confidence = "baixa"
            else:
                r.verdict = "Nenhum assinante mapeado em %s na janela." % q.ip
        if cur is not None:
            r.flows = flow_evidence(cur, source, q.ip, scope, start, end, q.remote, q.remote_port)
            if q.remote_port is not None and not r.flows:
                r.flows = flow_evidence(cur, source, q.ip, scope, start, end, q.remote, None)
            flow_subs = sorted({f["assinante"] for f in r.flows if f["assinante"] and (q.remote or q.remote_port is not None)})
            if r.confidence in ("baixa", "nenhuma") and len(flow_subs) == 1:
                r.verdict += " Pelos fluxos, o assinante que falou com o destino da denúncia foi %s." % flow_subs[0]
                r.confidence = "media"
    elif scope == "cgnat_private":
        r.verdict = "%s é IP privado de assinante: a denúncia normalmente cita o IP público do pool." % q.ip
        r.confidence = "alta"
        if cur is not None:
            r.flows = flow_evidence(cur, source, q.ip, scope, start, end, q.remote, q.remote_port)
    else:
        label = {"dedicated": "IP dedicado", "infra": "infraestrutura do provedor"}.get(scope, scope)
        r.verdict = "%s é %s: o responsável é o cliente/equipamento que usa este IP." % (q.ip, label)
        r.confidence = "alta"
        if cur is not None:
            r.flows = flow_evidence(cur, source, q.ip, scope, start, end, q.remote, q.remote_port)
    if cur is not None:
        r.events = event_evidence(cur, q.ip, start, end)
        oldest = flow_retention(cur, source)
        if oldest and start < oldest:
            r.notes.append("Fluxos guardados só desde %s UTC (rollup de 2 dias); evidência de fluxo pode faltar." % oldest)
    if not r.flows and cur is not None and scope != "external":
        r.notes.append("Sem fluxos amostrados no período: o NetFlow 1:2048 não vê tráfego pequeno (poucas tentativas de "
                       "login, poucos e-mails). O log NAT continua valendo.")
    return r


def ip_history(cur, ip, scope, source="huawei", days=7):
    """Historico de um IP (publico ou privado) para atender cliente ou denuncia sem horario."""
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)
    out = {"ip": ip, "scope": scope, "dias": days}
    cur.execute("SELECT direction,rule_name,COUNT(*),MIN(event_time),MAX(event_time),MAX(pps),MAX(mbps),"
                "GROUP_CONCAT(DISTINCT IF(subscriber_ip='',local_ip,subscriber_ip) SEPARATOR ', ') "
                "FROM orby_attack_events WHERE (local_ip=%s OR subscriber_ip=%s) AND event_time>=%s "
                "GROUP BY direction,rule_name ORDER BY COUNT(*) DESC LIMIT 50", (ip, ip, since))
    out["eventos"] = [{"sentido": r[0], "regra": r[1], "quantidade": r[2], "primeiro": r[3], "ultimo": r[4],
                       "pps": r[5], "mbps": r[6], "ips": (r[7] or "")[:300]} for r in cur.fetchall()]
    try:
        cur.execute("SELECT entry,source_label,category,first_seen,last_seen,removed_at FROM orby_reputation_listings "
                    "WHERE entry=%s ORDER BY removed_at IS NULL DESC,last_seen DESC LIMIT 50", (ip,))
        out["listas"] = [{"lista": r[1], "categoria": r[2], "desde": r[3], "visto": r[4], "saiu": r[5]}
                         for r in cur.fetchall()]
    except Exception:                                       # tabela da etapa 2 ainda nao criada
        out["listas"] = []
    col = "subscriber_ip" if scope == "cgnat_private" else "local_ip"
    cur.execute("SELECT remote_port,protocol,COUNT(DISTINCT remote_ip),SUM(flows),SUM(packets),SUM(bytes) "
                "FROM orby_flow_minute WHERE source=%s AND direction='out' AND " + col + "=%s "
                "AND bucket_utc>=UTC_TIMESTAMP()-INTERVAL 2 DAY GROUP BY remote_port,protocol "
                "ORDER BY COUNT(DISTINCT remote_ip) DESC LIMIT 15", (source, ip))
    out["saida_por_porta"] = [{"porta": r[0], "protocolo": r[1], "destinos": r[2], "fluxos": int(r[3] or 0),
                               "pacotes": float(r[4] or 0), "bytes": float(r[5] or 0)} for r in cur.fetchall()]
    if scope == "cgnat_pool":
        cur.execute("SELECT subscriber_ip,COUNT(DISTINCT remote_ip),SUM(flows),SUM(bytes) FROM orby_flow_minute "
                    "WHERE source=%s AND direction='out' AND local_ip=%s AND subscriber_ip<>'' "
                    "AND bucket_utc>=UTC_TIMESTAMP()-INTERVAL 2 DAY GROUP BY subscriber_ip "
                    "ORDER BY COUNT(DISTINCT remote_ip) DESC LIMIT 40", (source, ip))
        out["assinantes"] = [{"ip": r[0], "destinos": r[1], "fluxos": int(r[2] or 0), "bytes": float(r[3] or 0)}
                             for r in cur.fetchall()]
    elif scope == "cgnat_private":
        cur.execute("SELECT local_ip,MIN(bucket_utc),MAX(bucket_utc) FROM orby_flow_minute WHERE source=%s "
                    "AND subscriber_ip=%s AND bucket_utc>=UTC_TIMESTAMP()-INTERVAL 2 DAY GROUP BY local_ip LIMIT 20",
                    (source, ip))
        out["ips_publicos"] = [{"ip": r[0], "de": r[1], "ate": r[2]} for r in cur.fetchall()]
    return out


# ------------------------------------------------------------------ extracao de denuncias
IPV4 = r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])"
TS_PATTERNS = (
    ("iso", re.compile(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,]\d+)?\s*(Z|UTC|GMT|[+-]\d{2}:?\d{2})?")),
    ("apache", re.compile(r"(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?")),
    ("rfc2822", re.compile(r"(?:[A-Za-z]{3},\s*)?(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4}|UTC|GMT)?")),
    ("br", re.compile(r"(\d{2})/(\d{2})/(\d{4})\s+(\d{2}):(\d{2})(?::(\d{2}))?")),
    ("syslog", re.compile(r"\b([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\b")),
)


def _tz(token, default_tz):
    if not token or token in ("UTC", "GMT", "Z"):
        return timezone.utc if token else default_tz
    sign = 1 if token[0] == "+" else -1
    digits = token[1:].replace(":", "")
    return timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:4] or 0)))


def parse_time(text, default_tz, year=None):
    """Primeiro horario reconhecido no texto -> datetime UTC ingenuo, ou None."""
    for kind, rx in TS_PATTERNS:
        m = rx.search(text)
        if not m:
            continue
        g = m.groups()
        try:
            if kind == "iso":
                dt = datetime(int(g[0]), int(g[1]), int(g[2]), int(g[3]), int(g[4]), int(g[5]), tzinfo=_tz(g[6], default_tz))
            elif kind in ("apache", "rfc2822"):
                mon = MONTHS.get(g[1].lower())
                if not mon:
                    continue
                dt = datetime(int(g[2]), mon, int(g[0]), int(g[3]), int(g[4]), int(g[5]), tzinfo=_tz(g[6], default_tz))
            elif kind == "br":
                dt = datetime(int(g[2]), int(g[1]), int(g[0]), int(g[3]), int(g[4]), int(g[5] or 0), tzinfo=default_tz)
            else:
                mon = MONTHS.get(g[0].lower())
                if not mon:
                    continue
                dt = datetime(year or datetime.now(timezone.utc).year, mon, int(g[1]), int(g[2]), int(g[3]), int(g[4]),
                              tzinfo=default_tz)
        except ValueError:
            continue
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return None


def _port_near(line, ip):
    e = re.escape(ip)
    for rx in (e + r":(\d{1,5})\b", e + r"\]?\s*(?:port|porta)\s*:?\s*(\d{1,5})", e + r"\s*\((?:port|porta)\s*(\d{1,5})\)",
               e + r"\s+\S*\s*(?:source|src)[\s_-]*port\W+(\d{1,5})"):
        m = re.search(rx, line, re.I)
        if m:
            return int(m.group(1))
    if re.search(r"SRC=" + e + r"\b", line):
        m = re.search(r"\bSPT=(\d{1,5})", line)
        if m:
            return int(m.group(1))
    m = re.search(r"(?:source|src)[\s_-]*port\W+(\d{1,5})", line, re.I)
    return int(m.group(1)) if m else None


def _remote_near(line, ip, ours):
    m = re.search(r"\bDST=" + IPV4, line)
    remote = m.group(1) if m else None
    if not remote:
        for cand in re.findall(IPV4, line):
            if cand != ip and not ours(cand):
                try:
                    if ip_address(cand).is_global:
                        remote = cand
                        break
                except ValueError:
                    pass
    port = None
    m = re.search(r"\bDPT=(\d{1,5})", line) or re.search(r"(?:destination|dst)[\s_-]*port\W+(\d{1,5})", line, re.I)
    if m:
        port = int(m.group(1))
    elif re.search(r"\bsshd\[|\bssh2\b", line):
        port = 22
    elif re.search(r"\b(postfix|smtp|exim)\b", line, re.I):
        port = 25
    return remote, port


def extract_reports(text, scopes, default_tz=timezone.utc, window_min=10):
    """Denuncias (IP do provedor + horario + portas) encontradas num e-mail/relatorio colado."""
    ours = lambda ip: scopes.classify(ip)[0] not in ("external",)
    lines = text.splitlines()
    header_time = None
    year = None
    for line in lines[:80]:
        if line.lower().startswith(("date:", "data:", "sent:", "enviado")):
            header_time = parse_time(line, default_tz)
            if header_time:
                year = header_time.year
                break
    out, seen = [], set()
    last_time = None
    for i, line in enumerate(lines):
        t = parse_time(line, default_tz, year)
        if t:
            last_time = t
        if re.match(r"\s*(subject|assunto|from|to|de|para|cc|reply-to|return-path|received)\s*:", line, re.I):
            continue                                    # cabecalho do e-mail: so o corpo tem a ocorrencia
        for ip in re.findall(IPV4, line):
            try:
                ip_address(ip)
            except ValueError:
                continue
            if not ours(ip):
                continue
            when = t or last_time or header_time
            if when is None:
                for nxt in lines[i + 1:i + 4]:          # horario na linha seguinte (tabelas)
                    when = parse_time(nxt, default_tz, year)
                    if when:
                        break
            if when is None:
                continue
            port = _port_near(line, ip)
            remote, rport = _remote_near(line, ip, ours)
            key = (ip, when, port, remote, rport)
            if key in seen:
                continue
            seen.add(key)
            out.append(Query(ip, when, window_min, port, None, remote, rport, line.strip()[:300]))
            if len(out) >= MAX_REPORTS:
                return out
    return out


# ------------------------------------------------------------------ texto
def fmt_ts(value, tz=timezone.utc):
    if value is None:
        return "?"
    if isinstance(value, (int, float)):
        value = datetime.fromtimestamp(value, timezone.utc)
    elif value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(tz).strftime("%d/%m/%Y %H:%M:%S")


def identify_result(r: Result, identify, limit=60):
    """Login PPPoE / cliente de cada assinante (e do IP denunciado, quando dedicado)."""
    if not identify:
        return r
    for s in r.subscribers[:limit]:
        s["identificacao"] = identify(s["ip"], r.query.when) or ""
    if r.scope not in ("cgnat_pool",):
        who = identify(r.query.ip, r.query.when)
        if who:
            r.notes.insert(0, "Identificação de %s: %s" % (r.query.ip, who))
    return r


def render_text(r: Result, tz=timezone.utc):
    q = r.query
    zone = getattr(tz, "key", "UTC")
    lines = ["Denúncia: %s às %s (%s)%s%s%s" % (
        q.ip, fmt_ts(q.when, tz), zone, " porta de origem %d" % q.port if q.port is not None else "",
        " destino %s" % q.remote if q.remote else "", ":%d" % q.remote_port if q.remote_port is not None else "")]
    lines.append("Tipo do IP: %s%s" % (r.scope, " (%s)" % r.pool if r.pool else ""))
    lines.append("Resultado [%s]: %s" % (r.confidence, r.verdict))
    if q.port is not None and r.subscribers:
        for s in r.subscribers:
            if s.get("identificacao"):
                lines.append("  assinante %s: %s" % (s["ip"], s["identificacao"]))
    for m in r.mappings[:20]:
        if q.port is not None or len(r.mappings) <= 20:
            lines.append("  NAT %s %s:%d <- %s:%d  de %s até %s" % (
                m.protocol, m.public_ip, m.public_port, m.inside_ip, m.inside_port, fmt_ts(m.start, tz), fmt_ts(m.end, tz)))
    if q.port is None and r.subscribers:
        for s in r.subscribers[:40]:
            lines.append("  assinante %-16s %4d porta(s) %s  %s - %s%s" % (
                s["ip"], s["portas"], s.get("protocolos", ""), fmt_ts(s.get("inicio"), tz), fmt_ts(s.get("fim"), tz),
                ("  [%s]" % s["identificacao"]) if s.get("identificacao") else ""))
    for f in r.flows[:15]:
        lines.append("  fluxo %s -> %s:%s %s  %d fluxos  %s a %s" % (
            f["assinante"] or f["ip_publico"], f["remoto"], f["porta_remota"], f["protocolo"], f["fluxos"],
            fmt_ts(f["de"], tz), fmt_ts(f["ate"], tz)))
    for e in r.events[:10]:
        lines.append("  evento %s %s %s %s" % (fmt_ts(e["hora"], tz), e["regra"], e["assinante"] or e["ip_publico"], e["severidade"]))
    for n in r.notes:
        lines.append("Obs.: " + n)
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="OrbyMon: investigar denúncia de abuso (IP + horário -> assinante)")
    ap.add_argument("--config", default="/etc/orbymon/bidir.json")
    ap.add_argument("--ip")
    ap.add_argument("--time", help="horário da denúncia (ex.: 2026-10-30 14:05:00, ou ISO com fuso)")
    ap.add_argument("--tz", default="UTC", help="fuso de horários sem fuso explícito (padrão UTC)")
    ap.add_argument("--port", type=int, help="porta de ORIGEM citada na denúncia")
    ap.add_argument("--protocol", choices=("tcp", "udp", "icmp"))
    ap.add_argument("--remote", help="IP atacado (destino)")
    ap.add_argument("--remote-port", type=int)
    ap.add_argument("--window", type=int, default=10, help="minutos antes/depois (padrão 10)")
    ap.add_argument("--email", help="arquivo com o e-mail/relatório de abuso (extrai IPs, horários e portas)")
    ap.add_argument("--nat-dir", default=NAT_DIR)
    ap.add_argument("--no-db", action="store_true")
    args = ap.parse_args(argv)
    try:
        from .bidir_config import build_scopes, read_config
        cfg = read_config(args.config)
        scopes = build_scopes(cfg)
        tz = ZoneInfo(args.tz) if args.tz != "UTC" else timezone.utc
        if args.email:
            queries = extract_reports(Path(args.email).read_text(encoding="utf-8", errors="replace"), scopes, tz, args.window)
            if not queries:
                raise ValueError("nenhum IP do provedor com horário encontrado no texto")
        else:
            if not (args.ip and args.time):
                raise ValueError("informe --ip e --time, ou --email")
            when = parse_time(args.time, tz)
            if when is None:
                raise ValueError("horário não reconhecido: %s" % args.time)
            queries = [Query(args.ip, when, args.window, args.port, args.protocol, args.remote, args.remote_port)]
        db = None
        if not args.no_db:
            from .mysql_sink import connection_from_env
            db = connection_from_env()
        try:
            for q in queries:
                print(render_text(investigate(q, scopes, cfg["source"], db, args.nat_dir), tz))
                print()
        finally:
            if db is not None:
                db.close()
        return 0
    except Exception as exc:
        print("FALHA: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
