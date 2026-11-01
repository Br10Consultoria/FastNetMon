"""Ferramentas de diagnostico do painel: RDAP (dono e contato de abuso de um IP), AS (dono e prefixos
anunciados), DNS, ping e traceroute a partir do servidor. Entradas validadas; comandos sem shell e com tempo limite."""
from __future__ import annotations

from ipaddress import ip_address
import json
import re
import shutil
import socket
import subprocess
import urllib.parse
import urllib.request

HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\.?$")
DNS_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "PTR", "SOA", "CNAME")
UA = {"User-Agent": "OrbyMon-tools/1.0", "Accept": "application/rdap+json, application/json"}


class ToolError(ValueError):
    pass


def target(value, allow_host=True):
    value = (value or "").strip()
    try:
        return str(ip_address(value))
    except ValueError:
        pass
    if allow_host and HOST_RE.match(value):
        return value.rstrip(".").lower()
    raise ToolError("informe um IP%s válido" % (" ou nome" if allow_host else ""))


def _get_json(url, opener, timeout=15):
    req = urllib.request.Request(url, headers=UA)
    with opener(req, timeout=timeout) as resp:
        return json.loads(resp.read(4 * 1024 * 1024).decode("utf-8"))


def _vcard(entity):
    out = {}
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if not isinstance(item, list) or len(item) < 4:
            continue
        key, value = item[0], item[3]
        if key in ("fn", "email", "tel", "adr") and key not in out:
            out[key] = value if isinstance(value, str) else " ".join(str(v) for v in value if v) \
                if isinstance(value, list) else str(value)
    return out


def _entities(obj, depth=0):
    for e in obj.get("entities") or []:
        yield e
        if depth < 2:
            yield from _entities(e, depth + 1)


def rdap_ip(ip, opener=urllib.request.urlopen):
    ip = target(ip, allow_host=False)
    data = _get_json("https://rdap.org/ip/" + ip, opener)
    cidrs = ["%s/%s" % (c.get("v4prefix") or c.get("v6prefix"), c.get("length"))
             for c in data.get("cidr0_cidrs") or [] if c.get("length") is not None]
    out = {"ip": ip, "nome": data.get("name") or "", "handle": data.get("handle") or "",
           "pais": data.get("country") or "", "faixa": "%s - %s" % (data.get("startAddress", ""), data.get("endAddress", "")),
           "cidrs": cidrs, "abuse": [], "contatos": []}
    for e in _entities(data):
        card = _vcard(e)
        roles = e.get("roles") or []
        row = {"papel": ", ".join(roles), "nome": card.get("fn", ""), "email": card.get("email", ""),
               "handle": e.get("handle", "")}
        if "abuse" in roles and row["email"]:
            out["abuse"].append(row["email"])
        if row["nome"] or row["email"]:
            out["contatos"].append(row)
    out["abuse"] = sorted(set(out["abuse"]))
    out["contatos"] = out["contatos"][:12]
    return out


def asn_info(asn, opener=urllib.request.urlopen, limit=300):
    try:
        asn = int(str(asn).strip().upper().removeprefix("AS"))
    except ValueError:
        raise ToolError("ASN deve ser número (ex.: 262687 ou AS262687)")
    if not 1 <= asn <= 4294967295:
        raise ToolError("ASN fora da faixa")
    ov = _get_json("https://stat.ripe.net/data/as-overview/data.json?resource=AS%d&sourceapp=orbymon" % asn, opener)
    pf = _get_json("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%d&sourceapp=orbymon" % asn,
                   opener)
    prefixes = sorted({p.get("prefix", "") for p in (pf.get("data") or {}).get("prefixes") or [] if p.get("prefix")},
                      key=lambda p: (":" in p, p))
    d = ov.get("data") or {}
    return {"asn": asn, "nome": d.get("holder") or "", "anunciado": bool(d.get("announced")),
            "total": len(prefixes), "v4": sum(1 for p in prefixes if ":" not in p),
            "v6": sum(1 for p in prefixes if ":" in p), "prefixos": prefixes[:limit]}


def _run(args, timeout):
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return (out.stdout + out.stderr).strip()
    except FileNotFoundError:
        raise ToolError("%s não está instalado no servidor" % args[0])
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return (partial + "\n(tempo limite de %d s atingido)" % timeout).strip()


def dns(name, rtype="A", run=None, which=None):
    run, which = run or _run, which or shutil.which
    rtype = (rtype or "A").upper()
    if rtype not in DNS_TYPES:
        raise ToolError("tipo de registro inválido")
    name = target(name)
    if rtype == "PTR" or (":" in name or name.replace(".", "").isdigit()):
        try:
            ip_address(name)
        except ValueError:
            raise ToolError("PTR precisa de um IP")
        rtype = "PTR"
    if which("dig"):
        args = ["dig", "+time=3", "+tries=1", "+noall", "+answer"]
        args += ["-x", name] if rtype == "PTR" else [name, rtype]
        return run(args, 10) or "(sem resposta)"
    if rtype == "PTR":                                   # sem dig: resolvedor do sistema
        try:
            return socket.gethostbyaddr(name)[0]
        except OSError as exc:
            return "sem PTR (%s)" % exc
    if rtype in ("A", "AAAA"):
        fam = socket.AF_INET if rtype == "A" else socket.AF_INET6
        try:
            return "\n".join(sorted({i[4][0] for i in socket.getaddrinfo(name, None, fam)}))
        except OSError as exc:
            return "sem resposta (%s)" % exc
    raise ToolError("instale o dig (pacote dnsutils) para consultas %s" % rtype)


def ping(host, run=None):
    run = run or _run
    host = target(host)
    return run(["ping", "-n", "-c", "4", "-i", "0.5", "-W", "2", host], 15)


def traceroute(host, run=None, which=None):
    run, which = run or _run, which or shutil.which
    host = target(host)
    if which("traceroute"):
        return run(["traceroute", "-n", "-q", "1", "-w", "2", "-m", "20", host], 50)
    return run(["tracepath", "-n", "-m", "20", host], 50)


ASNAMES = "/var/lib/orbymon/asnames/asn.txt"      # lista do RIPE (asn.txt), atualizada pelo orbymon-exceptions


def asn_search(query, path=ASNAMES, opener=urllib.request.urlopen, limit=50):
    """AS por nome ou numero: [(asn, nome)]. Usa a lista local do RIPE; sem ela, consulta o RIPEstat."""
    q = " ".join((query or "").split())
    if not 2 <= len(q) <= 80 or re.search(r"[^\w .,&()/-]", q):
        raise ToolError("busca de 2 a 80 caracteres (letras, números, espaço e . , & ( ) / -)")
    terms = [t.lower() for t in q.split()]
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                low = line.lower()
                if all(t in low for t in terms):
                    num, _, name = line.strip().partition(" ")
                    if num.isdigit():
                        out.append((int(num), name.strip()))
                        if len(out) >= limit:
                            break
        return out
    except FileNotFoundError:
        pass
    data = _get_json("https://stat.ripe.net/data/searchcomplete/data.json?resource=%s&limit=%d&sourceapp=orbymon"
                     % (urllib.parse.quote(q), limit), opener)
    for cat in (data.get("data") or {}).get("categories") or []:
        for sug in cat.get("suggestions") or []:
            m = re.match(r"^AS(\d+)$", str(sug.get("value") or sug.get("label") or ""), re.I)
            if m:
                out.append((int(m.group(1)), str(sug.get("description") or "")))
    return out[:limit]


def update_asnames(path=ASNAMES, opener=urllib.request.urlopen, max_age_h=20, now=None):
    """Baixa a lista de nomes de AS do RIPE (uma vez por dia). Devolve o numero de linhas ou None se recente."""
    import os
    import time
    now = now or time.time()
    try:
        if now - os.stat(path).st_mtime < max_age_h * 3600:
            return None
    except FileNotFoundError:
        pass
    req = urllib.request.Request("https://ftp.ripe.net/ripe/asnames/asn.txt", headers={"User-Agent": UA["User-Agent"]})
    with opener(req, timeout=60) as resp:
        raw = resp.read(64 * 1024 * 1024).decode("utf-8", "replace")
    lines = [l for l in raw.splitlines() if l[:1].isdigit()]
    if len(lines) < 1000:
        raise ToolError("lista de AS incompleta (%d linhas); mantida a anterior" % len(lines))
    tmp = path + ".tmp"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)
    return len(lines)
