"""Reputacao dos IPs do provedor em listas publicas de bloqueio (etapa 2).

A cada execucao:
  1. baixa listas publicas (espelho FireHOL no GitHub + IPsum) e procura os blocos do provedor;
  2. a cada N horas, consulta DNSBLs (Spamhaus ZEN, SpamCop, Barracuda, UCEPROTECT, PSBL) para
     cada IPv4 e, com chave, o AbuseIPDB (check-block por /24);
  3. para cada IP listado de pool CGNAT, cruza com os fluxos de saida (48 h) e eventos de ataque
     para apontar QUAL assinante (IP privado) provavelmente causou a listagem;
  4. grava em orby_reputation_listings e avisa no Telegram (entrada e saida das listas).

Uso: python -m fmn_filters.reputation --config /etc/orbymon/bidir.json [--env-file /etc/orbymon/reputation.env]
     [--telegram-env /etc/orbymon/telegram.env] [--no-notify] [--mark-notified] [--dry-run]
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import html
from ipaddress import ip_address, ip_network
import json
import os
from pathlib import Path
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

FIREHOL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/"
MAX_DOWNLOAD = 64 * 1024 * 1024
MAX_DNSBL_ADDRESSES = 16384
WEB = (80, 443)
MAIL = (25, 465, 587)


@dataclass(frozen=True)
class Source:
    name: str
    label: str            # nome amigavel
    category: str         # o que a lista significa
    url: str
    ports: tuple = ()     # portas de destino tipicas do abuso (para achar o assinante)
    removal: str = ""     # como sair da lista
    fmt: str = "plain"    # plain (ip/cidr por linha) | ipsum (ip contagem)


BLOCKLIST_DE = "lista expira sozinha 48 h após o último ataque (https://www.blocklist.de/en/delist.html)"
SOURCES = (
    Source("blocklist_de_ssh", "blocklist.de SSH", "ataque/força bruta SSH", FIREHOL + "blocklist_de_ssh.ipset", (22,), BLOCKLIST_DE),
    Source("blocklist_de_mail", "blocklist.de e-mail", "ataque a servidores de e-mail (SMTP)", FIREHOL + "blocklist_de_mail.ipset", MAIL, BLOCKLIST_DE),
    Source("blocklist_de_imap", "blocklist.de IMAP/POP3", "força bruta IMAP/POP3", FIREHOL + "blocklist_de_imap.ipset", (110, 143, 993, 995), BLOCKLIST_DE),
    Source("blocklist_de_apache", "blocklist.de web", "ataque a sites (HTTP)", FIREHOL + "blocklist_de_apache.ipset", WEB, BLOCKLIST_DE),
    Source("blocklist_de_bruteforce", "blocklist.de login web", "força bruta em login de sites (WordPress etc.)", FIREHOL + "blocklist_de_bruteforce.ipset", WEB, BLOCKLIST_DE),
    Source("blocklist_de_bots", "blocklist.de bots", "bot de spam em formulários", FIREHOL + "blocklist_de_bots.ipset", WEB, BLOCKLIST_DE),
    Source("blocklist_de_ftp", "blocklist.de FTP", "força bruta FTP", FIREHOL + "blocklist_de_ftp.ipset", (21,), BLOCKLIST_DE),
    Source("blocklist_de_sip", "blocklist.de SIP", "ataque/fraude VoIP SIP", FIREHOL + "blocklist_de_sip.ipset", (5060, 5061), BLOCKLIST_DE),
    Source("blocklist_de_strongips", "blocklist.de persistentes", "atacante persistente (vários serviços)", FIREHOL + "blocklist_de_strongips.ipset", (), BLOCKLIST_DE),
    Source("bruteforceblocker", "BruteForceBlocker", "força bruta SSH", FIREHOL + "bruteforceblocker.ipset", (22,), "http://danger.rulez.sk/index.php/bruteforceblocker/"),
    Source("ciarmy", "CINS Army", "atacante visto pelos sensores CINS", FIREHOL + "ciarmy.ipset", (), "https://cinsscore.com/"),
    Source("greensnow", "GreenSnow", "atacante (varredura, força bruta)", FIREHOL + "greensnow.ipset", (), "https://greensnow.co/"),
    Source("et_compromised", "Emerging Threats", "host comprometido", FIREHOL + "et_compromised.ipset", (), "https://rules.emergingthreats.net/"),
    Source("dshield_7d", "DShield (SANS)", "rede /24 entre as que mais atacam", FIREHOL + "dshield_7d.netset", (), "https://isc.sans.edu/"),
    Source("spamhaus_drop", "Spamhaus DROP", "rede sequestrada ou criminosa", FIREHOL + "spamhaus_drop.netset", (), "https://www.spamhaus.org/drop/"),
    Source("firehol_level1", "FireHOL nível 1", "agregado de listas graves", FIREHOL + "firehol_level1.netset"),
    Source("firehol_level2", "FireHOL nível 2", "agregado de ataques (48 h)", FIREHOL + "firehol_level2.netset"),
    Source("firehol_level3", "FireHOL nível 3", "agregado de ataques (30 dias)", FIREHOL + "firehol_level3.netset"),
    Source("firehol_abusers_30d", "FireHOL abusers 30d", "abuso nos últimos 30 dias", FIREHOL + "firehol_abusers_30d.netset"),
    Source("sblam", "Sblam", "spam em formulários web", FIREHOL + "sblam.ipset", WEB, "https://sblam.com/"),
    Source("stopforumspam_7d", "StopForumSpam", "spam em fóruns", FIREHOL + "stopforumspam_7d.ipset", WEB, "https://www.stopforumspam.com/removal"),
    Source("botscout_7d", "BotScout", "bot de cadastro/spam", FIREHOL + "botscout_7d.ipset", WEB, "https://botscout.com/"),
    Source("php_spammers_7d", "Project Honey Pot spam", "spam em sites", FIREHOL + "php_spammers_7d.ipset", WEB, "https://www.projecthoneypot.org/"),
    Source("blocklist_net_ua", "blocklist.net.ua", "atacante (varredura, força bruta)", FIREHOL + "blocklist_net_ua.ipset", ()),
    Source("ipsum", "IPsum", "presente em várias listas de ameaças", "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt", (), fmt="ipsum"),
)


@dataclass(frozen=True)
class Dnsbl:
    name: str
    zone: str
    label: str
    removal: str
    ignore: tuple = ()     # codigos que nao sao abuso (ex.: PBL = faixa residencial)


DNSBLS = (
    Dnsbl("dnsbl_spamhaus_zen", "zen.spamhaus.org", "Spamhaus ZEN", "https://check.spamhaus.org/",
          ignore=("127.0.0.10", "127.0.0.11")),
    Dnsbl("dnsbl_spamcop", "bl.spamcop.net", "SpamCop", "expira em 24 h sem novas denúncias"),
    Dnsbl("dnsbl_barracuda", "b.barracudacentral.org", "Barracuda", "https://www.barracudacentral.org/rbl/removal-request"),
    Dnsbl("dnsbl_uceprotect", "dnsbl-1.uceprotect.net", "UCEPROTECT nível 1", "expira em 7 dias sem novas ocorrências"),
    Dnsbl("dnsbl_psbl", "psbl.surriel.com", "PSBL", "https://psbl.org/remove"),
)
SPAMHAUS_CODES = {"127.0.0.2": "SBL (fonte de spam)", "127.0.0.3": "CSS (spam de baixa reputação)",
                  "127.0.0.4": "XBL (máquina infectada/botnet)", "127.0.0.5": "XBL", "127.0.0.6": "XBL",
                  "127.0.0.7": "XBL", "127.0.0.9": "DROP"}


# ------------------------------------------------------------------ parse e casamento
def parse_entries(text: str, fmt: str = "plain"):
    """Entradas IP/CIDR de uma lista (ignora comentarios e linhas invalidas)."""
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        token = line.split()[0].split(";")[0]
        extra = {}
        if fmt == "ipsum":
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                extra["listas"] = int(parts[1])
        try:
            out.append((ip_network(token, strict=False), extra))
        except ValueError:
            continue
    return out


def match(entries, blocks):
    """Entradas que tocam os blocos do provedor -> {entrada: extra}."""
    found = {}
    by_version = {4: [b for b in blocks if b.version == 4], 6: [b for b in blocks if b.version == 6]}
    for net, extra in entries:
        for block in by_version[net.version]:
            if net.overlaps(block):
                key = str(net.network_address) if net.num_addresses == 1 else str(net)
                found[key] = extra
                break
    return found


def fetch(url, timeout=60, opener=urllib.request.urlopen):
    req = urllib.request.Request(url, headers={"User-Agent": "OrbyMon-reputation/1.0"})
    with opener(req, timeout=timeout) as resp:
        data = resp.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise ValueError("lista maior que %d MB" % (MAX_DOWNLOAD // 1048576))
    return data.decode("utf-8", "replace")


# ------------------------------------------------------------------ DNSBL
def _resolve(name):
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(name, None, socket.AF_INET)})
    except (socket.gaierror, UnicodeError, OSError):
        return []


def dnsbl_query(ip, zone, resolver=_resolve):
    rev = ".".join(reversed(ip.split(".")))
    return resolver("%s.%s" % (rev, zone))


def check_dnsbl(addresses, lists=DNSBLS, resolver=_resolve, workers=48):
    """-> (achados {nome: {ip: detalhe}}, status {nome: (ok, erro)})."""
    found, status = {}, {}
    usable = []
    for bl in lists:
        test = dnsbl_query("127.0.0.2", bl.zone, resolver)      # ponto de teste padrao de toda DNSBL
        if any(a.startswith("127.255.255.") for a in test):
            status[bl.name] = (False, "consulta recusada (resolvedor DNS público/aberto); use um resolvedor próprio")
        elif not any(a.startswith("127.") for a in test):
            status[bl.name] = (False, "sem resposta ao teste 127.0.0.2 (lista indisponível ou exige cadastro)")
        else:
            usable.append(bl)
            found[bl.name] = {}
    jobs = [(bl, ip) for bl in usable for ip in addresses]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda job: (job, dnsbl_query(job[1], job[0].zone, resolver)), jobs)
        for (bl, ip), answer in results:
            codes = [a for a in answer if a.startswith("127.") and a not in bl.ignore]
            if any(a.startswith("127.255.255.") for a in codes):
                status[bl.name] = (False, "consulta recusada pela lista (limite ou resolvedor público)")
                continue
            if codes:
                text = ", ".join(SPAMHAUS_CODES.get(c, c) for c in codes) if "spamhaus" in bl.zone else ", ".join(codes)
                found[bl.name][ip] = {"codigo": text}
    for bl in usable:
        status.setdefault(bl.name, (True, ""))
    return found, status


# ------------------------------------------------------------------ AbuseIPDB
def check_abuseipdb(key, blocks, opener=urllib.request.urlopen, max_calls=64):
    found = {}
    calls = 0
    for block in blocks:
        if block.version != 4:
            continue
        subnets = [block] if block.prefixlen >= 24 else list(block.subnets(new_prefix=24))
        for net in subnets:
            calls += 1
            if calls > max_calls:
                raise ValueError("blocos demais para o AbuseIPDB (máximo %d /24 por execução)" % max_calls)
            url = "https://api.abuseipdb.com/api/v2/check-block?" + urllib.parse.urlencode(
                {"network": str(net), "maxAgeInDays": 30})
            req = urllib.request.Request(url, headers={"Key": key, "Accept": "application/json",
                                                       "User-Agent": "OrbyMon-reputation/1.0"})
            try:
                with opener(req, timeout=30) as resp:
                    body = json.loads(resp.read().decode())
            except urllib.error.HTTPError as exc:
                raise RuntimeError("AbuseIPDB HTTP %s (chave inválida ou limite diário)" % exc.code) from None
            for row in (body.get("data") or {}).get("reportedAddress") or []:
                found[row["ipAddress"]] = {"denuncias": row.get("numReports"),
                                           "confianca": row.get("abuseConfidenceScore"),
                                           "ultima": row.get("mostRecentReport")}
    return found


# ------------------------------------------------------------------ responsavel (CGNAT)
def suspects(cur, source, ip, ports, scope, hours=48):
    """Assinantes que, pelos fluxos e eventos, mais provavelmente causaram a listagem de ``ip``."""
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)
    col = "subscriber_ip" if scope == "cgnat_pool" else "local_ip"
    out = {"periodo_horas": hours, "suspeitos": [], "eventos": []}
    params = [source, ip, since]
    port_sql = ""
    if ports:
        port_sql = " AND remote_port IN (%s)" % ",".join(["%s"] * len(ports))
        params += list(ports)
    cur.execute("SELECT " + col + ",SUM(flows),SUM(packets),COUNT(DISTINCT remote_ip),"
                "GROUP_CONCAT(DISTINCT remote_port ORDER BY remote_port SEPARATOR ',') FROM orby_flow_minute "
                "WHERE source=%s AND direction='out' AND local_ip=%s AND bucket_utc>=%s" + port_sql +
                (" AND subscriber_ip<>''" if scope == "cgnat_pool" else "") +
                " GROUP BY " + col + " ORDER BY SUM(flows) DESC LIMIT 5", params)
    for who, flows, packets, remotes, rports in cur.fetchall():
        out["suspeitos"].append({"ip": who, "fluxos": int(flows or 0), "pacotes": float(packets or 0),
                                 "destinos": int(remotes or 0), "portas": (rports or "")[:80]})
    cur.execute("SELECT subscriber_ip,COUNT(*),GROUP_CONCAT(DISTINCT rule_name SEPARATOR ', '),MAX(event_time) "
                "FROM orby_attack_events WHERE direction='out' AND local_ip=%s AND event_time>=%s "
                "GROUP BY subscriber_ip ORDER BY COUNT(*) DESC LIMIT 5",
                (ip, since - timedelta(hours=7 * 24 - hours)))
    for who, count, rules, last in cur.fetchall():
        out["eventos"].append({"ip": who or ip, "eventos": int(count), "regras": (rules or "")[:200],
                               "ultimo": str(last)})
    out["portas_analisadas"] = list(ports)
    return out


# ------------------------------------------------------------------ banco
def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)


@dataclass
class Listing:
    entry: str
    source: str
    label: str
    category: str
    removal: str
    ports: tuple
    extra: dict = field(default_factory=dict)


def store(db, listings, ok_sources, status, scopes, source_name, run_at, mark_notified=False):
    """Grava listagens e estado das fontes. Avisos pendentes ficam com notified_at NULL."""
    cur = db.cursor()
    for l in listings:
        scope, pool, _ = scopes.classify(l.entry) if "/" not in l.entry else ("bloco", "", 0)
        detail = dict(l.extra)
        if scope in ("cgnat_pool", "dedicated") and "/" not in l.entry and l.entry.count(".") == 3:
            detail.update(suspects(cur, source_name, l.entry, l.ports, scope))
        notified = run_at if mark_notified else None    # nova ou que voltou a lista: avisar
        cur.execute("""INSERT INTO orby_reputation_listings
 (entry,source,source_label,category,scope,pool,first_seen,last_seen,removed_at,removal_hint,detail,notified_at)
 VALUES (%s,%s,%s,%s,%s,%s,%s,%s,NULL,%s,%s,%s)
 ON DUPLICATE KEY UPDATE source_label=VALUES(source_label),category=VALUES(category),scope=VALUES(scope),
  pool=VALUES(pool),last_seen=VALUES(last_seen),removal_hint=VALUES(removal_hint),detail=VALUES(detail),
  first_seen=IF(removed_at IS NULL,first_seen,VALUES(first_seen)),
  notified_at=IF(removed_at IS NULL,notified_at,%s),removed_notified=IF(removed_at IS NULL,removed_notified,0),
  removed_at=NULL""",
                    (l.entry, l.source, l.label, l.category, scope, pool, run_at, run_at, l.removal,
                     json.dumps(detail, ensure_ascii=False, default=str), notified, notified))
    for name in ok_sources:          # so remove listagens de fontes consultadas com sucesso
        cur.execute("UPDATE orby_reputation_listings SET removed_at=%s WHERE source=%s AND removed_at IS NULL "
                    "AND last_seen<%s", (run_at, name, run_at))
    for name, (ok, error, entries, matched) in status.items():
        cur.execute("""INSERT INTO orby_reputation_sources (source,last_run,last_ok,entries,matched,status,error)
 VALUES (%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE last_run=VALUES(last_run),
 last_ok=IF(VALUES(status)='ok',VALUES(last_ok),last_ok),entries=IF(VALUES(status)='ok',VALUES(entries),entries),
 matched=IF(VALUES(status)='ok',VALUES(matched),matched),status=VALUES(status),error=VALUES(error)""",
                    (name, run_at, run_at if ok else None, entries, matched, "ok" if ok else "falha", error[:500]))
    if mark_notified:
        cur.execute("UPDATE orby_reputation_listings SET notified_at=%s WHERE notified_at IS NULL", (run_at,))
        cur.execute("UPDATE orby_reputation_listings SET removed_notified=1 WHERE removed_at IS NOT NULL")
    db.commit()


# ------------------------------------------------------------------ notificacao
def detail_rank(d):
    """Prefere a evidencia de lista com porta especifica (ex.: SSH -> porta 22) a de lista generica."""
    d = d or {}
    return (bool(d.get("portas_analisadas")) and bool(d.get("suspeitos")), len(d.get("eventos") or []),
            len(d.get("suspeitos") or []))


def pending_notifications(cur):
    cur.execute("""SELECT entry,source_label,category,scope,pool,removal_hint,detail,first_seen
 FROM orby_reputation_listings WHERE removed_at IS NULL AND notified_at IS NULL ORDER BY entry,source""")
    new = {}
    for entry, label, category, scope, pool, removal, detail, first in cur.fetchall():
        item = new.setdefault(entry, {"entry": entry, "scope": scope, "pool": pool, "lists": [], "detail": {}})
        item["lists"].append((label, category, removal))
        try:
            d = json.loads(detail) if isinstance(detail, (str, bytes)) else (detail or {})
        except ValueError:
            d = {}
        if detail_rank(d) > detail_rank(item["detail"]):
            item["detail"] = d
    # removidas: a entrada nao tem mais nenhuma listagem ativa
    cur.execute("""SELECT r.entry FROM orby_reputation_listings r WHERE r.removed_at IS NOT NULL AND r.removed_notified=0
 AND NOT EXISTS (SELECT 1 FROM orby_reputation_listings a WHERE a.entry=r.entry AND a.removed_at IS NULL)
 GROUP BY r.entry""")
    cleared = [row[0] for row in cur.fetchall()]
    return list(new.values()), cleared


SCOPE_PT = {"cgnat_pool": "pool CGNAT", "dedicated": "IP dedicado", "infra": "infraestrutura",
            "bloco": "bloco inteiro", "external": "fora dos blocos"}


def format_listing(item, header, link=""):
    lines = [header("🚫", "IP do provedor em lista de bloqueio")]
    where = SCOPE_PT.get(item["scope"], item["scope"])
    if item["pool"]:
        where += " " + html.escape(item["pool"])
    lines.append("<b>%s</b> (%s)" % (html.escape(item["entry"]), where))
    for label, category, _ in item["lists"][:8]:
        lines.append("• %s — %s" % (html.escape(label), html.escape(category)))
    if len(item["lists"]) > 8:
        lines.append("• e mais %d lista(s)" % (len(item["lists"]) - 8))
    d = item["detail"] or {}
    sus = d.get("suspeitos") or []
    ev = d.get("eventos") or []
    if item["scope"] == "cgnat_pool":
        if sus:
            ports = d.get("portas_analisadas") or []
            lines.append("<b>Prováveis responsáveis</b> (saída nas últimas %s h%s):" % (
                d.get("periodo_horas", 48), ", portas " + ",".join(map(str, ports)) if ports else ""))
            for s in sus[:3]:
                lines.append("  %s — %s fluxos para %s destinos" % (html.escape(s["ip"]), s["fluxos"], s["destinos"]))
        if ev:
            lines.append("Ataques originados detectados: " + ", ".join(
                "%s (%s)" % (html.escape(e["ip"]), e["eventos"]) for e in ev[:3]))
        if not sus and not ev:
            lines.append("Sem tráfego suspeito nos fluxos amostrados: use Investigar no painel com horário e porta da denúncia.")
    elif sus:
        lines.append("Tráfego de saída (48 h): %s fluxos para %s destinos, portas %s" % (
            sus[0]["fluxos"], sus[0]["destinos"], html.escape(sus[0]["portas"] or "-")))
    hints = sorted({r for _, _, r in item["lists"] if r})
    if hints:
        lines.append("Remoção: " + html.escape(hints[0]))
    return "\n".join(lines) + link


def notify(db, telegram, formatter, budget=10):
    cur = db.cursor()
    new, cleared = pending_notifications(cur)
    sent = 0
    now = utcnow()
    for item in new:
        if sent >= budget:
            break
        telegram.send(format_listing(item, formatter.header))
        cur.execute("UPDATE orby_reputation_listings SET notified_at=%s WHERE entry=%s AND notified_at IS NULL "
                    "AND removed_at IS NULL", (now, item["entry"]))
        db.commit()
        sent += 1
    rest = len(new) - sent
    if rest > 0:
        telegram.send(formatter.header("🚫", "Mais %d IP(s) entraram em listas de bloqueio" % rest) +
                      "\nVeja a página Reputação do painel.")
        cur.execute("UPDATE orby_reputation_listings SET notified_at=%s WHERE notified_at IS NULL AND removed_at IS NULL",
                    (now,))
        db.commit()
    if cleared:
        shown = ", ".join(html.escape(e) for e in cleared[:20]) + (" e mais %d" % (len(cleared) - 20) if len(cleared) > 20 else "")
        telegram.send(formatter.header("✅", "Saiu de todas as listas") + "\n" + shown)
        cur.execute("UPDATE orby_reputation_listings SET removed_notified=1 WHERE removed_at IS NOT NULL")
        db.commit()
    return {"novos": len(new), "enviados": sent, "removidos": len(cleared)}


# ------------------------------------------------------------------ execucao
def last_ok(cur, name):
    cur.execute("SELECT last_ok FROM orby_reputation_sources WHERE source=%s", (name,))
    row = cur.fetchone()
    return row[0] if row else None


def run(cfg, profile, settings, db=None, opener=urllib.request.urlopen, resolver=_resolve, now=None, log=print):
    from .bidir_config import build_scopes
    scopes = build_scopes(cfg, profile)
    blocks = [ip_network(c) for c in profile["protected_cidrs"]] + \
             [ip_network(c, strict=False) for c in cfg.get("ipv6_protected_cidrs", [])]
    run_at = now or utcnow()
    disabled = settings["disabled"]
    listings, ok_sources, status = [], [], {}
    for src in SOURCES:
        if src.name in disabled:
            continue
        try:
            entries = parse_entries(fetch(src.url, opener=opener), src.fmt)
            if len(entries) == 0 and src.name not in ("blocklist_de_ftp",):
                raise ValueError("lista vazia")
            found = match(entries, blocks)
            for entry, extra in found.items():
                category = src.category
                if src.fmt == "ipsum" and extra.get("listas"):
                    category = "presente em %d listas de ameaças" % extra["listas"]
                listings.append(Listing(entry, src.name, src.label, category, src.removal, src.ports, extra))
            ok_sources.append(src.name)
            status[src.name] = (True, "", len(entries), len(found))
        except Exception as exc:                      # uma fonte fora do ar nao derruba as outras
            status[src.name] = (False, str(exc), 0, 0)
            log("fonte %s falhou: %s" % (src.name, exc))
    heavy_due = True
    cur = db.cursor() if db is not None else None
    if cur is not None:
        prev = last_ok(cur, "dnsbl_spamhaus_zen") or last_ok(cur, "dnsbl_spamcop")
        heavy_due = prev is None or run_at - prev >= timedelta(hours=settings["heavy_every_h"]) - timedelta(minutes=5)
    if settings["dnsbl"] and heavy_due:
        addresses = [str(a) for b in blocks if b.version == 4 for a in b]
        if len(addresses) > MAX_DNSBL_ADDRESSES:
            log("DNSBL ignorada: %d endereços (máximo %d)" % (len(addresses), MAX_DNSBL_ADDRESSES))
        else:
            lists = [bl for bl in DNSBLS if bl.name not in disabled]
            found, st = check_dnsbl(addresses, lists, resolver)
            for bl in lists:
                ok, error = st.get(bl.name, (False, "não consultada"))
                hits = found.get(bl.name, {})
                for ip, extra in hits.items():
                    category = "lista de spam" + (": " + extra["codigo"] if extra.get("codigo") else "")
                    listings.append(Listing(ip, bl.name, bl.label, category, bl.removal, MAIL, extra))
                if ok:
                    ok_sources.append(bl.name)
                status[bl.name] = (ok, error, len(addresses), len(hits))
    if settings["abuseipdb_key"] and heavy_due and "abuseipdb" not in disabled:
        try:
            found = check_abuseipdb(settings["abuseipdb_key"], blocks, opener)
            for ip, extra in found.items():
                listings.append(Listing(ip, "abuseipdb", "AbuseIPDB", "denunciado %s vez(es), confiança %s%%" % (
                    extra.get("denuncias"), extra.get("confianca")), "https://www.abuseipdb.com/check/" + ip, (), extra))
            ok_sources.append("abuseipdb")
            status["abuseipdb"] = (True, "", sum(1 for b in blocks if b.version == 4), len(found))
        except Exception as exc:
            status["abuseipdb"] = (False, str(exc), 0, 0)
            log("AbuseIPDB falhou: %s" % exc)
    if db is not None:
        store(db, listings, ok_sources, status, scopes, cfg["source"], run_at, settings.get("mark_notified", False))
    return listings, status


def settings_from_env(env):
    disabled = {s.strip() for s in env.get("ORBYMON_REP_DISABLED", "").split(",") if s.strip()}
    every = int(env.get("ORBYMON_REP_HEAVY_EVERY_H", "6") or 6)
    if not 1 <= every <= 168:
        raise ValueError("ORBYMON_REP_HEAVY_EVERY_H entre 1 e 168")
    return {"disabled": disabled, "dnsbl": env.get("ORBYMON_REP_DNSBL", "1").strip() != "0",
            "abuseipdb_key": env.get("ABUSEIPDB_API_KEY", "").strip(), "heavy_every_h": every}


def main(argv=None):
    ap = argparse.ArgumentParser(description="OrbyMon: IPs do provedor em listas de bloqueio")
    ap.add_argument("--config", default="/etc/orbymon/bidir.json")
    ap.add_argument("--env-file", help="configuracao da reputacao (KEY='valor'; nunca executado)")
    ap.add_argument("--telegram-env", help="telegram.env para avisar novas listagens")
    ap.add_argument("--no-notify", action="store_true")
    ap.add_argument("--mark-notified", action="store_true", help="marca tudo como avisado (primeira execucao)")
    ap.add_argument("--dry-run", action="store_true", help="so mostra, sem gravar")
    args = ap.parse_args(argv)
    try:
        from .admin.config_store import read_env
        from .bidir_config import load_profile, read_config
        cfg = read_config(args.config)
        profile = load_profile(cfg)
        env = dict(os.environ)
        if args.env_file:
            env.update(read_env(Path(args.env_file)))
        settings = settings_from_env(env)
        settings["mark_notified"] = args.mark_notified
        db = None
        if not args.dry_run:
            from .mysql_sink import connection_from_env
            db = connection_from_env()
        started = time.time()
        try:
            listings, status = run(cfg, profile, settings, db)
            entries = sorted({l.entry for l in listings})
            failed = [n for n, s in status.items() if not s[0]]
            print("reputacao: %d fonte(s) ok, %d falha(s), %d IP/bloco(s) listados%s em %.0f s" % (
                len(status) - len(failed), len(failed), len(entries),
                (": " + ", ".join(entries[:20])) if entries else "", time.time() - started))
            for name in failed:
                print("  falha %s: %s" % (name, status[name][1]))
            if args.dry_run:
                for l in listings:
                    print("  %-18s %-24s %s" % (l.entry, l.label, l.category))
            if db is not None and args.telegram_env and not args.no_notify and not args.mark_notified:
                from .notify_telegram import Formatter, Settings, Telegram
                tenv = dict(os.environ)
                tenv.update(read_env(Path(args.telegram_env)))
                if tenv.get("TELEGRAM_BOT_TOKEN") and tenv.get("TELEGRAM_CHAT_IDS"):
                    ts = Settings.from_env(tenv)
                    from .channels import wrap
                    stats = notify(db, wrap(Telegram(ts.token, ts.chats), os.environ.get("ORBYMON_NOTIFY_ENV", "/etc/orbymon/notify.env"), ts.site), Formatter(ts))
                    if any(stats.values()):
                        print("telegram: %s" % stats)
        finally:
            if db is not None:
                db.close()
        return 0
    except Exception as exc:
        print("FALHA reputacao: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
