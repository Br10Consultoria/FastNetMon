"""C2 e botnets: clientes (CPEs) conversando com IPs de listas publicas de ameacas.

A cada execucao (timer de 10 min):
  1. atualiza as listas (a cada ORBYMON_THREAT_REFRESH_H horas; falha mantem a copia anterior):
       bot (C2/botnet)  Feodo Tracker, C2IntelFeeds, CyberCrime tracker e ThreatFox (com Auth-Key gratis
                        do abuse.ch em threat.env; sem chave fica de fora);
       reputacao        IPsum (3+ listas), Spamhaus DROP, Emerging Threats comprometidos;
  2. pega os IPs remotos para os quais a rede ENVIOU trafego desde a ultima execucao (orby_flow_minute, no
     ClickHouse quando configurado) e procura nas listas;
  3. grava os pares cliente x IP listado em orby_threat_hits (com o assinante do CGNAT ja resolvido pelo
     log do A10) e, para C2/botnet, um evento em orby_attack_events (detection='c2'): aparece no painel
     (Ataques) e no Telegram, uma vez por par por dia.

Limite: o NetStream e amostrado (1 em N pacotes). Conversa curta com C2 (beacon de poucos pacotes) so aparece
quando algum pacote cai na amostra; com os dias os clientes infectados vao aparecendo.

Uso: python -m fmn_filters.threat_intel --config /etc/orbymon/bidir.json [--env-file /etc/orbymon/threat.env]
     [--state-dir /var/lib/orbymon/threat] [--refresh] [--dry-run]
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from ipaddress import ip_address, ip_network
import json
import os
from pathlib import Path
import sys
import time
import urllib.request

FIREHOL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
MAX_DOWNLOAD = 64 * 1024 * 1024
STATE_DIR = "/var/lib/orbymon/threat"
MAX_WINDOW = timedelta(hours=6)
LAG = timedelta(minutes=3)               # o rollup grava o minuto com atraso
RETENTION_DAYS = 30
CATEGORIES = {"bot": "C2/botnet", "reputacao": "reputação"}


@dataclass(frozen=True)
class Feed:
    name: str
    label: str
    category: str          # bot | reputacao
    url: str
    fmt: str = "plain"     # plain | c2intel (ip,descricao) | threatfox (API com Auth-Key)


FEEDS = (
    Feed("feodo", "Feodo Tracker (abuse.ch)", "bot", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
    Feed("threatfox", "ThreatFox (abuse.ch)", "bot", THREATFOX_API, "threatfox"),
    Feed("c2intel", "C2IntelFeeds (Cobalt Strike e outros, 30 dias)", "bot",
         "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv", "c2intel"),
    Feed("cybercrime", "CyberCrime tracker", "bot", FIREHOL + "cybercrime.ipset"),
    Feed("ipsum", "IPsum (3+ listas)", "reputacao", "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"),
    Feed("spamhaus_drop", "Spamhaus DROP", "reputacao", FIREHOL + "spamhaus_drop.netset"),
    Feed("et_compromised", "Emerging Threats comprometidos", "reputacao",
         "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"),
)
FEED_BY_NAME = {f.name: f for f in FEEDS}


# ------------------------------------------------------------------ listas
def parse_plain(text):
    """[(rede, porta, malware)] de uma lista IP/CIDR por linha (comentarios # ou ;)."""
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        try:
            out.append((ip_network(line.split()[0], strict=False), 0, ""))
        except ValueError:
            continue
    return out


def parse_c2intel(text):
    """CSV 'ip,ioc' do C2IntelFeeds: '1.2.3.4,Possible Cobaltstrike C2 IP' -> malware 'Cobaltstrike'."""
    out = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        ip, _, desc = line.partition(",")
        try:
            net = ip_network(ip.strip(), strict=False)
        except ValueError:
            continue
        name = desc.strip().replace("Possible ", "").replace(" C2 IP", "").replace(" C2", "").strip()
        out.append((net, 0, name[:60]))
    return out


def parse_threatfox(text):
    """Resposta JSON do get_iocs: so ip:port de botnet_cc/payload_delivery (C2 e distribuicao de malware)."""
    out = []
    try:
        data = json.loads(text).get("data") or []
    except (ValueError, AttributeError):
        return out
    if not isinstance(data, list):
        return out
    for ioc in data:
        if not isinstance(ioc, dict) or ioc.get("ioc_type") != "ip:port":
            continue
        if ioc.get("threat_type") not in ("botnet_cc", "payload_delivery"):
            continue
        ip, _, port = str(ioc.get("ioc", "")).rpartition(":")
        try:
            net = ip_network(ip.strip("[]"), strict=False)
            port = int(port)
        except ValueError:
            continue
        out.append((net, port, str(ioc.get("malware_printable") or ioc.get("malware") or "")[:60]))
    return out


def fetch(feed, settings, opener=urllib.request.urlopen, timeout=60):
    headers = {"User-Agent": "OrbyFlow-threat/1.0"}
    data = None
    if feed.fmt == "threatfox":
        key = settings.get("threatfox_key", "")
        if not key:
            raise LookupError("sem Auth-Key do abuse.ch (painel > C2 e botnets)")
        headers.update({"Auth-Key": key, "Content-Type": "application/json"})
        data = json.dumps({"query": "get_iocs", "days": 7}).encode()
    req = urllib.request.Request(feed.url, data=data, headers=headers)
    with opener(req, timeout=timeout) as resp:
        body = resp.read(MAX_DOWNLOAD + 1)
    if len(body) > MAX_DOWNLOAD:
        raise ValueError("lista maior que %d MB" % (MAX_DOWNLOAD // 1024 ** 2))
    text = body.decode("utf-8", "replace")
    if feed.fmt == "threatfox":
        try:
            status = json.loads(text).get("query_status")
        except (ValueError, AttributeError):
            status = "resposta invalida"
        if status not in ("ok", "no_result"):
            raise ValueError("ThreatFox: %s" % str(status)[:80])
    return text


def parse(feed, text):
    return {"threatfox": parse_threatfox, "c2intel": parse_c2intel}.get(feed.fmt, parse_plain)(text)


def refresh(state_dir, settings, db=None, opener=urllib.request.urlopen, now=None, force=False, log=print):
    """Baixa as listas vencidas para state_dir/<nome>.txt. Retorna {nome: (ok, mensagem, entradas)}."""
    now = now or datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
    state_dir = Path(state_dir)
    every = timedelta(hours=settings.get("refresh_h", 6))
    status = {}
    for feed in FEEDS:
        if feed.name in settings.get("disabled", ()):
            continue
        path = state_dir / (feed.name + ".txt")
        if not force and path.exists() and \
                datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).replace(tzinfo=None) > now - every:
            continue
        try:
            text = fetch(feed, settings, opener)
            n = len(parse(feed, text))
            if n == 0 and path.exists() and feed.fmt != "threatfox":
                raise ValueError("lista veio vazia; mantida a copia anterior")
            tmp = path.with_suffix(".tmp")
            tmp.write_text(text, encoding="utf-8")
            tmp.replace(path)
            status[feed.name] = (True, "", n)
        except LookupError as exc:
            status[feed.name] = (False, str(exc), 0)
        except Exception as exc:              # rede, HTTP, formato: mantem a copia anterior
            status[feed.name] = (False, str(exc)[:200], 0)
            log("AVISO lista %s: %s" % (feed.name, str(exc)[:200]))
    if db is not None and status:
        cur = db.cursor()
        for name, (ok, err, n) in status.items():
            f = FEED_BY_NAME[name]
            cur.execute("""INSERT INTO orby_threat_sources (name,label,category,last_run,last_ok,entries,status,error)
VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE label=VALUES(label),category=VALUES(category),
last_run=VALUES(last_run),last_ok=COALESCE(VALUES(last_ok),last_ok),entries=IF(VALUES(status)='ok',VALUES(entries),entries),
status=VALUES(status),error=VALUES(error)""",
                        (name, f.label, f.category, now, now if ok else None, n, "ok" if ok else "falha", err))
        db.commit()
    return status


class Index:
    """Procura um IP nas listas: IPs exatos em dicionario, redes em lista ordenada (com fim maximo acumulado)."""

    def __init__(self, exclude=()):
        self.exact = {}
        self.nets = {4: [], 6: []}
        self.exclude = [ip_network(c, strict=False) for c in exclude]
        self.feeds = {}

    def _skip(self, net):
        if not net.is_global or net.is_multicast:
            return True
        if (net.version == 4 and net.prefixlen < 8) or (net.version == 6 and net.prefixlen < 19):
            return True             # agregados grandes demais: falso positivo garantido
        return any(net.version == x.version and net.overlaps(x) for x in self.exclude)

    def add(self, feed, entries):
        n = 0
        for net, port, malware in entries:
            if self._skip(net):
                continue
            info = (feed.name, feed.category, port, malware)
            if net.num_addresses == 1:
                self.exact.setdefault(int(net.network_address), set()).add(info)
            else:
                self.nets[net.version].append((int(net.network_address), int(net.broadcast_address), info))
            n += 1
        self.feeds[feed.name] = n
        return n

    def build(self):
        self._starts, self._maxend = {}, {}
        for v, items in self.nets.items():
            items.sort()
            self._starts[v] = [s for s, _, _ in items]
            acc, mx = [], -1
            for _, e, _ in items:
                mx = max(mx, e)
                acc.append(mx)
            self._maxend[v] = acc
        return self

    def lookup(self, ip):
        try:
            a = ip_address(ip)
        except ValueError:
            return set()
        n = int(a)
        found = set(self.exact.get(n, ()))
        items = self.nets[a.version]
        i = bisect_right(self._starts[a.version], n) - 1
        while i >= 0 and self._maxend[a.version][i] >= n:
            s, e, info = items[i]
            if s <= n <= e:
                found.add(info)
            i -= 1
        return found

    def size(self):
        return len(self.exact) + sum(len(x) for x in self.nets.values())


def load_index(state_dir, exclude, disabled=()):
    idx = Index(exclude)
    for feed in FEEDS:
        if feed.name in disabled:
            continue
        path = Path(state_dir) / (feed.name + ".txt")
        if path.exists():
            idx.add(feed, parse(feed, path.read_text(encoding="utf-8", errors="replace")))
    return idx.build()


# ------------------------------------------------------------------ fluxos
class MariaSource:
    def __init__(self, db, source):
        self.db, self.source = db, source

    def remotes(self, start, end):
        cur = self.db.cursor()
        cur.execute("SELECT DISTINCT remote_ip FROM orby_flow_minute WHERE bucket_utc>=%s AND bucket_utc<%s "
                    "AND direction='out' AND source=%s", (start, end, self.source))
        return [r[0] for r in cur.fetchall()]

    def detail(self, start, end, ips):
        cur = self.db.cursor()
        ph = ",".join(["%s"] * len(ips))
        cur.execute("SELECT local_ip,subscriber_ip,scope,pool,remote_ip,protocol,remote_port,SUM(packets),SUM(bytes),"
                    "SUM(flows),MIN(bucket_utc),MAX(bucket_utc) FROM orby_flow_minute WHERE bucket_utc>=%s AND "
                    "bucket_utc<%s AND direction='out' AND source=%s AND remote_ip IN (" + ph + ") GROUP BY local_ip,"
                    "subscriber_ip,scope,pool,remote_ip,protocol,remote_port", [start, end, self.source] + list(ips))
        return [tuple(r) for r in cur.fetchall()]


class ClickSource:
    def __init__(self, client, source):
        self.c, self.source = client, source
        self.t = "%s.flow_minute" % client.database

    def _p(self, start, end):
        return {"s": self.source, "a": start, "b": end}

    def remotes(self, start, end):
        rows = self.c.query("SELECT DISTINCT remote_ip AS r FROM %s WHERE source={s:String} AND bucket>={a:DateTime('UTC')}"
                            " AND bucket<{b:DateTime('UTC')} AND direction='out'" % self.t, self._p(start, end))
        return [r["r"] for r in rows]

    def detail(self, start, end, ips):
        p = self._p(start, end)
        p["ips"] = "[" + ",".join("'%s'" % str(ip_address(i)) for i in ips) + "]"
        rows = self.c.query(
            "SELECT local_ip AS a,subscriber_ip AS b,scope AS c,pool AS d,remote_ip AS e,protocol AS f,remote_port AS g,"
            "sum(packets) AS h,sum(bytes) AS i,sum(flows) AS j,min(bucket) AS k,max(bucket) AS l FROM %s WHERE "
            "source={s:String} AND bucket>={a:DateTime('UTC')} AND bucket<{b:DateTime('UTC')} AND direction='out' AND "
            "remote_ip IN {ips:Array(String)} GROUP BY a,b,c,d,e,f,g" % self.t, p)
        fmt = "%Y-%m-%d %H:%M:%S"
        return [(r["a"], r["b"], r["c"], r["d"], r["e"], r["f"], int(r["g"]), float(r["h"]), float(r["i"]),
                 int(r["j"]), datetime.strptime(r["k"], fmt), datetime.strptime(r["l"], fmt)) for r in rows]


# ------------------------------------------------------------------ gravacao
HIT_SQL = """INSERT INTO orby_threat_hits (cpe_ip,remote_ip,protocol,remote_port,public_ip,scope,pool,category,sources,
listed_port,malware,first_seen,last_seen,flows,packets,bytes) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
ON DUPLICATE KEY UPDATE public_ip=VALUES(public_ip),scope=VALUES(scope),pool=VALUES(pool),category=VALUES(category),
sources=VALUES(sources),listed_port=VALUES(listed_port),malware=VALUES(malware),first_seen=LEAST(first_seen,VALUES(first_seen)),
last_seen=GREATEST(last_seen,VALUES(last_seen)),flows=flows+VALUES(flows),packets=packets+VALUES(packets),
bytes=bytes+VALUES(bytes)"""
EVENT_SQL = """INSERT IGNORE INTO orby_attack_events (event_id,event_time,rule_name,severity,detection,direction,scope,
pool,local_ip,subscriber_ip,protocol,local_port,remote_port,pps,mbps,remote_ips,syn_ratio,input_if,output_if,details)
VALUES (%s,%s,%s,%s,'c2','out',%s,%s,%s,%s,%s,0,%s,0,0,1,0,0,0,%s)"""


def classify(infos):
    """(categoria, fontes, porta listada, malware) de um IP que casou."""
    bot = [i for i in infos if i[1] == "bot"]
    use = bot or list(infos)
    labels = sorted({FEED_BY_NAME[i[0]].label for i in infos})
    port = next((i[2] for i in use if i[2]), 0)
    malware = ", ".join(sorted({i[3] for i in use if i[3]}))[:120]
    return ("bot" if bot else "reputacao"), ", ".join(labels)[:250], port, malware


def build_hits(rows, idx):
    hits = []
    for (local, sub, scope, pool, remote, proto, rport, pk, by, fl, t0, t1) in rows:
        infos = idx.lookup(remote)
        if not infos:
            continue
        cat, sources, lport, malware = classify(infos)
        cpe = sub or local
        hits.append({"cpe_ip": cpe, "remote_ip": remote, "protocol": proto, "remote_port": int(rport or 0),
                     "public_ip": local, "scope": scope, "pool": pool or "", "subscriber_ip": sub or "",
                     "category": cat, "sources": sources, "listed_port": lport, "malware": malware,
                     "first_seen": t0, "last_seen": t1, "flows": int(fl), "packets": float(pk), "bytes": float(by)})
    return hits


def store(db, hits, events_for=("bot",)):
    cur = db.cursor()
    for h in hits:
        cur.execute(HIT_SQL, (h["cpe_ip"], h["remote_ip"], h["protocol"], h["remote_port"], h["public_ip"], h["scope"],
                              h["pool"], h["category"], h["sources"], h["listed_port"], h["malware"], h["first_seen"],
                              h["last_seen"], h["flows"], h["packets"], h["bytes"]))
    events = 0
    for h in hits:
        if h["category"] not in events_for:
            continue
        day = h["last_seen"].strftime("%Y-%m-%d")
        eid = hashlib.sha256(("c2|%s|%s|%s" % (h["cpe_ip"], h["remote_ip"], day)).encode()).hexdigest()
        rule = ("C2/botnet: " + h["malware"]) if h["malware"] else "C2/botnet: IP de comando conhecido"
        details = {"remote_ip": h["remote_ip"], "listas": h["sources"], "malware": h["malware"],
                   "porta_listada": h["listed_port"], "bytes": h["bytes"], "fluxos": h["flows"],
                   "categoria": h["category"]}
        cur.execute(EVENT_SQL, (eid, h["last_seen"], rule[:100], "high", h["scope"], h["pool"], h["public_ip"],
                                h["subscriber_ip"], h["protocol"], h["remote_port"], json.dumps(details)))
        events += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
    db.commit()
    return events


def prune(db, now, days=RETENTION_DAYS):
    cur = db.cursor()
    cur.execute("DELETE FROM orby_threat_hits WHERE last_seen < %s", (now - timedelta(days=days),))
    db.commit()


# ------------------------------------------------------------------ execucao
def window(state_dir, now):
    end = (now - LAG).replace(second=0, microsecond=0)
    path = Path(state_dir) / "last_end"
    try:
        start = datetime.strptime(path.read_text().strip(), "%Y-%m-%d %H:%M:%S")
    except (OSError, ValueError):
        start = end - timedelta(minutes=15)
    start = max(start, end - MAX_WINDOW)
    return start, end


def save_window(state_dir, end):
    path = Path(state_dir) / "last_end"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(end.strftime("%Y-%m-%d %H:%M:%S"))
    tmp.replace(path)


def run(flows, idx, start, end, db=None, settings=None, chunk=500):
    settings = settings or {}
    if end <= start:
        return [], 0
    remotes = flows.remotes(start, end)
    matched = [ip for ip in remotes if idx.lookup(ip)]
    rows = []
    for n in range(0, len(matched), chunk):
        rows += flows.detail(start, end, matched[n:n + chunk])
    hits = build_hits(rows, idx)
    events = 0
    if db is not None and hits:
        events = store(db, hits, ("bot", "reputacao") if settings.get("events_reputation") else ("bot",))
    return hits, events


def settings_from_env(env):
    disabled = {s.strip() for s in env.get("ORBYMON_THREAT_DISABLED", "").split(",") if s.strip()}
    every = int(env.get("ORBYMON_THREAT_REFRESH_H", "6") or 6)
    if not 1 <= every <= 168:
        raise ValueError("ORBYMON_THREAT_REFRESH_H entre 1 e 168")
    return {"disabled": disabled, "refresh_h": every, "threatfox_key": env.get("THREATFOX_AUTH_KEY", "").strip(),
            "events_reputation": env.get("ORBYMON_THREAT_EVENTS_REPUTATION", "0").strip() == "1"}


def main(argv=None):
    ap = argparse.ArgumentParser(description="OrbyFlow: clientes falando com C2/botnet e IPs de má reputação")
    ap.add_argument("--config", default="/etc/orbymon/bidir.json")
    ap.add_argument("--env-file", help="threat.env (KEY='valor'; lido como dado, nunca executado)")
    ap.add_argument("--state-dir", default=STATE_DIR)
    ap.add_argument("--refresh", action="store_true", help="baixa todas as listas agora")
    ap.add_argument("--dry-run", action="store_true", help="mostra os casamentos sem gravar")
    args = ap.parse_args(argv)
    try:
        from .admin.config_store import read_env
        from .bidir_config import load_profile, read_config
        from .mysql_sink import connection_from_env
        cfg = read_config(args.config)
        profile = load_profile(cfg)
        env = dict(os.environ)
        if args.env_file and Path(args.env_file).exists():
            env.update(read_env(Path(args.env_file)))
        settings = settings_from_env(env)
        Path(args.state_dir).mkdir(parents=True, exist_ok=True)
        db = connection_from_env(read_timeout=300)
        started = time.time()
        try:
            status = refresh(args.state_dir, settings, None if args.dry_run else db, force=args.refresh)
            for name, (ok, err, n) in sorted(status.items()):
                print("lista %-15s %s" % (name, ("%d entradas" % n) if ok else "falha: " + err))
            ours = list(profile["protected_cidrs"]) + list(profile["cgnat_pools"]) + \
                list(profile.get("inside_private_cidrs", [])) + list(cfg.get("extra_infrastructure_cidrs", []))
            idx = load_index(args.state_dir, ours, settings["disabled"])
            flows = MariaSource(db, cfg["source"])
            try:
                from .clickhouse import Client
                client = Client.from_env(timeout=120)
                if client is not None:
                    flows = ClickSource(client, cfg["source"])
            except Exception as exc:
                print("AVISO ClickHouse indisponivel, usando MariaDB: %s" % str(exc)[:120])
            now = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
            start, end = window(args.state_dir, now)
            hits, events = run(flows, idx, start, end, None if args.dry_run else db, settings)
            if not args.dry_run:
                save_window(args.state_dir, end)
                prune(db, now)
            bots = sum(1 for h in hits if h["category"] == "bot")
            print("ameacas %s a %s: %d entradas nas listas, %d par(es) cliente x IP listado (%d C2/botnet), "
                  "%d evento(s) novo(s), %.0f s" % (start, end, idx.size(), len(hits), bots, events,
                                                   time.time() - started))
            if args.dry_run:
                for h in sorted(hits, key=lambda x: -x["bytes"])[:50]:
                    print("  %-15s -> %-39s %s/%s %-9s %s %s" % (h["cpe_ip"], h["remote_ip"], h["protocol"],
                                                                 h["remote_port"], h["category"], h["sources"],
                                                                 h["malware"]))
        finally:
            db.close()
        return 0
    except Exception as exc:
        print("FALHA ameacas: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
