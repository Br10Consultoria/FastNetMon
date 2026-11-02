"""Tela unica de Ataques: eventos dos dois sentidos agrupados em ataques, com filtros combinados, e o detalhe de cada
ataque (origem, destino, portas, protocolo, IP privado do assinante, IPs remotos com ASN/pais, minuto a minuto).

Eventos vem do MariaDB (orby_attack_events, guardados). O detalhe vem dos fluxos por minuto: do ClickHouse quando
configurado e com dados no periodo (retencao longa), senao do MariaDB (orby_flow_minute, ~2 dias).
Somente leitura. Os resultados contem IPs de assinantes: so para o painel (acesso autenticado)."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
import json

from .customer_report import ReportError, _match_sql, parse_targets

MAX_EVENTS = 5000
MAX_ATTACKS = 300
GROUP_GAP_MIN = 30
MAX_SPAN_DAYS = 31
SEV_RANK = {"warning": 1, "high": 2, "critical": 3}
SCOPE_PT = {"dedicated": "IP dedicado", "cgnat_pool": "IP de pool CGNAT", "cgnat_private": "assinante CGNAT",
            "cgnat_subscriber": "assinante CGNAT (via log A10)", "infra": "infraestrutura"}
SERVICES = {("udp", 53): "DNS", ("udp", 123): "NTP", ("udp", 1900): "SSDP", ("udp", 11211): "memcached",
            ("udp", 389): "CLDAP", ("udp", 19): "chargen", ("udp", 161): "SNMP", ("udp", 3702): "WS-Discovery",
            ("udp", 5060): "SIP", ("udp", 3283): "ARD", ("udp", 10001): "Ubiquiti", ("udp", 37810): "DVR",
            ("tcp", 22): "SSH", ("tcp", 23): "Telnet", ("tcp", 2323): "Telnet", ("tcp", 80): "HTTP",
            ("tcp", 443): "HTTPS", ("tcp", 3389): "RDP", ("tcp", 445): "SMB", ("tcp", 25): "SMTP",
            ("tcp", 8080): "HTTP-alt", ("tcp", 7547): "TR-069", ("udp", 443): "QUIC"}
AMPLIFIERS = {53, 123, 1900, 11211, 389, 19, 161, 3702, 3283, 10001, 37810}


class AttackError(ValueError):
    pass


def service(proto, port):
    return SERVICES.get((proto or "", int(port or 0)), "")


# ------------------------------------------------------------------ filtros
def parse_filters(args, now, parse_time, tz, customers=()):
    """Valida o formulario. Horarios no fuso tz -> UTC ingenuo."""
    f = {k: (args.get(k) or "").strip()[:200] for k in
         ("inicio", "fim", "sentido", "ip", "cliente", "remoto", "porta", "proto", "regra", "sev", "tipo")}
    f["sentido"] = f["sentido"] if f["sentido"] in ("in", "out") else ""
    f["sev"] = f["sev"] if f["sev"] in SEV_RANK else ""
    f["tipo"] = f["tipo"] if f["tipo"] in ("flow", "nat") else ""
    end = parse_time(f["fim"], tz) if f["fim"] else now
    start = parse_time(f["inicio"], tz) if f["inicio"] else end - timedelta(days=1)
    if start is None or end is None:
        raise AttackError("horário não reconhecido (use 2026-10-30 14:05)")
    if end <= start:
        raise AttackError("fim antes do início")
    if end - start > timedelta(days=MAX_SPAN_DAYS):
        raise AttackError("período de no máximo %d dias" % MAX_SPAN_DAYS)
    f["start"], f["end"] = start, end
    f["nets"] = []
    if f["cliente"]:
        c = next((x for x in customers if str(x["id"]) == f["cliente"]), None)
        if not c:
            raise AttackError("cliente não encontrado")
        f["nets"] = parse_targets(" ".join(c["prefixes"]))
    if f["ip"]:
        try:
            f["nets"] += parse_targets(f["ip"])
        except ReportError as exc:
            raise AttackError(str(exc))
    if f["remoto"]:
        try:
            f["remoto"] = str(ip_address(f["remoto"]))
        except ValueError:
            raise AttackError("IP remoto inválido")
    if f["porta"]:
        if not f["porta"].isdigit() or not 0 < int(f["porta"]) < 65536:
            raise AttackError("porta inválida")
        f["porta_n"] = int(f["porta"])
    if f["proto"] and not f["proto"].isalnum():
        raise AttackError("protocolo inválido")
    f["proto"] = f["proto"].lower()
    return f


def _event_where(f):
    # a janela do evento termina no minuto do event_time; inclui eventos ate 1 h antes para fechar o agrupamento
    where = ["event_time>=%s", "event_time<%s"]
    params = [f["start"], f["end"]]
    if f["sentido"]:
        where.append("direction=%s")
        params.append(f["sentido"])
    if f["tipo"]:
        where.append("detection=%s")
        params.append(f["tipo"])
    if f["sev"]:
        where.append("severity IN (%s)" % ",".join(["%s"] * sum(1 for v in SEV_RANK.values()
                                                                  if v >= SEV_RANK[f["sev"]])))
        params += [k for k, v in SEV_RANK.items() if v >= SEV_RANK[f["sev"]]]
    if f["regra"]:
        where.append("rule_name=%s")
        params.append(f["regra"])
    if f["proto"]:
        where.append("protocol=%s")
        params.append(f["proto"])
    if f.get("porta_n"):
        where.append("(local_port=%s OR remote_port=%s OR JSON_CONTAINS(details,%s,'$.top_portas'))")
        params += [f["porta_n"], f["porta_n"], json.dumps({"porta": f["porta_n"]})]
    if f["nets"]:
        sql, p = _match_sql(("local_ip", "subscriber_ip"), f["nets"])
        where.append(sql)
        params += p
    return where, params


EVENT_COLS = ("event_time", "rule_name", "severity", "detection", "direction", "scope", "pool", "local_ip",
              "subscriber_ip", "protocol", "local_port", "remote_port", "pps", "mbps", "remote_ips", "syn_ratio",
              "details")


def fetch_events(cur, f, remote_locals=None):
    """Eventos do periodo. remote_locals: IPs nossos que falaram com o remoto filtrado (do backend de fluxos)."""
    where, params = _event_where(f)
    if f["remoto"]:
        cond = "JSON_CONTAINS(details,%s,'$.top_remote_ips')"
        params.append(json.dumps(f["remoto"]))
        if remote_locals:
            locals_ = sorted(remote_locals)[:2000]
            ph = ",".join(["%s"] * len(locals_))
            cond = "(%s OR local_ip IN (%s) OR subscriber_ip IN (%s))" % (cond, ph, ph)
            params += locals_ + locals_
        where.append(cond)
    cur.execute("SELECT " + ",".join(EVENT_COLS) + " FROM orby_attack_events WHERE " + " AND ".join(where) +
                " ORDER BY event_time LIMIT %d" % MAX_EVENTS, params)
    out = []
    for row in cur.fetchall():
        e = dict(zip(EVENT_COLS, row))
        try:
            e["details"] = json.loads(e["details"]) if isinstance(e["details"], (str, bytes)) else (e["details"] or {})
        except ValueError:
            e["details"] = {}
        out.append(e)
    return out


# ------------------------------------------------------------------ agrupamento
def entity_of(e):
    """IP 'nosso' que identifica o ataque: assinante (privado) no CGNAT, senao o IP publico/dedicado."""
    if e["scope"] in ("cgnat_private", "cgnat_subscriber") and e["subscriber_ip"]:
        return "subscriber_ip", e["subscriber_ip"]
    return "local_ip", e["local_ip"]


def group_key(e):
    col, ip = entity_of(e)
    return (e["direction"], e["rule_name"], e["scope"], col, ip, e["protocol"] or "", int(e["local_port"] or 0),
            int(e["remote_port"] or 0))


def group_events(events, gap_minutes=GROUP_GAP_MIN, limit=MAX_ATTACKS):
    """Eventos repetidos do mesmo alvo/regra (cooldown) viram um ataque com inicio, fim e pico."""
    by_key = {}
    for e in sorted(events, key=lambda x: x["event_time"]):
        k = group_key(e)
        lst = by_key.setdefault(k, [])
        if lst and e["event_time"] - lst[-1]["last"] <= timedelta(minutes=gap_minutes):
            _merge(lst[-1], e)
        else:
            lst.append(_new(k, e))
    attacks = [a for lst in by_key.values() for a in lst]
    for a in attacks:
        _finish(a)
    attacks.sort(key=lambda a: a["last"], reverse=True)
    return attacks[:limit], len(attacks)


def _new(k, e):
    d = e["details"]
    minutes = int(d.get("minutes") or 1)
    a = {"direction": k[0], "rule": k[1], "scope": k[2], "entity_col": k[3], "entity": k[4], "protocol": k[5],
         "local_port": k[6], "remote_port": k[7], "first": e["event_time"], "last": e["event_time"],
         "start": e["event_time"] - timedelta(minutes=minutes - 1), "events": 0, "severity": e["severity"],
         "detection": e["detection"], "pool": e["pool"], "pps": 0.0, "mbps": 0.0, "remote_ips": 0,
         "allocs": 0, "active_ports": 0, "remotes": Counter(), "publics": Counter(), "subs": Counter(),
         "ports": {}, "local_ips": Counter()}
    _merge(a, e)
    return a


def _merge(a, e):
    d = e["details"]
    a["last"] = max(a["last"], e["event_time"])
    a["events"] += 1
    if SEV_RANK.get(e["severity"], 0) > SEV_RANK.get(a["severity"], 0):
        a["severity"] = e["severity"]
    a["pps"] = max(a["pps"], float(e["pps"] or 0))
    a["mbps"] = max(a["mbps"], float(e["mbps"] or 0))
    a["remote_ips"] = max(a["remote_ips"], int(e["remote_ips"] or 0))
    a["allocs"] = max(a["allocs"], int(d.get("allocs_per_min") or 0))
    a["active_ports"] = max(a["active_ports"], int(d.get("active_ports") or 0))
    a["pool"] = a["pool"] or e["pool"]
    a["local_ips"][e["local_ip"]] += 1
    for ip in d.get("top_remote_ips") or []:
        a["remotes"][ip] += 1
    for ip in d.get("public_ips") or []:
        a["publics"][ip] += 1
    for s in d.get("top_subscribers") or []:
        if isinstance(s, dict) and s.get("ip"):
            a["subs"][s["ip"]] += float(s.get("share") or 0)
    for p in d.get("top_portas") or []:
        if isinstance(p, dict):
            key = (p.get("protocolo") or "", p.get("porta"))
            a["ports"][key] = max(a["ports"].get(key, 0), int(p.get("destinos") or 0))


def _finish(a):
    a["end"] = a["last"] + timedelta(minutes=1)
    a["remotes_top"] = [ip for ip, _ in a.pop("remotes").most_common(5)]
    a["publics_top"] = [ip for ip, _ in a.pop("publics").most_common(5)]
    a["subs_top"] = [ip for ip, _ in a.pop("subs").most_common(5)]
    a["ports_top"] = sorted(({"protocolo": k[0], "porta": k[1], "destinos": v} for k, v in a.pop("ports").items()),
                            key=lambda x: -x["destinos"])[:5]
    lips = a.pop("local_ips")
    a["public_ip"] = (lips.most_common(1)[0][0] if lips else "")
    if a["entity_col"] == "subscriber_ip" and a["public_ip"] and a["public_ip"] != a["entity"] and \
            a["public_ip"] not in a["publics_top"]:
        a["publics_top"].insert(0, a["public_ip"])
    a["minutes"] = int((a["end"] - a["start"]).total_seconds() // 60)
    a["service"] = service(a["protocol"], a["remote_port"]) or service(a["protocol"], a["local_port"])
    a["origem"], a["destino"], a["porta_origem"], a["porta_destino"] = endpoints(a)


def endpoints(a):
    """(origem, destino, porta origem, porta destino) no sentido do ataque."""
    ours = a["entity"]
    if a["entity_col"] == "subscriber_ip" and a.get("public_ip") and a["public_ip"] != a["entity"]:
        ours = "%s (público %s)" % (a["entity"], a["public_ip"])
    if a["remotes_top"]:
        remote = ", ".join(a["remotes_top"][:2]) + ("…" if len(a["remotes_top"]) > 2 or a["remote_ips"] > 2 else "")
    elif a["remote_ips"]:
        remote = "%d IPs" % a["remote_ips"]
    elif a["ports_top"]:
        remote = "%d destinos" % max(p["destinos"] for p in a["ports_top"])
    else:
        remote = "—"
    if a["direction"] == "in":
        return remote, ours, a["remote_port"] or "", a["local_port"] or ""
    return ours, remote, a["local_port"] or "", a["remote_port"] or ""


def key_params(a):
    """Parametros de URL que identificam um ataque (para o detalhe)."""
    return {"sentido": a["direction"], "regra": a["rule"], "escopo": a["scope"], "col": a["entity_col"],
            "alvo": a["entity"], "proto": a["protocol"], "pl": a["local_port"], "pr": a["remote_port"],
            "de": a["start"].strftime("%Y-%m-%dT%H:%M"), "ate": a["end"].strftime("%Y-%m-%dT%H:%M")}


def parse_key(args):
    try:
        k = {"direction": args["sentido"], "rule": args.get("regra", "")[:100], "scope": args.get("escopo", "")[:16],
             "entity_col": args["col"], "entity": str(ip_address(args["alvo"])),
             "protocol": (args.get("proto") or "")[:12], "local_port": int(args.get("pl") or 0),
             "remote_port": int(args.get("pr") or 0),
             "start": datetime.strptime(args["de"], "%Y-%m-%dT%H:%M"),
             "end": datetime.strptime(args["ate"], "%Y-%m-%dT%H:%M")}
    except (KeyError, ValueError):
        raise AttackError("ataque não identificado (link incompleto)")
    if k["direction"] not in ("in", "out") or k["entity_col"] not in ("local_ip", "subscriber_ip"):
        raise AttackError("ataque não identificado")
    if k["protocol"] and not k["protocol"].isalnum():
        raise AttackError("protocolo inválido")
    if not (0 <= k["local_port"] < 65536 and 0 <= k["remote_port"] < 65536):
        raise AttackError("porta inválida")
    if not timedelta(0) < k["end"] - k["start"] <= timedelta(days=MAX_SPAN_DAYS):
        raise AttackError("período inválido")
    return k


# ------------------------------------------------------------------ fluxos (detalhe)
class MariaFlows:
    """orby_flow_minute no MariaDB (retencao curta). Consultas sempre por IP + periodo (indices por IP)."""
    name = "MariaDB (detalhado de ~2 dias)"

    def __init__(self, cur, source="huawei"):
        self.cur, self.source = cur, source

    def since(self):
        self.cur.execute("SELECT MIN(bucket_utc) FROM orby_flow_minute WHERE source=%s", (self.source,))
        row = self.cur.fetchone()
        return row[0] if row else None

    def _where(self, k, start, end, remote=None):
        w = ["source=%s", "bucket_utc>=%s", "bucket_utc<%s", "direction=%s", k["entity_col"] + "=%s"]
        p = [self.source, start, end, k["direction"], k["entity"]]
        if k["protocol"]:
            w.append("protocol=%s")
            p.append(k["protocol"])
        if k["local_port"]:
            w.append("local_port=%s")
            p.append(k["local_port"])
        if k["remote_port"]:
            w.append("remote_port=%s")
            p.append(k["remote_port"])
        if remote:
            w.append("remote_ip=%s")
            p.append(remote)
        return " AND ".join(w), p

    def _rows(self, sql, params, keys):
        self.cur.execute(sql, params)
        return [dict(zip(keys, r)) for r in self.cur.fetchall()]

    def detail(self, k, start, end, remote=None, limit=100):
        w, p = self._where(k, start, end, remote)
        t = "FROM orby_flow_minute WHERE " + w
        out = {}
        out["totais"] = self._rows("SELECT SUM(packets),SUM(bytes),SUM(flows),COUNT(DISTINCT remote_ip),"
                                   "MIN(bucket_utc),MAX(bucket_utc) " + t, p,
                                   ("pacotes", "bytes", "fluxos", "remotos", "de", "ate"))[0]
        out["conversas"] = self._rows(
            "SELECT remote_ip,protocol,local_port,remote_port,SUM(packets),SUM(bytes),SUM(flows),local_ip,"
            "MAX(subscriber_ip) " + t + " GROUP BY remote_ip,protocol,local_port,remote_port,local_ip "
            "ORDER BY SUM(packets) DESC LIMIT %d" % limit, p,
            ("remote_ip", "protocol", "local_port", "remote_port", "pacotes", "bytes", "fluxos", "local_ip",
             "subscriber_ip"))
        out["portas"] = self._rows(
            "SELECT protocol,local_port,remote_port,SUM(packets),SUM(bytes),COUNT(DISTINCT remote_ip) " + t +
            " GROUP BY protocol,local_port,remote_port ORDER BY SUM(packets) DESC LIMIT 20", p,
            ("protocol", "local_port", "remote_port", "pacotes", "bytes", "remotos"))
        out["minutos"] = self._rows(
            "SELECT bucket_utc,SUM(packets),SUM(bytes),COUNT(DISTINCT remote_ip) " + t +
            " GROUP BY bucket_utc ORDER BY bucket_utc", p, ("bucket", "pacotes", "bytes", "remotos"))
        other = "local_ip" if k["entity_col"] == "subscriber_ip" else "subscriber_ip"
        out["outros"] = self._rows(
            "SELECT " + other + ",SUM(packets) " + t + " AND " + other + "<>'' GROUP BY " + other +
            " ORDER BY SUM(packets) DESC LIMIT 20", p, ("ip", "pacotes"))
        return out

    def locals_for_remote(self, remote, start, end):
        return None                        # sem indice por IP remoto no MariaDB: so pelos principais do evento


class ClickFlows:
    """flow_minute no ClickHouse (retencao longa, filtros por IP com indice bloom)."""
    name = "ClickHouse"

    def __init__(self, client, source="huawei"):
        self.c, self.source = client, source
        self.t = "%s.flow_minute" % client.database

    def since(self):
        rows = self.c.query("SELECT min(bucket) AS b, count() AS n FROM %s WHERE source={s:String}" % self.t,
                            {"s": self.source})
        if not rows or not int(rows[0]["n"] or 0):
            return None
        return datetime.strptime(rows[0]["b"], "%Y-%m-%d %H:%M:%S")

    def _where(self, k, start, end, remote=None):
        w = ["source={s:String}", "bucket>={a:DateTime('UTC')}", "bucket<{b:DateTime('UTC')}",
             "direction={d:String}", "%s={e:String}" % k["entity_col"]]
        p = {"s": self.source, "a": start, "b": end, "d": k["direction"], "e": k["entity"]}
        if k["protocol"]:
            w.append("protocol={pr:String}")
            p["pr"] = k["protocol"]
        if k["local_port"]:
            w.append("local_port={lp:UInt16}")
            p["lp"] = k["local_port"]
        if k["remote_port"]:
            w.append("remote_port={rp:UInt16}")
            p["rp"] = k["remote_port"]
        if remote:
            w.append("remote_ip={ri:String}")
            p["ri"] = remote
        return " AND ".join(w), p

    def _q(self, sql, p, keys):
        rows = self.c.query(sql, p)
        out = []
        for r in rows:
            d = {}
            for key, (_, v) in zip(keys, r.items()):
                d[key] = v
            out.append(d)
        return out

    def detail(self, k, start, end, remote=None, limit=100):
        w, p = self._where(k, start, end, remote)
        t = "FROM %s WHERE %s" % (self.t, w)
        out = {}
        tot = self._q("SELECT sum(packets) AS a,sum(bytes) AS b,sum(flows) AS c,uniqExact(remote_ip) AS d,"
                      "min(bucket) AS e,max(bucket) AS f " + t, p,
                      ("pacotes", "bytes", "fluxos", "remotos", "de", "ate"))
        out["totais"] = tot[0] if tot else {}
        if not out["totais"].get("pacotes"):
            out["totais"]["de"] = out["totais"]["ate"] = None
        out["conversas"] = self._q(
            "SELECT remote_ip AS a,protocol AS b,local_port AS c,remote_port AS d,sum(packets) AS e,sum(bytes) AS f,"
            "sum(flows) AS g,local_ip AS h,max(subscriber_ip) AS i " + t +
            " GROUP BY remote_ip,protocol,local_port,remote_port,local_ip ORDER BY e DESC LIMIT %d" % limit, p,
            ("remote_ip", "protocol", "local_port", "remote_port", "pacotes", "bytes", "fluxos", "local_ip",
             "subscriber_ip"))
        out["portas"] = self._q(
            "SELECT protocol AS a,local_port AS b,remote_port AS c,sum(packets) AS d,sum(bytes) AS e,"
            "uniqExact(remote_ip) AS f " + t + " GROUP BY protocol,local_port,remote_port ORDER BY d DESC LIMIT 20",
            p, ("protocol", "local_port", "remote_port", "pacotes", "bytes", "remotos"))
        out["minutos"] = self._q(
            "SELECT bucket AS a,sum(packets) AS b,sum(bytes) AS c,uniqExact(remote_ip) AS d " + t +
            " GROUP BY bucket ORDER BY bucket", p, ("bucket", "pacotes", "bytes", "remotos"))
        other = "local_ip" if k["entity_col"] == "subscriber_ip" else "subscriber_ip"
        out["outros"] = self._q(
            "SELECT %s AS a,sum(packets) AS b %s AND %s<>'' GROUP BY %s ORDER BY b DESC LIMIT 20"
            % (other, t, other, other), p, ("ip", "pacotes"))
        for key in ("totais",):
            for f in ("de", "ate"):
                if isinstance(out[key].get(f), str):
                    out[key][f] = datetime.strptime(out[key][f], "%Y-%m-%d %H:%M:%S")
        for m in out["minutos"]:
            m["bucket"] = datetime.strptime(m["bucket"], "%Y-%m-%d %H:%M:%S")
        return out

    def locals_for_remote(self, remote, start, end):
        rows = self.c.query("SELECT DISTINCT local_ip AS a, subscriber_ip AS b FROM %s WHERE source={s:String} AND "
                            "bucket>={x:DateTime('UTC')} AND bucket<{y:DateTime('UTC')} AND remote_ip={r:String} "
                            "LIMIT 5000" % self.t, {"s": self.source, "x": start, "y": end, "r": remote})
        out = set()
        for r in rows:
            out.update(v for v in (r["a"], r["b"]) if v)
        return out


def pick_backend(maria, click, start):
    """ClickHouse quando cobre o inicio do periodo; senao o que tiver o dado mais antigo."""
    options = []
    for b in (click, maria):
        if b is None:
            continue
        try:
            options.append((b, b.since()))
        except Exception:
            continue
    covering = [(b, s) for b, s in options if s is not None and s <= start]
    if covering:
        return covering[0]
    have = [(b, s) for b, s in options if s is not None]
    return min(have, key=lambda x: x[1]) if have else (maria, None)


# ------------------------------------------------------------------ detalhe
def build_detail(cur, k, maria, click=None, geo=None, remote=None, limit=50):
    """Eventos do ataque + fluxos do periodo (com folga de 2 min antes) + resumo em texto."""
    cur.execute("SELECT " + ",".join(EVENT_COLS) + " FROM orby_attack_events WHERE event_time>=%s AND event_time<%s "
                "AND direction=%s AND rule_name=%s AND " + k["entity_col"] + "=%s ORDER BY event_time LIMIT 500",
                (k["start"], k["end"], k["direction"], k["rule"], k["entity"]))
    events = []
    for row in cur.fetchall():
        e = dict(zip(EVENT_COLS, row))
        try:
            e["details"] = json.loads(e["details"]) if isinstance(e["details"], (str, bytes)) else (e["details"] or {})
        except ValueError:
            e["details"] = {}
        if group_key(e)[5:] == (k["protocol"], k["local_port"], k["remote_port"]) and e["scope"] == k["scope"]:
            events.append(e)
    attack = None
    if events:
        groups, _ = group_events(events, gap_minutes=10 ** 6)
        attack = groups[0]
    start = k["start"] - timedelta(minutes=2)
    end = k["end"]
    backend, since = pick_backend(maria, click, start)
    flows, error = None, None
    if since is None or since >= end:
        error = "sem fluxos guardados para esse período (fora da retenção do detalhado)"
    else:
        try:
            flows = backend.detail(k, max(start, since), end, remote=remote, limit=limit)
        except Exception as exc:
            error = "consulta dos fluxos falhou: %s" % (str(exc)[:200] or type(exc).__name__)
    if flows:
        flows["outros"] = [o for o in flows["outros"] if o["ip"] and o["ip"] != k["entity"]]
        for c in flows["conversas"]:
            c.update(geo_info(geo, c["remote_ip"]))
            c["servico"] = service(c["protocol"], c["remote_port"]) or service(c["protocol"], c["local_port"])
        for p in flows["portas"]:
            p["servico"] = service(p["protocol"], p["remote_port"]) or service(p["protocol"], p["local_port"])
        flows["asns"] = _asn_summary(flows["conversas"])
    return {"key": k, "attack": attack, "events": events, "flows": flows, "backend": backend.name if backend else "",
            "since": since, "partial": bool(since and since > start), "error": error}


def geo_info(geo, ip):
    if geo is None:
        return {"asn": "", "asn_name": "", "pais": ""}
    try:
        g = geo.lookup(ip) or {}
    except Exception:
        g = {}
    return {"asn": g.get("asn") or "", "asn_name": g.get("asn_name") or "",
            "pais": g.get("country_iso") or g.get("country") or ""}


def _asn_summary(conversas):
    acc = {}
    for c in conversas:
        if not c.get("asn"):
            continue
        a = acc.setdefault(c["asn"], {"asn": c["asn"], "nome": c["asn_name"], "ips": set(), "pacotes": 0.0,
                                      "paises": Counter()})
        a["ips"].add(c["remote_ip"])
        a["pacotes"] += float(c["pacotes"] or 0)
        if c["pais"]:
            a["paises"][c["pais"]] += 1
    out = sorted(acc.values(), key=lambda a: -a["pacotes"])[:15]
    for a in out:
        a["ips"] = len(a["ips"])
        a["paises"] = ", ".join(p for p, _ in a["paises"].most_common(3))
    return out


def summary_text(d, fmt_ts, identify=None):
    """Texto curto para explicar o ataque (cliente, equipe ou resposta de denuncia)."""
    k, a, fl = d["key"], d["attack"], d["flows"]
    sent = "recebido" if k["direction"] == "in" else "originado"
    L = ["Ataque %s — regra %s" % (sent, k["rule"] or "?")]
    who = SCOPE_PT.get(k["scope"], k["scope"])
    L.append("IP da rede: %s (%s)%s" % (k["entity"], who, (" — " + identify) if identify else ""))
    if a and a.get("publics_top") and k["entity_col"] == "subscriber_ip":
        L.append("IP público usado (CGNAT): %s" % ", ".join(a["publics_top"][:3]))
    L.append("Período: %s a %s" % (fmt_ts(k["start"]), fmt_ts(k["end"])))
    if a:
        if a["detection"] == "nat":
            L.append("Detecção: alocação de portas NAT (pico %d/min, %d portas ativas)" % (a["allocs"],
                                                                                         a["active_ports"]))
        else:
            L.append("Pico: %.0f pacotes/s · %.1f Mbps · %d IPs remotos" % (a["pps"], a["mbps"], a["remote_ips"]))
    if fl and fl["portas"]:
        p = fl["portas"][0]
        port = p["remote_port"]                          # in: porta de origem remota; out: porta de destino
        lbl = "porta de origem" if k["direction"] == "in" else "porta de destino"
        svc = p["servico"]
        L.append("Principal: %s %s %s%s" % (p["protocol"], lbl, port or "variável", (" (%s)" % svc) if svc else ""))
        if k["direction"] == "in" and p["protocol"] == "udp" and int(p["remote_port"] or 0) in AMPLIFIERS:
            L.append("Padrão de ataque de amplificação %s: servidores %s abertos na internet respondendo para o IP "
                     "(os IPs de origem são refletores, não o atacante real)." % (svc, svc))
        if k["direction"] == "out" and int(p["remote_port"] or 0) in (22, 23, 2323):
            L.append("Padrão de varredura %s para muitos destinos: típico de equipamento infectado (botnet)."
                     % (svc or ""))
    if fl and fl["totais"].get("remotos"):
        L.append("IPs remotos distintos nos fluxos amostrados: %d" % int(fl["totais"]["remotos"]))
    L.append("Valores estimados a partir de NetFlow amostrado (1:2048).")
    return "\n".join(L)


def svg_series(points, key="pacotes", width=720, height=130, divisor=60.0, label="pacotes/s", tz=None):
    """Linha minuto a minuto (servidor; o painel nao usa JavaScript)."""
    if not points:
        return ""
    vals = [float(p[key] or 0) / divisor for p in points]
    top = max(vals) or 1.0
    n = len(vals)
    x = lambda i: 4 + (i * (width - 8) / max(1, n - 1))
    y = lambda v: height - 20 - (v / top) * (height - 34)
    pts = " ".join("%.1f,%.1f" % (x(i), y(v)) for i, v in enumerate(vals))
    area = "%.1f,%d %s %.1f,%d" % (x(0), height - 20, pts, x(n - 1), height - 20)
    parts = ['<svg class="chart" viewBox="0 0 %d %d" role="img" aria-label="%s por minuto">' % (width, height, label),
             '<polygon class="area" points="%s"/>' % area, '<polyline class="line" points="%s"/>' % pts]
    step = max(1, n // 6)
    for i in range(0, n, step):
        b = points[i]["bucket"]
        if tz is not None:
            b = b.replace(tzinfo=timezone.utc).astimezone(tz)
        parts.append('<text x="%.1f" y="%d" class="lbl">%s</text>' % (x(i), height - 4, b.strftime("%H:%M")))
    parts.append('<text x="4" y="12" class="lbl">máx. %s %s</text></svg>' % (human(top), label))
    return "".join(parts)


def mbps(v):
    v = float(v or 0)
    return ("%.0f" % v if v >= 100 else "%.1f" % v).replace(".", ",")


def human(v):
    v = float(v or 0)
    for unit in ("", " mil", " mi", " bi"):
        if abs(v) < 1000:
            return ("%.0f%s" % (v, unit)) if unit == "" or v >= 100 else ("%.1f%s" % (v, unit)).replace(".", ",")
        v /= 1000.0
    return "%.0f tri" % v
