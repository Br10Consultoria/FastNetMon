"""Detector bidirecional (F4): ataques RECEBIDOS e ORIGINADOS, cientes de CGNAT.

Diferencas em relacao a fase 3:
- soma o trafego do mesmo alvo entre interfaces (um ataque dividido em dois uplinks
  nao passa mais despercebido); a interface continua registrada para atribuicao;
- avalia a saida (nossa rede -> internet), alem da entrada;
- limites por escopo: IP dedicado, IP de pool CGNAT (compartilhado), IP privado do
  assinante visto antes do NAT e assinante resolvido pelo log NAT do A10;
- usa porta de origem de servico (amplificacao/reflexao), proporcao SYN e IPs remotos;
- regras NAO amostradas baseadas em alocacao de portas do A10.

Somente alerta: nenhuma acao em roteadores, A10 ou firewall.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
import sys

from .bidir_config import DEFAULT_CONFIG, read_config
from .mysql_sink import ALERT_SQL, alert_to_row, connection_from_env

COLUMNS = ("bucket_utc", "direction", "scope", "pool", "local_ip", "subscriber_ip",
           "remote_ip", "protocol", "local_port", "remote_port", "input_if",
           "output_if", "packets", "bytes", "syn_packets", "zero_port_packets")
SQL_ROWS = ("SELECT " + ",".join(COLUMNS) + """ FROM orby_flow_minute
WHERE source=%s AND bucket_utc >= %s AND bucket_utc < %s
ORDER BY bucket_utc LIMIT %s""")
SQL_NAT = """SELECT bucket_utc,inside_ip,allocs,frees,active_ports FROM orby_nat_user_minute
WHERE bucket_utc >= %s AND bucket_utc < %s ORDER BY bucket_utc LIMIT %s"""
EVENT_SQL = """INSERT IGNORE INTO orby_attack_events (event_id,event_time,rule_name,severity,
detection,direction,scope,pool,local_ip,subscriber_ip,protocol,local_port,remote_port,
pps,mbps,remote_ips,syn_ratio,input_if,output_if,details) VALUES (""" + ",".join(["%s"] * 20) + ")"
STATE_KEY = "source=%s AND rule_name=%s AND direction=%s AND scope=%s AND entity=%s AND " \
            "protocol=%s AND local_port=%s AND remote_port=%s"


class _Acc:
    __slots__ = ("packets", "bytes", "syn", "zero", "remotes", "ifaces", "subs", "pubs", "pool")

    def __init__(self):
        self.packets = self.bytes = self.syn = self.zero = 0.0
        self.remotes, self.ifaces, self.subs, self.pubs = Counter(), Counter(), Counter(), Counter()
        self.pool = ""


def _entities(row):
    scope = row["scope"]
    if scope == "cgnat_pool":
        yield "cgnat_pool", row["local_ip"]
        if row["subscriber_ip"]:
            yield "cgnat_subscriber", row["subscriber_ip"]
    elif scope in ("dedicated", "cgnat_private"):
        yield scope, row["local_ip"]


def _minute_ok(acc, limits):
    pps = acc.packets / 60
    mbps = acc.bytes * 8 / 60e6
    remote_ips = len(acc.remotes)
    ratio = acc.syn / acc.packets if acc.packets else 0.0
    zero = acc.zero / acc.packets if acc.packets else 0.0
    ok = ((("min_pps" not in limits) or pps >= limits["min_pps"]) and
          (("min_mbps" not in limits) or mbps >= limits["min_mbps"]) and
          (("min_remote_ips" not in limits) or remote_ips >= limits["min_remote_ips"]) and
          (("min_syn_ratio" not in limits) or ratio >= limits["min_syn_ratio"]) and
          (("min_zero_port_ratio" not in limits) or zero >= limits["min_zero_port_ratio"]))
    return ok, pps, mbps, remote_ips, ratio, zero


def scaled(limits, factor):
    if factor == 1:
        return limits
    return {k: (v * factor if k in ("min_pps", "min_mbps") else v) for k, v in limits.items()}


def evaluate(rows, rule, start, exc=None, dyn=None):
    """Eventos de fluxo para uma regra, na janela [start, start+consecutive_minutes).
    exc: excecoes (exceptions.Matcher); dyn: limites por hora (baseline.Limits)."""
    n = rule["consecutive_minutes"]
    end = start + timedelta(minutes=n)
    limits = rule["limits"]
    split = set(rule["split_by"])
    protocols = set(rule["protocols"])
    lports, rports = set(rule.get("local_ports", ())), set(rule.get("remote_ports", ()))
    groups = defaultdict(dict)
    for row in rows:
        if (row["direction"] != rule["direction"] or row["protocol"] not in protocols
                or not start <= row["bucket_utc"] < end):
            continue
        if (lports and row["local_port"] not in lports) or (rports and row["remote_port"] not in rports):
            continue
        if exc and exc.ignore_row(rule["name"], rule["direction"], (row["local_ip"], row["subscriber_ip"]),
                                  row["remote_ip"]):
            continue
        for vscope, entity in _entities(row):
            if vscope not in limits:
                continue
            key = (vscope, entity, row["protocol"],
                   row["local_port"] if "local_port" in split else 0,
                   row["remote_port"] if "remote_port" in split else 0)
            acc = groups[key].setdefault(row["bucket_utc"], _Acc())
            acc.packets += float(row["packets"])
            acc.bytes += float(row["bytes"])
            acc.syn += float(row["syn_packets"])
            acc.zero += float(row.get("zero_port_packets") or 0.0)
            acc.remotes[row["remote_ip"]] += float(row["packets"])
            acc.ifaces[(int(row["input_if"]), int(row["output_if"]))] += float(row["packets"])
            acc.pool = row["pool"] or acc.pool
            if vscope == "cgnat_pool" and row["subscriber_ip"]:
                acc.subs[row["subscriber_ip"]] += float(row["packets"])
            if vscope == "cgnat_subscriber":
                acc.pubs[row["local_ip"]] += float(row["packets"])
    events = []
    for (vscope, entity, protocol, lport, rport), series in sorted(groups.items()):
        accs = [series.get(start + timedelta(minutes=i)) for i in range(n)]
        if any(a is None for a in accs):
            continue
        mult = exc.multiplier(rule["name"], rule["direction"], entity) if exc else 1.0
        used, dynamic = [], False
        for i in range(n):
            lim, d = dyn.get(rule["name"], vscope, limits[vscope], start + timedelta(minutes=i)) if dyn \
                else (limits[vscope], False)
            used.append(scaled(lim, mult))
            dynamic = dynamic or d
        checks = [_minute_ok(a, lim) for a, lim in zip(accs, used)]
        if not all(c[0] for c in checks):
            continue
        last = accs[-1]
        subs = Counter()
        for a in accs:
            subs.update(a.subs)
        total = sum(subs.values()) or 1
        top_if = last.ifaces.most_common(1)[0][0]
        events.append({
            "rule": rule["name"],
            "direction": rule["direction"], "scope": vscope, "pool": last.pool,
            "entity": entity,
            "local_ip": (last.pubs.most_common(1)[0][0] if vscope == "cgnat_subscriber" and last.pubs
                         else entity),
            "subscriber_ip": entity if vscope in ("dedicated", "cgnat_private", "cgnat_subscriber") else "",
            "protocol": protocol, "local_port": lport, "remote_port": rport,
            "pps": round(max(c[1] for c in checks), 2), "mbps": round(max(c[2] for c in checks), 4),
            "remote_ips": max(c[3] for c in checks), "syn_ratio": round(max(c[4] for c in checks), 4),
            "input_if": top_if[0], "output_if": top_if[1],
            "bucket": end - timedelta(minutes=1), "detection": "flow",
            "details": {
                "top_remote_ips": [ip for ip, _ in last.remotes.most_common(3)],
                "top_subscribers": [{"ip": ip, "share": round(v / total, 3)}
                                    for ip, v in subs.most_common(5)],
                "public_ips": [ip for ip, _ in last.pubs.most_common(3)],
                "interfaces": [{"in": i, "out": o} for (i, o), _ in last.ifaces.most_common(3)],
                "zero_port_ratio": round(max(c[5] for c in checks), 4),
                "minutes": n,
                "limits": {k: used[-1][k] for k in ("min_pps", "min_mbps") if k in used[-1]},
                "dynamic_limit": dynamic, "limit_multiplier": mult},
        })
    return events


def dedupe(events):
    """Se o assinante e visto antes do NAT, o mesmo evento resolvido via log NAT e redundante."""
    private = {(e["rule"], e["subscriber_ip"], e["protocol"], e["local_port"], e["remote_port"])
               for e in events if e["scope"] == "cgnat_private"}
    return [e for e in events if not (
        e["scope"] == "cgnat_subscriber" and
        (e["rule"], e["subscriber_ip"], e["protocol"], e["local_port"], e["remote_port"]) in private)]


def evaluate_nat(rows, rule, start):
    """Regras com contadores NAO amostrados do A10 (alocacao de portas por assinante)."""
    n = rule["consecutive_minutes"]
    end = start + timedelta(minutes=n)
    per_ip = defaultdict(dict)
    for row in rows:
        if start <= row["bucket_utc"] < end:
            per_ip[row["inside_ip"]][row["bucket_utc"]] = row
    events = []
    for ip, series in sorted(per_ip.items()):
        points = [series.get(start + timedelta(minutes=i)) for i in range(n)]
        if any(p is None for p in points):
            continue
        if not all(("min_allocs_per_min" not in rule or p["allocs"] >= rule["min_allocs_per_min"]) and
                   ("min_active_ports" not in rule or p["active_ports"] >= rule["min_active_ports"])
                   for p in points):
            continue
        events.append({
            "rule": rule["name"],
            "direction": "out", "scope": "cgnat_private", "pool": "", "entity": ip,
            "local_ip": ip, "subscriber_ip": ip, "protocol": "", "local_port": 0, "remote_port": 0,
            "pps": 0.0, "mbps": 0.0, "remote_ips": 0, "syn_ratio": 0.0, "input_if": 0, "output_if": 0,
            "bucket": end - timedelta(minutes=1), "detection": "nat",
            "details": {"allocs_per_min": max(p["allocs"] for p in points),
                        "active_ports": max(p["active_ports"] for p in points), "minutes": n}})
    return events


def enrich_nat(ev, rows, start, end):
    """Evento NAT (contagem de portas do A10) nao tem protocolo/porta: completa com o que o assinante mais
    usou na saida no mesmo periodo, pelos fluxos amostrados (portas por destinos distintos, taxa e IP publico)."""
    ip = ev["subscriber_ip"]
    by_port = defaultdict(lambda: [set(), 0.0, 0.0])
    publics, minutes = Counter(), set()
    for row in rows:
        if row["direction"] != "out" or row["subscriber_ip"] != ip or not start <= row["bucket_utc"] < end:
            continue
        item = by_port[(row["protocol"], row["remote_port"])]
        item[0].add(row["remote_ip"])
        item[1] += float(row["packets"])
        item[2] += float(row["bytes"])
        minutes.add(row["bucket_utc"])
        if row["scope"] == "cgnat_pool":
            publics[(row["local_ip"], row["pool"])] += float(row["packets"])
    if not by_port:
        ev["details"]["fluxos"] = "sem fluxos amostrados do assinante no periodo"
        return ev
    ranked = sorted(by_port.items(), key=lambda kv: (-len(kv[1][0]), -kv[1][1]))
    (proto, port), (remotes, _, _) = ranked[0]
    n = max(len(minutes), 1)
    ev["key_proto_ports"] = (ev["protocol"], ev["local_port"], ev["remote_port"])   # cooldown estavel
    ev["protocol"], ev["remote_port"] = proto, port
    ev["remote_ips"] = len(set().union(*(v[0] for _, v in ranked)))
    ev["pps"] = round(sum(v[1] for _, v in ranked) / 60 / n, 2)
    ev["mbps"] = round(sum(v[2] for _, v in ranked) * 8 / 60e6 / n, 4)
    if publics:
        (pub, pool), _ = publics.most_common(1)[0]
        ev["pool"] = pool
        ev["details"]["public_ips"] = [p for (p, _), _ in publics.most_common(3)]
    ev["details"]["top_portas"] = [{"protocolo": pr, "porta": po or "efemera", "destinos": len(v[0])}
                                   for (pr, po), v in ranked[:5]]
    return ev


def _key_ports(ev):
    return ev.get("key_proto_ports", (ev["protocol"], ev["local_port"], ev["remote_port"]))


def _event_id(rule, ev):
    proto, lport, rport = _key_ports(ev)
    return hashlib.sha256(json.dumps(
        [rule["name"], ev["bucket"].isoformat(), ev["direction"], ev["scope"], ev["entity"],
         proto, lport, rport], separators=(",", ":")).encode()).hexdigest()


def insert_event(cur, source, rule, ev, cooldown):
    key = (source, rule["name"], ev["direction"], ev["scope"], ev["entity"]) + tuple(_key_ports(ev))
    cur.execute("INSERT IGNORE INTO orby_bidir_rule_state (source,rule_name,direction,scope,entity,"
                "protocol,local_port,remote_port) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)", key)
    cur.execute("SELECT last_alert_utc FROM orby_bidir_rule_state WHERE " + STATE_KEY + " FOR UPDATE", key)
    old = cur.fetchone()
    if old is None:
        raise RuntimeError("nao foi possivel consultar cooldown da regra")
    if old[0] is not None and ev["bucket"] < old[0] + timedelta(minutes=cooldown):
        return False
    cur.execute(EVENT_SQL, (
        _event_id(rule, ev), ev["bucket"], rule["name"], rule["severity"], ev["detection"],
        ev["direction"], ev["scope"], ev["pool"], ev["local_ip"], ev["subscriber_ip"],
        ev["protocol"], ev["local_port"], ev["remote_port"], ev["pps"], ev["mbps"],
        ev["remote_ips"], ev["syn_ratio"], ev["input_if"], ev["output_if"],
        json.dumps(ev["details"], ensure_ascii=False)))
    group = {"direction": ev["direction"], "scope": ev["scope"], "entity": ev["entity"],
             "protocol": ev["protocol"], "local_ip": ev["local_ip"],
             "subscriber_ip": ev["subscriber_ip"], "pool": ev["pool"]}
    if ev["direction"] == "in":
        group["dst_ip"] = ev["local_ip"]
        group["dst_port"] = ev["local_port"]
    else:
        group["src_ip"] = ev["subscriber_ip"] or ev["local_ip"]
        group["dst_port"] = ev["remote_port"]
    cur.execute(ALERT_SQL, alert_to_row({
        "action": "alert_only", "rule": "OrbyFlow F4: " + rule["name"], "severity": rule["severity"],
        "kind": "flow", "time_unix": ev["bucket"].replace(tzinfo=timezone.utc).timestamp(),
        "group": group, "context": {},
        "metrics_estimated": {"pps": ev["pps"], "mbps": ev["mbps"],
                              "unique_sources": ev["remote_ips"], "rps": 0}}))
    cur.execute("UPDATE orby_bidir_rule_state SET last_alert_utc=%s WHERE " + STATE_KEY,
                (ev["bucket"],) + key)
    return True


def _fetch(cur, sql, params, names, limit):
    cur.execute(sql, params + (limit + 1,))
    raw = cur.fetchall()
    if len(raw) > limit:
        raise RuntimeError("volume de linhas excede max_query_rows: nao ha analise parcial")
    return [dict(zip(names, r)) for r in raw]


def run(config, now=None, dry_run=False):
    if not config["enabled"]:
        print("F4 desativada: ative enabled=true apos validar limites")
        return 0
    when = now if now is not None else datetime.now(timezone.utc)
    utc = when.astimezone(timezone.utc).replace(tzinfo=None, second=0, microsecond=0)
    end = utc - timedelta(minutes=config["settle_minutes"])
    widest = max([r["consecutive_minutes"] for r in config["rules"] + config["nat_rules"]])
    begin = end - timedelta(minutes=widest)
    db = connection_from_env()
    signals = written = 0
    try:
        with db.cursor() as cur:
            rows = _fetch(cur, SQL_ROWS, (config["source"], begin, end), COLUMNS, config["max_query_rows"])
            nat_rows = _fetch(cur, SQL_NAT, (begin, end),
                              ("bucket_utc", "inside_ip", "allocs", "frees", "active_ports"),
                              config["max_query_rows"])
            from . import baseline, exceptions
            exc = exceptions.load(cur, utc)
            dyn = baseline.Limits(config, baseline.load(cur) if baseline.settings(config)["enabled"] else {})
            found = []
            for rule in config["rules"]:
                if rule["enabled"]:
                    evs = evaluate(rows, rule, end - timedelta(minutes=rule["consecutive_minutes"]), exc, dyn)
                    found.extend((rule, ev) for ev in dedupe(evs))
            for rule in config["nat_rules"]:
                if rule["enabled"]:
                    nat_start = end - timedelta(minutes=rule["consecutive_minutes"])
                    for ev in evaluate_nat(nat_rows, rule, nat_start):
                        found.append((rule, enrich_nat(ev, rows, nat_start, end)))
            signals = len(found)
            for rule, ev in found:
                if dry_run:
                    print("DRY RUN %s: %s escopo=%s ip=%s assinante=%s %s lport=%d rport=%d "
                          "pps=%.0f mbps=%.1f remotos=%d" % (
                              rule["name"], ev["direction"], ev["scope"], ev["local_ip"],
                              ev["subscriber_ip"] or "-", ev["protocol"] or "nat", ev["local_port"],
                              ev["remote_port"], ev["pps"], ev["mbps"], ev["remote_ips"]))
                else:
                    written += int(insert_event(cur, config["source"], rule, ev, config["cooldown_minutes"]))
            if not dry_run:
                cur.execute("""INSERT INTO orby_bidir_checks
(source,last_checked_at,latest_bucket_utc,status,signals,alerts) VALUES (%s,%s,%s,%s,%s,%s)
ON DUPLICATE KEY UPDATE last_checked_at=VALUES(last_checked_at),
latest_bucket_utc=VALUES(latest_bucket_utc),status=VALUES(status),
signals=VALUES(signals),alerts=VALUES(alerts)""",
                            (config["source"], utc, end - timedelta(minutes=1), "passive", signals, written))
        if not dry_run:
            db.commit()
        print("F4 janela=%s ate %s sinais=%d novos_eventos=%d dry_run=%s" % (begin, end, signals, written, dry_run))
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    return written


def main(argv=None):
    ap = argparse.ArgumentParser(description="OrbyFlow F4: deteccao bidirecional passiva (sem bloqueio)")
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    try:
        config = read_config(args.config)
        if args.validate:
            print("F4 OK: %d regras de fluxo, %d regras NAT, ativo=%s" %
                  (len(config["rules"]), len(config["nat_rules"]), config["enabled"]))
        else:
            run(config, dry_run=args.dry_run)
        return 0
    except Exception as exc:
        print("FALHA F4: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
