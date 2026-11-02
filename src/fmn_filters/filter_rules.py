"""Alarmes por filtro: avalia regras (filtro nfdump + condicoes) minuto a minuto sobre os arquivos nfcapd.

Regra (orby_filter_rules.definition, JSON):
  conditions: [{metric: mbps|pps|flows|bpp, op: gt|ge|lt|le|above_avg|below_avg, value, window}]
     gt/ge/lt/le       -> limite fixo (Mbps, pacotes/s, fluxos/min ou bytes/pacote)
     above_avg (value%) -> atual > media dos `window` minutos anteriores x (1 + value/100)
     below_avg (value%) -> atual < media x (1 - value/100)   (queda de trafego)
     above_usual / below_usual (value%, window = dias) -> compara com o MESMO horario (+-10 min) dos
                          `window` dias anteriores (linha de base do proprio filtro; precisa de historico)
  logic: and|or         consecutive: minutos seguidos para abrir   resolve_after: minutos sem casar para encerrar
  report: {agg: dstip|srcip|dstport|srcport|proto|record, top}   notify: Telegram   retention_days: serie

Cada minuto avaliado vira uma amostra (grafico/media). Incidente: aberto -> resfriando -> resolvido.
Uso (timer de 1 min): python -m fmn_filters.filter_rules --config /etc/orbymon/bidir.json
     [--telegram-env /etc/orbymon/telegram.env] [--dry-run]
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import html
import json
import os
from pathlib import Path
import sys
import time

from . import flow_query as fq

METRICS = {"mbps": "Mbps", "pps": "pacotes/s", "flows": "fluxos/min", "bpp": "bytes/pacote"}
OPS = {"gt": ">", "ge": "≥", "lt": "<", "le": "≤", "above_avg": "acima da média", "below_avg": "abaixo da média",
       "above_usual": "acima do habitual", "below_usual": "abaixo do habitual"}
AVG_OPS = ("above_avg", "below_avg")
USUAL_OPS = ("above_usual", "below_usual")
USUAL_SPAN = timedelta(minutes=10)      # "mesmo horario" = +-10 min nos dias anteriores
AGGS = {"dstip": "destinos", "srcip": "origens", "dstport": "portas de destino", "srcport": "portas de origem",
        "proto": "protocolos", "record": "conversas"}
SEVERITIES = ("warning", "high", "critical")
DIRECTIONS = ("in", "out", "any")
CATCH_UP = timedelta(minutes=15)       # se o servico parou, nao reprocessa mais que isso
SETTLE = 40                            # segundos apos o fim do minuto para o arquivo fechar


class RuleError(ValueError):
    pass


# ------------------------------------------------------------------ validacao
def validate(name, expr, definition, severity="high", direction="in", table=None):
    name = (name or "").strip()
    if not 3 <= len(name) <= 80:
        raise RuleError("nome entre 3 e 80 caracteres")
    if severity not in SEVERITIES:
        raise RuleError("severidade inválida")
    if direction not in DIRECTIONS:
        raise RuleError("sentido inválido")
    if table is not None:
        fq.expand(expr, table)                       # atalhos e caracteres
    d = dict(definition or {})
    conds = d.get("conditions") or []
    if not 1 <= len(conds) <= 5:
        raise RuleError("de 1 a 5 condições")
    clean = []
    for c in conds:
        metric, op = c.get("metric"), c.get("op")
        if metric not in METRICS or op not in OPS:
            raise RuleError("condição inválida")
        try:
            value = float(c.get("value"))
        except (TypeError, ValueError):
            raise RuleError("valor da condição deve ser número")
        item = {"metric": metric, "op": op, "value": value}
        if op in ("above_avg", "below_avg"):
            window = int(c.get("window") or 15)
            if not 2 <= window <= 120:
                raise RuleError("janela da média entre 2 e 120 minutos")
            if op == "above_avg" and not 1 <= value <= 10000:
                raise RuleError("aumento entre 1% e 10000%")
            if op == "below_avg" and not 1 <= value <= 99:
                raise RuleError("queda entre 1% e 99%")
            item["window"] = window
        elif op in USUAL_OPS:
            days = int(c.get("window") or 7)
            if not 1 <= days <= 28:
                raise RuleError("comparação com o habitual: de 1 a 28 dias")
            if op == "above_usual" and not 1 <= value <= 10000:
                raise RuleError("aumento entre 1% e 10000%")
            if op == "below_usual" and not 1 <= value <= 99:
                raise RuleError("queda entre 1% e 99%")
            item["window"] = days
        elif value < 0:
            raise RuleError("valor negativo")
        clean.append(item)
    report = d.get("report") or {}
    out = {"logic": "or" if d.get("logic") == "or" else "and", "conditions": clean,
           "consecutive": int(d.get("consecutive") or 1), "resolve_after": int(d.get("resolve_after") or 5),
           "report": {"agg": report.get("agg") if report.get("agg") in AGGS else "dstip",
                      "top": int(report.get("top") or 5)},
           "notify": bool(d.get("notify", True)), "retention_days": int(d.get("retention_days") or 7)}
    if not 1 <= out["consecutive"] <= 30:
        raise RuleError("minutos seguidos entre 1 e 30")
    if not 1 <= out["resolve_after"] <= 240:
        raise RuleError("encerramento entre 1 e 240 minutos")
    if not 1 <= out["report"]["top"] <= 20:
        raise RuleError("top entre 1 e 20")
    if not 1 <= out["retention_days"] <= 90:
        raise RuleError("histórico entre 1 e 90 dias")
    usual_days = max([c["window"] for c in clean if c["op"] in USUAL_OPS] or [0])
    out["retention_days"] = max(out["retention_days"], usual_days + 1)     # o habitual precisa do historico
    return name, expr.strip(), out


def describe(definition):
    parts = []
    for c in definition["conditions"]:
        unit = METRICS[c["metric"]]
        if c["op"] in AVG_OPS:
            parts.append("%s %d%% %s de %d min" % (unit, c["value"], OPS[c["op"]], c["window"]))
        elif c["op"] in USUAL_OPS:
            parts.append("%s %d%% %s (mesmo horário, %d dia(s))" % (unit, c["value"], OPS[c["op"]], c["window"]))
        else:
            parts.append("%s %s %s" % (unit, OPS[c["op"]], ("%g" % c["value"])))
    joiner = " E " if definition["logic"] == "and" else " OU "
    return joiner.join(parts) + " · %d min seguido(s)" % definition["consecutive"]


# ------------------------------------------------------------------ minutos e medicao
def minute_files(flow_dir, since: datetime, now: datetime):
    """{minuto_utc: [arquivos]} para minutos completos depois de `since` (arquivo de 30 s pelo mtime)."""
    out = defaultdict(list)
    limit = now.replace(tzinfo=timezone.utc).timestamp() - SETTLE
    t0 = since.replace(tzinfo=timezone.utc).timestamp()
    with os.scandir(flow_dir) as it:
        for e in it:
            if not (e.name.startswith("nfcapd.20") and e.name[7:].isdigit() and e.is_file()):
                continue
            start = e.stat().st_mtime - 30                         # inicio do intervalo do arquivo
            minute = int(start // 60) * 60
            if minute + 60 <= limit and minute >= t0:
                out[datetime.fromtimestamp(minute, timezone.utc).replace(tzinfo=None)].append(e.name)
    return {m: sorted(f) for m, f in sorted(out.items())}


def measure(flow_dir, files, expanded, timeout=20):
    out = fq._run(["-R", "%s/%s:%s" % (flow_dir, files[0], files[-1]), "-o", "csv", "-s", "proto/bytes",
                   "-n", "0", expanded], timeout)
    _, s = fq._csv_blocks(out)
    b, p, f = fq._num(s, "bytes"), fq._num(s, "packets"), fq._num(s, "flows")
    return {"bps": b * 8 / 60, "pps": p / 60, "flows": f, "bpp": (b / p) if p else 0.0}


def metric_value(sample, metric):
    return sample["bps"] / 1e6 if metric == "mbps" else sample[metric]


def check(definition, sample, history, usual=None, minute=None):
    """history: amostras anteriores (lista de dict) mais recentes por ultimo.
    usual: amostras do mesmo horario em dias anteriores (dict com 't'), para above_usual/below_usual."""
    results = []
    for c in definition["conditions"]:
        cur = metric_value(sample, c["metric"])
        if c["op"] in USUAL_OPS:
            since = (minute - timedelta(days=c["window"]) - USUAL_SPAN) if minute else None
            past = [metric_value(h, c["metric"]) for h in (usual or []) if since is None or h["t"] >= since]
            if len(past) < 10 * max(1, (c["window"] + 1) // 2):      # ao menos metade dos dias com dados
                results.append(False)
                continue
            avg = sum(past) / len(past)
            if c["op"] == "above_usual":
                results.append(avg > 0 and cur > avg * (1 + c["value"] / 100))
            else:
                results.append(cur < avg * (1 - c["value"] / 100))
            continue
        if c["op"] in AVG_OPS:
            past = [metric_value(h, c["metric"]) for h in history[-c["window"]:]]
            if len(past) < max(2, c["window"] // 2):
                results.append(False)                  # sem historico suficiente: nao dispara
                continue
            avg = sum(past) / len(past)
            if c["op"] == "above_avg":           # media zero: aumento relativo indefinido (use tambem um limite fixo)
                results.append(avg > 0 and cur > avg * (1 + c["value"] / 100))
            else:
                results.append(cur < avg * (1 - c["value"] / 100))
        else:
            v = c["value"]
            results.append({"gt": cur > v, "ge": cur >= v, "lt": cur < v, "le": cur <= v}[c["op"]])
    return all(results) if definition["logic"] == "and" else any(results)


def top_report(flow_dir, files, expanded, agg, top, scopes=None, db=None, source="huawei", when=None):
    stat = fq.MODES[agg][1]
    out = fq._run(["-R", "%s/%s:%s" % (flow_dir, files[0], files[-1]), "-o", "csv", "-s", "%s/bytes" % stat,
                   "-n", str(top), expanded], 20)
    rows, _ = fq._csv_blocks(out)
    items = []
    for r in rows[:top]:
        if agg == "record":
            label = "%s:%s → %s:%s %s" % (r.get("sa", ""), r.get("sp", ""), r.get("da", ""), r.get("dp", ""),
                                         r.get("pr", "").lower())
            ip = r.get("da", "")
            b = fq._num(r, "ibyt")
            p = fq._num(r, "ipkt")
        else:
            label = ip = r.get("val", "").strip()
            b, p = fq._num(r, "byt", "ibyt"), fq._num(r, "pkt", "ipkt")
        item = {"key": label, "bps": b * 8 / 60, "pps": p / 60}
        if scopes is not None and agg in ("dstip", "srcip", "record"):
            scope, pool, _ = scopes.classify(ip)
            item["scope"], item["pool"] = scope, pool
            if scope == "cgnat_pool" and db is not None and when is not None:
                item["assinantes"] = subscribers(db, source, ip, when)
        items.append(item)
    return items


def subscribers(db, source, ip, when, limit=3):
    """Assinantes atras do IP do pool no minuto (rollup F4 com log NAT do A10)."""
    try:
        cur = db.cursor()
        cur.execute("SELECT subscriber_ip,SUM(bytes) FROM orby_flow_minute WHERE source=%s AND local_ip=%s "
                    "AND subscriber_ip<>'' AND bucket_utc BETWEEN %s AND %s GROUP BY subscriber_ip "
                    "ORDER BY SUM(bytes) DESC LIMIT %s",
                    (source, ip, when - timedelta(minutes=2), when + timedelta(minutes=2), limit))
        return [r[0] for r in cur.fetchall()]
    except Exception:
        return []


def usual_days(definition):
    return max([c["window"] for c in definition["conditions"] if c["op"] in USUAL_OPS] or [0])


def simulate(flow_dir, expr, definition, table, now, minutes=30, budget=40.0, usual_fn=None):
    """Mede o filtro nos ultimos `minutes` e mostra em quais minutos a regra dispararia (sem gravar nada).
    usual_fn(minuto, dias): amostras gravadas do mesmo horario (sem ela, o 'habitual' nao dispara)."""
    days = usual_days(definition)
    expanded = fq.expand(expr, table)
    t0 = time.monotonic()
    points, hist, streak = [], [], 0
    for minute, files in minute_files(flow_dir, now - timedelta(minutes=minutes), now).items():
        if time.monotonic() - t0 > budget:
            break
        sample = measure(flow_dir, files, expanded)
        usual = usual_fn(minute, days) if (days and usual_fn) else None
        matched = check(definition, sample, hist, usual, minute)
        streak = streak + 1 if matched else 0
        points.append(dict(sample, t=minute, matched=matched, opens=streak == definition["consecutive"]))
        hist.append(sample)
    return points


# ------------------------------------------------------------------ banco
RULE_FIELDS = ("id", "name", "enabled", "severity", "direction", "expr", "definition")


def load_rules(cur, only_enabled=True):
    cur.execute("SELECT " + ",".join(RULE_FIELDS) + " FROM orby_filter_rules" +
                (" WHERE enabled=1" if only_enabled else "") + " ORDER BY id")
    rules = []
    for row in cur.fetchall():
        r = dict(zip(RULE_FIELDS, row))
        d = r["definition"]
        r["definition"] = json.loads(d) if isinstance(d, (str, bytes)) else d
        rules.append(r)
    return rules


def load_state(cur, rule_id):
    cur.execute("SELECT last_bucket,streak,status FROM orby_filter_rule_state WHERE rule_id=%s", (rule_id,))
    row = cur.fetchone()
    return {"last_bucket": row[0], "streak": int(row[1]), "status": row[2]} if row else \
        {"last_bucket": None, "streak": 0, "status": "normal"}


def history(cur, rule_id, before, minutes):
    cur.execute("SELECT bps,pps,flows,bpp FROM orby_filter_rule_samples WHERE rule_id=%s AND bucket_utc<%s "
                "AND bucket_utc>=%s ORDER BY bucket_utc", (rule_id, before, before - timedelta(minutes=minutes)))
    return [{"bps": r[0], "pps": r[1], "flows": r[2], "bpp": r[3]} for r in cur.fetchall()]


def usual_samples(cur, rule_id, minute, days):
    """Amostras do mesmo horario (+-10 min) nos `days` dias anteriores."""
    if not days:
        return []
    ranges = [(minute - timedelta(days=k) - USUAL_SPAN, minute - timedelta(days=k) + USUAL_SPAN)
              for k in range(1, days + 1)]
    cur.execute("SELECT bucket_utc,bps,pps,flows,bpp FROM orby_filter_rule_samples WHERE rule_id=%s AND (" +
                " OR ".join(["bucket_utc BETWEEN %s AND %s"] * len(ranges)) + ")",
                (rule_id,) + tuple(x for r in ranges for x in r))
    return [{"t": r[0], "bps": r[1], "pps": r[2], "flows": r[3], "bpp": r[4]} for r in cur.fetchall()]


def open_incident(cur, rule_id):
    cur.execute("SELECT id,started_at,last_match_at,peak_bps,peak_pps,peak_flows,matches,status FROM "
                "orby_filter_incidents WHERE rule_id=%s AND status<>'resolved' ORDER BY id DESC LIMIT 1", (rule_id,))
    row = cur.fetchone()
    keys = ("id", "started_at", "last_match_at", "peak_bps", "peak_pps", "peak_flows", "matches", "status")
    return dict(zip(keys, row)) if row else None


def attack_event(cur, rule, inc_id, when, sample, top, scopes):
    """Registra o incidente em orby_attack_events (aparece nos dashboards); ja marcado como notificado."""
    first = top[0] if top else {}
    ip = first.get("key", "") if rule["definition"]["report"]["agg"] in ("dstip", "srcip") else ""
    scope, pool = (first.get("scope", ""), first.get("pool", ""))
    if scope not in ("dedicated", "cgnat_pool", "cgnat_private", "infra"):
        ip, scope, pool = "", "filter", ""
    subs = first.get("assinantes") or []
    event_id = hashlib.sha256(("filter:%s:%s" % (rule["id"], inc_id)).encode()).hexdigest()
    cur.execute("""INSERT IGNORE INTO orby_attack_events (event_id,event_time,rule_name,severity,detection,direction,
 scope,pool,local_ip,subscriber_ip,protocol,local_port,remote_port,pps,mbps,remote_ips,syn_ratio,input_if,output_if,
 details,notified_at) VALUES (%s,%s,%s,%s,'filter',%s,%s,%s,%s,%s,'',0,0,%s,%s,0,0,0,0,%s,UTC_TIMESTAMP())""",
                (event_id, when, ("Filtro: " + rule["name"])[:100], rule["severity"],
                 "out" if rule["direction"] == "out" else "in", scope[:16], pool[:64], ip[:45],
                 (subs[0] if len(subs) == 1 else "")[:45], sample["pps"], sample["bps"] / 1e6,
                 json.dumps({"filtro": rule["expr"], "top": top}, ensure_ascii=False)))


def evaluate_rule(db, rule, flow_dir, table, now, scopes=None, source="huawei", log=print):
    """Processa os minutos pendentes de uma regra. Retorna lista de acoes (aberto/encerrado)."""
    cur = db.cursor()
    d = rule["definition"]
    state = load_state(cur, rule["id"])
    since = state["last_bucket"] + timedelta(minutes=1) if state["last_bucket"] else now - CATCH_UP
    since = max(since, now - CATCH_UP)
    expanded = fq.expand(rule["expr"], table)
    minutes = minute_files(flow_dir, since, now)
    windows = [c["window"] for c in d["conditions"] if c["op"] in AVG_OPS] + [0]
    days = usual_days(d)
    actions = []
    for minute, files in minutes.items():
        sample = measure(flow_dir, files, expanded)
        hist = history(cur, rule["id"], minute, max(windows) + 1) if max(windows) else []
        matched = check(d, sample, hist, usual_samples(cur, rule["id"], minute, days), minute)
        cur.execute("""INSERT INTO orby_filter_rule_samples (rule_id,bucket_utc,bps,pps,flows,bpp,matched)
 VALUES (%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE bps=VALUES(bps),pps=VALUES(pps),flows=VALUES(flows),
 bpp=VALUES(bpp),matched=VALUES(matched)""", (rule["id"], minute, sample["bps"], sample["pps"], sample["flows"],
                                                sample["bpp"], int(matched)))
        state["streak"] = state["streak"] + 1 if matched else 0
        inc = open_incident(cur, rule["id"])
        if matched and inc:
            cur.execute("""UPDATE orby_filter_incidents SET status='open',last_match_at=%s,matches=matches+1,
 peak_bps=GREATEST(peak_bps,%s),peak_pps=GREATEST(peak_pps,%s),peak_flows=GREATEST(peak_flows,%s) WHERE id=%s""",
                        (minute, sample["bps"], sample["pps"], sample["flows"], inc["id"]))
            state["status"] = "open"
        elif matched and state["streak"] >= d["consecutive"]:
            try:
                top = top_report(flow_dir, files, expanded, d["report"]["agg"], d["report"]["top"], scopes, db,
                                 source, minute)
            except fq.QueryError as exc:
                top = [{"key": "relatório indisponível: %s" % exc, "bps": 0, "pps": 0}]
            start = minute - timedelta(minutes=d["consecutive"] - 1)
            cur.execute("""INSERT INTO orby_filter_incidents (rule_id,rule_name,severity,status,started_at,
 last_match_at,peak_bps,peak_pps,peak_flows,matches,top) VALUES (%s,%s,%s,'open',%s,%s,%s,%s,%s,%s,%s)""",
                        (rule["id"], rule["name"], rule["severity"], start, minute, sample["bps"], sample["pps"],
                         sample["flows"], d["consecutive"], json.dumps(top, ensure_ascii=False)))
            inc_id = cur.lastrowid
            attack_event(cur, rule, inc_id, start, sample, top, scopes)
            state["status"] = "open"
            actions.append(("aberto", rule["name"], minute))
        elif inc and not matched:
            if minute - inc["last_match_at"] >= timedelta(minutes=d["resolve_after"]):
                cur.execute("UPDATE orby_filter_incidents SET status='resolved',resolved_at=%s WHERE id=%s",
                            (minute, inc["id"]))
                state["status"] = "normal"
                actions.append(("encerrado", rule["name"], minute))
            else:
                cur.execute("UPDATE orby_filter_incidents SET status='cooling' WHERE id=%s", (inc["id"],))
                state["status"] = "cooling"
        elif not inc:
            state["status"] = "normal"
        state["last_bucket"] = minute
        cur.execute("""INSERT INTO orby_filter_rule_state (rule_id,last_bucket,streak,status,last_bps,last_pps,
 last_flows,last_error) VALUES (%s,%s,%s,%s,%s,%s,%s,'') ON DUPLICATE KEY UPDATE last_bucket=VALUES(last_bucket),
 streak=VALUES(streak),status=VALUES(status),last_bps=VALUES(last_bps),last_pps=VALUES(last_pps),
 last_flows=VALUES(last_flows),last_error=''""", (rule["id"], minute, state["streak"], state["status"],
                                                   sample["bps"], sample["pps"], sample["flows"]))
        db.commit()
    return actions


def set_error(db, rule_id, message):
    cur = db.cursor()
    cur.execute("""INSERT INTO orby_filter_rule_state (rule_id,last_error) VALUES (%s,%s)
 ON DUPLICATE KEY UPDATE last_error=VALUES(last_error)""", (rule_id, message[:300]))
    db.commit()


def prune(db, rules):
    cur = db.cursor()
    for r in rules:
        cur.execute("DELETE FROM orby_filter_rule_samples WHERE rule_id=%s AND bucket_utc<UTC_TIMESTAMP()-INTERVAL %s DAY",
                    (r["id"], int(r["definition"].get("retention_days", 7))))
    cur.execute("DELETE FROM orby_filter_rule_samples WHERE rule_id NOT IN (SELECT id FROM orby_filter_rules)")
    cur.execute("DELETE FROM orby_filter_incidents WHERE status='resolved' AND resolved_at<UTC_TIMESTAMP()-INTERVAL 90 DAY")
    db.commit()


# ------------------------------------------------------------------ Telegram
def fmt_item(it, identify=None, when=None):
    e = html.escape
    extra = ""
    if it.get("pool"):
        extra = " (%s)" % e(it["pool"])
    elif it.get("scope") == "dedicated":
        extra = " (dedicado)"
    subs = it.get("assinantes") or []
    ident = (lambda ip: identify(ip, when) if identify and when else "")
    if subs:
        extra += " · assinante%s %s" % ("s" if len(subs) > 1 else "", ", ".join(
            "<code>%s</code>%s" % (e(s), (" (%s)" % e(ident(s))) if ident(s) else "") for s in subs))
    elif it.get("scope") == "dedicated" and ident(str(it["key"])):
        extra += " · %s" % e(ident(str(it["key"])))
    return "• <code>%s</code>%s — %s · %s" % (e(str(it["key"])), extra, fq.human(it["bps"], "bps"),
                                             fq.human(it["pps"], "pps"))


def notify(db, telegram, formatter, rules_by_id, now, reminder_min=30, budget=10):
    cur = db.cursor()
    sent = 0
    cur.execute("""SELECT id,rule_id,rule_name,severity,status,started_at,last_match_at,resolved_at,peak_bps,peak_pps,
 peak_flows,matches,top,notified_open,notified_reminder,notified_close FROM orby_filter_incidents
 WHERE (notified_open IS NULL) OR (status<>'resolved') OR (status='resolved' AND notified_close IS NULL)
 ORDER BY id""")
    keys = ("id", "rule_id", "rule_name", "severity", "status", "started_at", "last_match_at", "resolved_at",
            "peak_bps", "peak_pps", "peak_flows", "matches", "top", "notified_open", "notified_reminder",
            "notified_close")
    sev_pt = {"warning": "aviso", "high": "alta", "critical": "crítica"}
    for row in cur.fetchall():
        if sent >= budget:
            break
        inc = dict(zip(keys, row))
        rule = rules_by_id.get(inc["rule_id"])
        if rule is None or not rule["definition"].get("notify", True):
            cur.execute("UPDATE orby_filter_incidents SET notified_open=COALESCE(notified_open,%s),"
                        "notified_close=IF(status='resolved',%s,notified_close) WHERE id=%s", (now, now, inc["id"]))
            continue
        top = json.loads(inc["top"]) if isinstance(inc["top"], (str, bytes)) else (inc["top"] or [])
        d = rule["definition"]
        icon = "📤" if rule["direction"] == "out" else "🚨"
        e = html.escape
        if inc["notified_open"] is None:
            lines = [formatter.header(icon, "Alarme: " + e(inc["rule_name"])) + " · " + sev_pt.get(inc["severity"], ""),
                     "Condição: %s" % e(describe(d)),
                     "Agora: %s · %s · %s fluxos/min" % (fq.human(inc["peak_bps"], "bps"), fq.human(inc["peak_pps"], "pps"),
                                                         "%.0f" % inc["peak_flows"])]
            if top:
                lines.append("Top %s:" % AGGS[d["report"]["agg"]])
                lines += [fmt_item(it, getattr(formatter, "identify", None), inc["last_match_at"])
                          for it in top[:d["report"]["top"]]]
            lines.append("Filtro: <code>%s</code>" % e(rule["expr"][:300]))
            lines.append("Início: %s" % formatter.local(inc["started_at"]))
            first = top[0]["key"] if top and d["report"]["agg"] in ("dstip", "srcip") else None
            telegram.send("\n".join(lines) + (formatter.link(first, inc["started_at"]) if first else ""))
            cur.execute("UPDATE orby_filter_incidents SET notified_open=%s,notified_reminder=%s WHERE id=%s",
                        (now, now, inc["id"]))
            sent += 1
            inc["notified_reminder"] = now
        if inc["status"] == "resolved" and inc["notified_close"] is None:   # pode abrir e fechar na mesma rodada
            dur = inc["last_match_at"] - inc["started_at"] + timedelta(minutes=1)
            telegram.send("\n".join([
                formatter.header("✅", "Alarme encerrado: " + e(inc["rule_name"])),
                "Duração: %d min (%s a %s)" % (dur.total_seconds() // 60, formatter.local(inc["started_at"]),
                                               formatter.local(inc["last_match_at"])),
                "Pico: %s · %s · %.0f fluxos/min" % (fq.human(inc["peak_bps"], "bps"), fq.human(inc["peak_pps"], "pps"),
                                                    inc["peak_flows"])]))
            cur.execute("UPDATE orby_filter_incidents SET notified_close=%s WHERE id=%s", (now, inc["id"]))
            sent += 1
        elif inc["status"] != "resolved" and inc["notified_reminder"] and \
                now - inc["notified_reminder"] >= timedelta(minutes=reminder_min):
            telegram.send("\n".join([
                formatter.header("⏳", "Alarme continua: " + e(inc["rule_name"])),
                "Há %d min · maior pico %s · %s" % ((now - inc["started_at"]).total_seconds() // 60,
                                                    fq.human(inc["peak_bps"], "bps"), fq.human(inc["peak_pps"], "pps"))]))
            cur.execute("UPDATE orby_filter_incidents SET notified_reminder=%s WHERE id=%s", (now, inc["id"]))
            sent += 1
        db.commit()
    db.commit()
    return sent


# ------------------------------------------------------------------ execucao
def run(db, cfg, profile, flow_root, now=None, telegram=None, formatter=None, reminder_min=30, log=print,
        budget=50.0):
    from .bidir_config import build_scopes
    now = now or datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
    table = fq.macros(cfg, profile)
    scopes = build_scopes(cfg, profile)
    flow_dir = Path(flow_root) / cfg["source"]
    cur = db.cursor()
    rules = load_rules(cur)
    started = time.monotonic()
    actions = []
    for rule in rules:
        if time.monotonic() - started > budget:
            log("tempo esgotado: regras restantes ficam para o proximo minuto")
            break
        try:
            actions += evaluate_rule(db, rule, flow_dir, table, now, scopes, cfg["source"], log)
        except (fq.QueryError, ValueError) as exc:
            db.rollback()
            set_error(db, rule["id"], str(exc))
            log("regra %s: %s" % (rule["name"], exc))
    prune(db, rules)
    sent = 0
    if telegram is not None:
        sent = notify(db, telegram, formatter, {r["id"]: r for r in load_rules(cur, False)}, now, reminder_min)
    return actions, sent


def test_all(db, cfg, profile, flow_root, minutes=60, now=None, budget=40.0, log=print):
    """Simula TODOS os alarmes (ligados ou nao) nos ultimos `minutes` sem gravar nada: quantas vezes abririam e o
    maior valor medido de cada condicao, para escolher o limite antes de ligar."""
    now = now or datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
    table = fq.macros(cfg, profile)
    flow_dir = Path(flow_root) / cfg["source"]
    out = []
    for rule in load_rules(db.cursor(), only_enabled=False):
        d = rule["definition"]
        try:
            pts = simulate(flow_dir, rule["expr"], d, table, now, minutes, budget)
        except (fq.QueryError, ValueError) as exc:
            out.append({"nome": rule["name"], "ligado": bool(rule["enabled"]), "erro": str(exc)[:160]})
            continue
        conds = []
        for c in d["conditions"]:
            vals = sorted(metric_value(p, c["metric"]) for p in pts) or [0.0]
            conds.append({"medida": c["metric"], "op": c["op"], "valor": c["value"], "max": vals[-1],
                          "p95": vals[int(0.95 * (len(vals) - 1))]})
        out.append({"nome": rule["name"], "ligado": bool(rule["enabled"]), "minutos": len(pts),
                    "casaram": sum(1 for p in pts if p["matched"]), "abririam": sum(1 for p in pts if p["opens"]),
                    "condicoes": conds})
    return out


def print_test(rows, minutes):
    fmt = lambda v: ("%.0f" % v) if v >= 100 else ("%.1f" % v)
    print("Simulacao dos ultimos %d min (nada gravado, nenhum aviso enviado)" % minutes)
    print("%-48s %-6s %8s %8s  %s" % ("alarme", "ligado", "casaram", "abririam", "condicao: limite | max medido | p95"))
    for r in rows:
        if "erro" in r:
            print("%-48s %-6s ERRO: %s" % (r["nome"][:48], "sim" if r["ligado"] else "nao", r["erro"]))
            continue
        cond = "; ".join("%s %s %s | max %s | p95 %s" % (c["medida"], c["op"], fmt(float(c["valor"])), fmt(c["max"]),
                                                         fmt(c["p95"])) for c in r["condicoes"])
        print("%-48s %-6s %8s %8s  %s" % (r["nome"][:48], "sim" if r["ligado"] else "nao",
                                          "%d/%d" % (r["casaram"], r["minutos"]), r["abririam"], cond))
    print("abririam = quantos alarmes teriam aberto; 'acima do habitual' so funciona com historico do alarme ligado.")


def main(argv=None):
    ap = argparse.ArgumentParser(description="OrbyFlow: alarmes por filtro (nfdump)")
    ap.add_argument("--config", default="/etc/orbymon/bidir.json")
    ap.add_argument("--flow-root", default="/var/lib/orbymon/flows")
    ap.add_argument("--telegram-env", help="telegram.env para avisar (lido como dados)")
    ap.add_argument("--radius-env", default="/etc/orbymon/radius.env",
                    help="RADIUS para mostrar o login PPPoE (lido como dados; ignorado se nao existir)")
    ap.add_argument("--testar-todos", type=int, metavar="MIN",
                    help="simula todos os alarmes (inclusive desligados) nos ultimos MIN minutos e sai (5-120)")
    args = ap.parse_args(argv)
    try:
        from .admin.config_store import read_env
        from .bidir_config import load_profile, read_config
        from .mysql_sink import connection_from_env
        cfg = read_config(args.config)
        profile = load_profile(cfg)
        if args.testar_todos is not None:
            if not 5 <= args.testar_todos <= 120:
                raise ValueError("--testar-todos entre 5 e 120 minutos")
            db = connection_from_env()
            try:
                print_test(test_all(db, cfg, profile, args.flow_root, args.testar_todos), args.testar_todos)
            finally:
                db.close()
            return 0
        telegram = formatter = None
        reminder = 30
        if args.telegram_env:
            from .notify_telegram import Formatter, Settings, Telegram
            env = dict(os.environ)
            env.update(read_env(Path(args.telegram_env)))
            if env.get("TELEGRAM_BOT_TOKEN") and env.get("TELEGRAM_CHAT_IDS"):
                s = Settings.from_env(env)
                from .channels import wrap
                telegram, formatter, reminder = (wrap(Telegram(s.token, s.chats), os.environ.get("ORBYMON_NOTIFY_ENV", "/etc/orbymon/notify.env"), s.site),
                                                 Formatter(s), s.reminder_min)
        db = connection_from_env()
        if formatter is not None:
            from .customers import build_identifier
            formatter.identify = build_identifier(db, args.radius_env if os.path.exists(args.radius_env) else None)
        try:
            actions, sent = run(db, cfg, profile, args.flow_root, telegram=telegram, formatter=formatter,
                                reminder_min=reminder)
        finally:
            db.close()
        for kind, name, minute in actions:
            print("%s: %s (%s UTC)" % (kind, name, minute))
        if sent:
            print("telegram: %d mensagem(ns)" % sent)
        return 0
    except Exception as exc:
        print("FALHA alarmes: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
