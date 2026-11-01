"""Relatorio por cliente ou IP num periodo: ataques recebidos/originados, alarmes por filtro, trafego, listas de
reputacao e (CGNAT) IPs publicos usados. Gera tambem um texto pronto para anexar na resposta a uma denuncia."""
from __future__ import annotations

from datetime import timedelta
from ipaddress import ip_address, ip_network
import json

MAX_DAYS = 31
MAX_TARGETS = 64


class ReportError(ValueError):
    pass


def parse_targets(text):
    nets = []
    for token in (text or "").replace(",", " ").split():
        try:
            net = ip_network(token, strict=False)
        except ValueError:
            raise ReportError("IP ou prefixo inválido: %s" % token[:60])
        if net.prefixlen < (20 if net.version == 4 else 40):
            raise ReportError("prefixo amplo demais para relatório: %s" % net)
        nets.append(net)
    if not nets:
        raise ReportError("informe um cliente, IP ou prefixo")
    if len(nets) > MAX_TARGETS:
        raise ReportError("no máximo %d IPs/prefixos" % MAX_TARGETS)
    return nets


def _match_sql(cols, nets):
    """(sql, params): alguma das colunas dentro de algum dos prefixos (IPv4 e IPv6)."""
    single = [str(n.network_address) for n in nets if n.num_addresses == 1]
    ranges = [n for n in nets if n.num_addresses > 1]
    parts, params = [], []
    for col in cols:
        if single:
            parts.append("%s IN (%s)" % (col, ",".join(["%s"] * len(single))))
            params += single
        for n in ranges:
            parts.append("INET6_ATON(%s) BETWEEN INET6_ATON(%%s) AND INET6_ATON(%%s)" % col)
            params += [str(n.network_address), str(n.broadcast_address)]
    return "(" + " OR ".join(parts) + ")", params


def _inside(ip, nets):
    try:
        a = ip_address(ip)
    except ValueError:
        return False
    return any(a.version == n.version and a in n for n in nets)


def build(cur, nets, start, end, source="huawei", scopes=None, identify=None):
    if end <= start:
        raise ReportError("fim do período antes do início")
    if end - start > timedelta(days=MAX_DAYS):
        raise ReportError("período de no máximo %d dias" % MAX_DAYS)
    try:
        cur.execute("SET SESSION max_statement_time=40")    # MariaDB: consulta pesada nao trava o painel
    except Exception:
        pass
    r = {"alvos": [str(n) for n in nets], "inicio": start, "fim": end, "eventos": [], "eventos_lista": [],
         "incidentes": [], "trafego": {}, "portas_saida": [], "remotos": [], "listas": [], "ips_publicos": [],
         "identificacao": [], "trafego_desde": None}
    # escopo e identificacao de cada IP unico
    for n in nets:
        if n.num_addresses == 1:
            ip = str(n.network_address)
            scope, pool = scopes.classify(ip) if scopes else ("", "")
            who = identify(ip, end) if identify else ""
            r["identificacao"].append({"ip": ip, "escopo": scope, "pool": pool, "quem": who})
    where, params = _match_sql(("local_ip", "subscriber_ip"), nets)
    cur.execute("SELECT direction,rule_name,severity,COUNT(*),MIN(event_time),MAX(event_time),MAX(pps),MAX(mbps) "
                "FROM orby_attack_events WHERE event_time>=%s AND event_time<%s AND " + where +
                " GROUP BY direction,rule_name,severity ORDER BY direction,COUNT(*) DESC LIMIT 100",
                [start, end] + params)
    r["eventos"] = [{"sentido": x[0], "regra": x[1], "severidade": x[2], "quantidade": int(x[3]), "primeiro": x[4],
                     "ultimo": x[5], "pps": float(x[6] or 0), "mbps": float(x[7] or 0)} for x in cur.fetchall()]
    cur.execute("SELECT event_time,direction,rule_name,local_ip,subscriber_ip,protocol,local_port,remote_port,pps,mbps,"
                "remote_ips FROM orby_attack_events WHERE event_time>=%s AND event_time<%s AND " + where +
                " ORDER BY event_time DESC LIMIT 50", [start, end] + params)
    r["eventos_lista"] = [{"hora": x[0], "sentido": x[1], "regra": x[2], "ip": x[3], "assinante": x[4],
                           "protocolo": x[5], "porta_local": x[6], "porta_remota": x[7], "pps": float(x[8] or 0),
                           "mbps": float(x[9] or 0), "remotos": int(x[10] or 0)} for x in cur.fetchall()]
    try:
        cur.execute("SELECT rule_name,severity,status,started_at,resolved_at,peak_bps,peak_pps,top FROM "
                    "orby_filter_incidents WHERE started_at<%s AND (resolved_at IS NULL OR resolved_at>=%s) "
                    "ORDER BY started_at DESC LIMIT 2000", (end, start))
        for x in cur.fetchall():
            try:
                top = json.loads(x[7]) if isinstance(x[7], (str, bytes)) else (x[7] or [])
            except ValueError:
                top = []
            hits = [t for t in top if _inside(str(t.get("key", "")), nets) or
                    any(_inside(s, nets) for s in t.get("assinantes") or [])]
            if hits:
                r["incidentes"].append({"alarme": x[0], "severidade": x[1], "situacao": x[2], "inicio": x[3],
                                        "fim": x[4], "pico_bps": float(x[5] or 0), "pico_pps": float(x[6] or 0),
                                        "itens": hits[:3]})
    except Exception:
        pass                                      # alarmes por filtro ainda nao instalados
    # trafego (limitado a retencao do rollup)
    cur.execute("SELECT MIN(bucket_utc) FROM orby_flow_minute WHERE source=%s", (source,))
    row = cur.fetchone()
    r["trafego_desde"] = row[0] if row else None
    t0 = max(start, r["trafego_desde"]) if r["trafego_desde"] else start
    if r["trafego_desde"] and t0 < end:
        cur.execute("SELECT direction,SUM(bytes),SUM(packets),SUM(flows),COUNT(DISTINCT remote_ip) FROM orby_flow_minute "
                    "WHERE source=%s AND bucket_utc>=%s AND bucket_utc<%s AND " + where + " GROUP BY direction",
                    [source, t0, end] + params)
        for x in cur.fetchall():
            r["trafego"][x[0]] = {"bytes": float(x[1] or 0), "pacotes": float(x[2] or 0), "fluxos": int(x[3] or 0),
                                  "remotos": int(x[4] or 0)}
        cur.execute("SELECT protocol,remote_port,COUNT(DISTINCT remote_ip),SUM(flows),SUM(bytes) FROM orby_flow_minute "
                    "WHERE source=%s AND direction='out' AND bucket_utc>=%s AND bucket_utc<%s AND " + where +
                    " GROUP BY protocol,remote_port ORDER BY COUNT(DISTINCT remote_ip) DESC LIMIT 15",
                    [source, t0, end] + params)
        r["portas_saida"] = [{"protocolo": x[0], "porta": x[1], "destinos": int(x[2]), "fluxos": int(x[3] or 0),
                              "bytes": float(x[4] or 0)} for x in cur.fetchall()]
        cur.execute("SELECT direction,remote_ip,SUM(bytes),SUM(flows) FROM orby_flow_minute WHERE source=%s AND "
                    "bucket_utc>=%s AND bucket_utc<%s AND " + where + " GROUP BY direction,remote_ip "
                    "ORDER BY SUM(bytes) DESC LIMIT 20", [source, t0, end] + params)
        r["remotos"] = [{"sentido": x[0], "ip": x[1], "bytes": float(x[2] or 0), "fluxos": int(x[3] or 0)}
                        for x in cur.fetchall()]
        priv, pp = _match_sql(("subscriber_ip",), nets)
        cur.execute("SELECT local_ip,MIN(bucket_utc),MAX(bucket_utc) FROM orby_flow_minute WHERE source=%s AND "
                    "scope='cgnat_pool' AND bucket_utc>=%s AND bucket_utc<%s AND " + priv +
                    " GROUP BY local_ip ORDER BY MIN(bucket_utc) LIMIT 30", [source, t0, end] + pp)
        r["ips_publicos"] = [{"ip": x[0], "de": x[1], "ate": x[2]} for x in cur.fetchall()]
    try:
        lw, lp = _match_sql(("entry",), nets)
        cur.execute("SELECT entry,source_label,category,first_seen,last_seen,removed_at FROM orby_reputation_listings "
                    "WHERE first_seen<%s AND (removed_at IS NULL OR removed_at>=%s) AND " + lw +
                    " ORDER BY first_seen LIMIT 100", [end, start] + lp)
        r["listas"] = [{"ip": x[0], "lista": x[1], "categoria": x[2], "desde": x[3], "visto": x[4], "saiu": x[5]}
                       for x in cur.fetchall()]
    except Exception:
        pass
    return r


def human_bytes(b):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1000:
            return ("%.1f %s" % (b, unit)).replace(".", ",")
        b /= 1000.0
    return ("%.1f PB" % b).replace(".", ",")


def render_text(r, fmt_ts, title=""):
    """Texto puro para anexar numa resposta de abuso (horarios no fuso de fmt_ts)."""
    L = ["Relatório OrbyMon%s" % (" — " + title if title else ""),
         "Alvos: %s" % ", ".join(r["alvos"]),
         "Período: %s a %s" % (fmt_ts(r["inicio"]), fmt_ts(r["fim"])), ""]
    for i in r["identificacao"]:
        L.append("IP %s: %s%s%s" % (i["ip"], i["escopo"] or "?", " (%s)" % i["pool"] if i["pool"] else "",
                                     " — " + i["quem"] if i["quem"] else ""))
    if r["identificacao"]:
        L.append("")
    sent = {"in": "recebido", "out": "originado"}
    L.append("Ataques detectados: %d" % sum(e["quantidade"] for e in r["eventos"]))
    for e in r["eventos"]:
        L.append("  %s · %s · %d evento(s) · %s a %s · pico %.0f pps / %.1f Mbps" % (
            sent.get(e["sentido"], e["sentido"]), e["regra"], e["quantidade"], fmt_ts(e["primeiro"]),
            fmt_ts(e["ultimo"]), e["pps"], e["mbps"]))
    if r["incidentes"]:
        L.append("Alarmes por filtro: %d" % len(r["incidentes"]))
        for i in r["incidentes"]:
            L.append("  %s · %s a %s" % (i["alarme"], fmt_ts(i["inicio"]), fmt_ts(i["fim"]) if i["fim"] else "em aberto"))
    L.append("")
    if r["trafego"]:
        desde = max(r["inicio"], r["trafego_desde"]) if r["trafego_desde"] else r["inicio"]
        L.append("Tráfego amostrado desde %s:" % fmt_ts(desde))
        for d, t in sorted(r["trafego"].items()):
            L.append("  %s: %s, %d fluxos, %d IPs remotos" % (sent.get(d, d), human_bytes(t["bytes"]), t["fluxos"],
                                                             t["remotos"]))
        if r["portas_saida"]:
            L.append("  Saída por porta (destinos distintos): " + ", ".join(
                "%s/%s %d" % (p["protocolo"], p["porta"] or "efêmera", p["destinos"]) for p in r["portas_saida"][:8]))
    else:
        L.append("Tráfego: fora da retenção do rollup (dados agregados mais antigos já descartados).")
    if r["ips_publicos"]:
        L.append("IPs públicos usados (CGNAT): " + ", ".join(p["ip"] for p in r["ips_publicos"]))
    if r["listas"]:
        L.append("")
        L.append("Listas de reputação:")
        for x in r["listas"]:
            L.append("  %s em %s (%s) desde %s%s" % (x["ip"], x["lista"], x["categoria"], fmt_ts(x["desde"]),
                                                    ", saiu " + fmt_ts(x["saiu"]) if x["saiu"] else ""))
    return "\n".join(L)
