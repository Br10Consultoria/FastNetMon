"""Consulta de eventos de ataque, maiores consumidores e uso de portas NAT (somente leitura).

Os resultados contem IPs de assinantes (IP privado CGNAT): execute apenas com o
usuario do servico e nao compartilhe a saida publicamente.
"""
from __future__ import annotations

import argparse
import json
import sys

from .mysql_sink import connection_from_env

EVENTS_SQL = """SELECT event_time,rule_name,severity,direction,scope,pool,local_ip,subscriber_ip,
protocol,local_port,remote_port,pps,mbps,remote_ips,syn_ratio
FROM orby_attack_events WHERE event_time >= UTC_TIMESTAMP() - INTERVAL %s HOUR"""
EVENT_HEADERS = ("hora_utc", "regra", "sev", "dir", "escopo", "pool", "ip_local",
                 "ip_assinante", "proto", "porta_local", "porta_remota", "pps", "mbps",
                 "ips_remotos", "syn")
TALKERS_SQL = """SELECT direction,scope,IF(subscriber_ip<>'',subscriber_ip,local_ip) AS entity,
SUM(packets)/(60*%s) AS pps,SUM(bytes)*8/(60000000*%s) AS mbps,COUNT(DISTINCT remote_ip) AS remotes
FROM orby_flow_minute WHERE source='huawei' AND bucket_utc >= UTC_TIMESTAMP() - INTERVAL %s MINUTE
GROUP BY direction,scope,entity ORDER BY mbps DESC LIMIT %s"""
NAT_SQL = """SELECT inside_ip,SUM(allocs) AS allocs,MAX(active_ports) AS max_active_ports,
ROUND(SUM(allocs)/COUNT(*),1) AS avg_allocs_per_active_min
FROM orby_nat_user_minute WHERE bucket_utc >= UTC_TIMESTAMP() - INTERVAL %s MINUTE
GROUP BY inside_ip ORDER BY allocs DESC LIMIT %s"""


def build_events_query(hours, direction=None, ip=None, limit=50):
    if not (1 <= hours <= 8760 and 1 <= limit <= 1000):
        raise ValueError("--hours 1..8760 e --limit 1..1000")
    sql, params = EVENTS_SQL, [hours]
    if direction:
        sql += " AND direction=%s"
        params.append(direction)
    if ip:
        sql += " AND (subscriber_ip=%s OR local_ip=%s)"
        params += [ip, ip]
    return sql + " ORDER BY event_time DESC LIMIT %s", tuple(params + [limit])


def render(headers, rows):
    table = [tuple(str(c) for c in headers)] + [tuple("" if c is None else str(c) for c in r) for r in rows]
    widths = [max(len(r[i]) for r in table) for i in range(len(headers))]
    return "\n".join("  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip() for r in table)


def main(argv=None):
    ap = argparse.ArgumentParser(description="OrbyFlow F4: consulta de ataques entrada/saida")
    ap.add_argument("--hours", type=int, default=6)
    ap.add_argument("--direction", choices=("in", "out"))
    ap.add_argument("--ip", help="IP publico ou IP privado CGNAT do assinante")
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--top-talkers", type=int, metavar="MINUTOS",
                    help="maiores consumidores nos ultimos N minutos (calibrar limites)")
    ap.add_argument("--nat-top", type=int, metavar="MINUTOS",
                    help="assinantes com mais alocacoes de porta NAT nos ultimos N minutos")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        if args.top_talkers:
            sql, params = TALKERS_SQL, (args.top_talkers,) * 3 + (args.limit,)
            headers = ("dir", "escopo", "entidade", "pps_medio", "mbps_medio", "ips_remotos")
        elif args.nat_top:
            sql, params = NAT_SQL, (args.nat_top, args.limit)
            headers = ("ip_assinante", "alocacoes", "portas_ativas_max", "alocacoes_por_minuto_ativo")
        else:
            sql, params = build_events_query(args.hours, args.direction, args.ip, args.limit)
            headers = EVENT_HEADERS
        db = connection_from_env()
        try:
            with db.cursor() as cur:
                cur.execute(sql, params)
                rows = cur.fetchall()
        finally:
            db.close()
        if args.json:
            print(json.dumps([dict(zip(headers, map(str, r))) for r in rows], ensure_ascii=False, indent=2))
        else:
            print(render(headers, rows))
        return 0
    except Exception as exc:
        print("FALHA consulta: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
