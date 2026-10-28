"""MariaDB/MySQL sink: events and one-minute aggregated flow traffic.

Input is newline-delimited JSON, never untrusted SQL. Database is external and
must have schema.sql applied. Process only trusted telemetry on a private host.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
import sys
from .parsers import parse_record, stream_records


def connection_from_env():
    try:
        import pymysql
    except ImportError as exc:
        raise RuntimeError('Instale pip install PyMySQL ou pip install ".[mysql]"') from exc
    for name in ('ORBYMON_DB_HOST','ORBYMON_DB_NAME','ORBYMON_DB_USER','ORBYMON_DB_PASSWORD'):
        if not os.environ.get(name):
            raise ValueError('Variável ausente: ' + name)
    return pymysql.connect(host=os.environ['ORBYMON_DB_HOST'],
                           port=int(os.environ.get('ORBYMON_DB_PORT','3306')),
                           user=os.environ['ORBYMON_DB_USER'],
                           password=os.environ['ORBYMON_DB_PASSWORD'],
                           database=os.environ['ORBYMON_DB_NAME'],
                           charset='utf8mb4', autocommit=False,
                           connect_timeout=5, read_timeout=30, write_timeout=30,
                           init_command="SET time_zone = '+00:00'")


def alert_to_row(alert: dict) -> tuple:
    if alert.get('action') != 'alert_only':
        raise ValueError('Apenas alertas modo alert_only são aceitos nesta versão')
    context = alert.get('context', {})
    group = alert.get('group', {})
    if not isinstance(context, dict) or not isinstance(group, dict):
        raise ValueError('context/group inválido')
    event_time = datetime.fromtimestamp(float(alert['time_unix']), timezone.utc).replace(tzinfo=None)
    ident = hashlib.sha256(json.dumps({'rule': alert.get('rule'), 'time_unix': alert.get('time_unix'),
         'group': group}, sort_keys=True, separators=(',',':')).encode()).hexdigest()
    m = alert.get('metrics_estimated', {})
    # src_* metadata may only be carried for rules grouping by source IP/ASN.
    # A mixed-source destination alert MUST NOT be attributed to one ASN.
    return (ident,event_time,str(alert['rule']),str(alert.get('severity','warning')),
            str(alert.get('kind','flow')),group.get('src_ip'),group.get('dst_ip'),
            context.get('src_asn'),context.get('src_asn_name'),context.get('src_country'),
            context.get('dst_asn'),context.get('dst_asn_name'),context.get('dst_country'),
            context.get('src_latitude'),context.get('src_longitude'),group.get('dst_port'),
            group.get('protocol'),m.get('pps',0),m.get('mbps',0),
            m.get('unique_sources',0),m.get('rps',0),json.dumps(group,ensure_ascii=False))


ALERT_SQL = '''INSERT IGNORE INTO orby_alerts (
alert_id,event_time,rule_name,severity,attack_kind,src_ip,dst_ip,src_asn,src_asn_name,src_country,
dst_asn,dst_asn_name,dst_country,src_latitude,src_longitude,dst_port,protocol,
pps,mbps,unique_sources,rps,group_data) VALUES ('''+','.join(['%s']*22)+')'

FLOW_SQL = '''INSERT INTO orby_traffic_minute
(bucket_utc,src_asn,src_asn_name,src_country,dst_asn,dst_country,protocol,dst_port,total_packets,total_bytes,flow_records)
VALUES ('''+','.join(['%s']*11)+''') ON DUPLICATE KEY UPDATE
 total_packets=total_packets+VALUES(total_packets),total_bytes=total_bytes+VALUES(total_bytes),
 flow_records=flow_records+VALUES(flow_records),
 src_asn_name=IF(VALUES(src_asn_name)!='', VALUES(src_asn_name), src_asn_name)'''


def flow_to_group(raw: dict) -> tuple | None:
    event = parse_record(raw, assume_utc=True)
    if event is None or event.kind != 'flow':
        return None
    # bucket by flow end timestamp. This is an approximation; long flows
    # are not spread over all minutes. Do not equate to a packet-level capture.
    bucket = datetime.fromtimestamp(event.end, timezone.utc).replace(second=0,microsecond=0,tzinfo=None)
    return (bucket, event.src_asn, event.src_asn_name[:255], event.src_country,
            event.dst_asn, event.dst_country, event.protocol[:20], event.dst_port)


def flush_flows(cur, rows: dict):
    payload = [key+(data[0],data[1],data[2]) for key,data in rows.items()]
    if payload:
        cur.executemany(FLOW_SQL, payload)
    rows.clear()


def process(stream, cur, kind: str, fmt='ndjson', batch=1000, commit=lambda:None):
    count = 0
    groups = defaultdict(lambda:[0.,0.,0])
    for raw in stream_records(stream, fmt):
        if kind == 'alerts':
            cur.execute(ALERT_SQL, alert_to_row(raw))
        else:
            group = flow_to_group(raw)
            if group is not None:
                flow = parse_record(raw, assume_utc=True)
                groups[group][0] += flow.packets
                groups[group][1] += flow.bytes
                groups[group][2] += 1
        count += 1
        if count % batch == 0:
            if kind == 'flows':
                flush_flows(cur, groups)
            commit()
    if kind == 'flows':
        flush_flows(cur, groups)
    commit()
    return count


def main(argv=None):
    parser=argparse.ArgumentParser(description='OrbyMon event sink MariaDB - use DB credentials in environment')
    parser.add_argument('--kind',required=True,choices=('alerts','flows'))
    parser.add_argument('--format',default='ndjson',choices=('ndjson','json'))
    parser.add_argument('--batch',type=int,default=1000)
    args=parser.parse_args(argv)
    if args.batch < 1 or args.batch > 100000:
        parser.error('batch deve estar entre 1 e 100000')
    db=connection_from_env()
    try:
        with db.cursor() as cur:
            print(f'Persistidos {process(sys.stdin,cur,args.kind,args.format,args.batch,db.commit)} registros',file=sys.stderr)
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__=='__main__':
    main()
