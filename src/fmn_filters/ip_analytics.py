"""OrbyFlow fase 2: pares IP por minuto, separado da ingestao geral.

Sem mitigacao e sem alteracao no Huawei. Checkpoint e metricas na mesma
transacao MariaDB. GeoLite2 opcional, com consulta exclusivamente offline.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
import os
import sys
import time

from .enrichment import Enricher
from .ingest_nfcapd import ROOT, candidates, decode_file
from .mysql_sink import connection_from_env
from .parsers import parse_record

INSERT_PAIR = """INSERT INTO orby_ip_pairs_minute (
source,bucket_utc,src_ip,dst_ip,protocol,dst_port,input_if,output_if,netflow_direction,
src_prefix,dst_prefix,src_asn,dst_asn,src_asn_name,dst_asn_name,src_country,dst_country,
src_latitude,src_longitude,dst_latitude,dst_longitude,total_packets,total_bytes,flow_records
) VALUES (""" + ",".join(["%s"] * 24) + """) ON DUPLICATE KEY UPDATE
total_packets=total_packets+VALUES(total_packets),
total_bytes=total_bytes+VALUES(total_bytes),
flow_records=flow_records+VALUES(flow_records),
src_asn_name=IF(VALUES(src_asn_name)!='',VALUES(src_asn_name),src_asn_name),
dst_asn_name=IF(VALUES(dst_asn_name)!='',VALUES(dst_asn_name),dst_asn_name),
src_country=IF(VALUES(src_country)!='',VALUES(src_country),src_country),
dst_country=IF(VALUES(dst_country)!='',VALUES(dst_country),dst_country),
src_latitude=COALESCE(VALUES(src_latitude),src_latitude),
src_longitude=COALESCE(VALUES(src_longitude),src_longitude),
dst_latitude=COALESCE(VALUES(dst_latitude),dst_latitude),
dst_longitude=COALESCE(VALUES(dst_longitude),dst_longitude)"""


def prefix(raw: dict, side: str, addr: str) -> str:
    """So usa CIDR quando a mascara foi exportada e cobre o IP de fato."""
    try:
        ip = ip_address(addr)
        mask = raw.get(side + "_mask")
        if mask is None or not (1 <= int(mask) <= ip.max_prefixlen):
            return ""
        base = raw.get(side + "_net") or addr
        network = ip_network(str(base) + "/" + str(int(mask)), strict=False)
        return str(network) if network.version == ip.version and ip in network else ""
    except (ValueError, TypeError):
        return ""


def metadata(event, side: str, enricher: Enricher):
    addr = getattr(event, side + "_ip")
    geo = enricher.lookup(addr)
    router_asn = getattr(event, side + "_asn")
    asn = router_asn if router_asn > 0 else int(geo.get("asn", 0))
    name = getattr(event, side + "_asn_name")
    if not name and asn and int(geo.get("asn", 0)) == asn:
        name = geo.get("asn_name", "")
    country = getattr(event, side + "_country") or geo.get("country", "")
    lat = getattr(event, side + "_latitude")
    lon = getattr(event, side + "_longitude")
    return (asn, str(name)[:255], str(country)[:2].upper(),
            lat if lat is not None else geo.get("latitude"),
            lon if lon is not None else geo.get("longitude"))


def aggregate(records: list, source: str, enricher: Enricher):
    groups = {}
    count = 0
    for raw in records:
        if str(raw.get("type", "")).upper() == "EVENT" and "kind" not in raw:
            continue
        src_raw = next((raw[k] for k in ("src_ip","src4_addr","src6_addr","srcip")
                        if raw.get(k)), None)
        dst_raw = next((raw[k] for k in ("dst_ip","dst4_addr","dst6_addr","dstip")
                        if raw.get(k)), None)
        try:
            src = ip_address(str(src_raw)).compressed
            dst = ip_address(str(dst_raw)).compressed
        except ValueError:
            # Nao deixar um registro sem IP parar a ingestao dos demais.
            continue
        event = parse_record(raw, assume_utc=True)
        if event is None or event.kind != "flow":
            continue
        bucket = datetime.fromtimestamp(event.end, timezone.utc).replace(
            second=0, microsecond=0, tzinfo=None)
        direction = int(raw.get("direction") if raw.get("direction") is not None else -1)
        if not (-1 <= direction <= 32767):
            raise ValueError("Direcao NetFlow invalida")
        key = (source,bucket,src,dst,event.protocol[:20],event.dst_port,
               event.input_if,event.output_if,direction)
        src_asn,src_name,src_country,src_lat,src_lon = metadata(event,"src",enricher)
        dst_asn,dst_name,dst_country,dst_lat,dst_lon = metadata(event,"dst",enricher)
        attributes = (prefix(raw,"src",src),prefix(raw,"dst",dst),
                      src_asn,dst_asn,src_name,dst_name,src_country,dst_country,
                      src_lat,src_lon,dst_lat,dst_lon)
        if key not in groups:
            groups[key] = [attributes,0.0,0.0,0]
        groups[key][1] += event.packets  # nfdump ja expandiu 1:2048
        groups[key][2] += event.bytes
        groups[key][3] += 1
        count += 1
    return [key + vals[0] + (vals[1],vals[2],vals[3])
            for key,vals in groups.items()],count


def pending_files(db, source, files):
    if not files:
        return []
    saved = {}
    with db.cursor() as cur:
        for n in range(0,len(files),200):
            part=files[n:n+200]
            placeholders=",".join(["%s"]*len(part))
            cur.execute("SELECT file_name,file_size,file_mtime_ns "
                        "FROM orby_ip_ingested_files WHERE source=%s "
                        "AND file_name IN (" + placeholders + ")",
                        (source,) + tuple(p.name for p in part))
            for name,size,mtime in cur.fetchall():
                saved[name]=(int(size),int(mtime))
    output=[]
    for path in files:
        old=saved.get(path.name)
        if old is None:
            output.append(path)
        else:
            st=path.stat()
            if old!=(st.st_size,st.st_mtime_ns):
                raise ValueError("Arquivo previamente processado mudou: "+path.name)
    return output


def save_file(db,source,path,st,rows,count):
    with db.cursor() as cur:
        cur.execute("""INSERT IGNORE INTO orby_ip_ingested_files
(source,file_name,file_size,file_mtime_ns,flow_count)
VALUES (%s,%s,%s,%s,%s)""",
                    (source,path.name,st.st_size,st.st_mtime_ns,count))
        if not cur.rowcount:
            cur.execute("SELECT file_size,file_mtime_ns FROM orby_ip_ingested_files "
                        "WHERE source=%s AND file_name=%s",(source,path.name))
            old=cur.fetchone()
            if old is None or (int(old[0]),int(old[1]))!=(st.st_size,st.st_mtime_ns):
                raise ValueError("Arquivo processado mudou: "+path.name)
            db.rollback()
            return False
        for n in range(0,len(rows),500):
            cur.executemany(INSERT_PAIR,rows[n:n+500])
    db.commit()
    return True


def prune(db, hours, batch=50000):
    """Retencao da Fase 2: com NetStream completo a tabela cresce dezenas de milhoes de linhas/dia."""
    with db.cursor() as cur:
        cur.execute("DELETE FROM orby_ip_pairs_minute WHERE bucket_utc < "
                    "UTC_TIMESTAMP() - INTERVAL %s HOUR LIMIT %s", (hours, batch))
        removed = cur.rowcount
        cur.execute("DELETE FROM orby_ip_ingested_files WHERE ingested_at < "
                    "UTC_TIMESTAMP() - INTERVAL %s HOUR LIMIT %s", (hours, batch))
    db.commit()
    return removed


def clickhouse_sink():
    """Gravacao opcional no ClickHouse (ORBYMON_CH_URL no ambiente); None quando desligado."""
    from .clickhouse import Sink
    return Sink.from_env()


def sync_dimensions(client,cur):
    from .clickhouse import sync_dimensions as sync
    return sync(client,cur)


def run(source="huawei",*,max_files=20,max_age_hours=1,min_age=45,
        dry_run=False,folder=None,enricher=None,retention_hours=72,time_budget=150):
    directory=folder if folder is not None else ROOT/source
    eligible=candidates(directory,time.time(),min_age,max_age_hours*3600)
    db=None if dry_run or not eligible else connection_from_env()
    geo=enricher or Enricher(os.getenv("ORBYMON_ASN_MMDB") or None,
                            os.getenv("ORBYMON_CITY_MMDB") or None)
    imported=0
    failed=0
    sink=None if db is None else clickhouse_sink()
    try:
        if sink is not None:
            sent=sink.flush_spool()
            if sent:
                print("ClickHouse: %d lote(s) do spool reenviado(s)" % sent,flush=True)
        pending=eligible if db is None else pending_files(db,source,eligible)
        paths=pending[:max_files]
        print("fonte=%s elegiveis=%d pendentes=%d lote=%d dry_run=%s" %
              (source,len(eligible),len(pending),len(paths),dry_run),flush=True)
        started=time.monotonic()
        for path in paths:
            if time_budget and time.monotonic()-started>time_budget:
                print("ORCAMENTO de %ds atingido; restante fica para a proxima execucao" % time_budget,
                      flush=True)
                break
            try:
                st,records,_=decode_file(path,time.time())
                rows,count=aggregate(records,source,geo)
                if dry_run:
                    print("DRY-RUN %s fluxos=%d pares=%d" %
                          (path.name,count,len(rows)),flush=True)
                else:
                    ok=save_file(db,source,path,st,rows,count)
                    imported+=int(ok)
                    if ok and sink is not None:   # depois do commit no MariaDB; falha vai para o spool
                        sink.write_pairs(sink.token(source,path.name,st.st_size,st.st_mtime_ns),rows)
                    print("%s %s fluxos=%d pares=%d" %
                          ("IMPORTADO" if ok else "JA_IMPORTADO",
                           path.name,count,len(rows)),flush=True)
            except Exception as exc:
                failed+=1
                if db: db.rollback()
                print("ERRO %s: %s" % (path.name,exc),file=sys.stderr,flush=True)
        if sink is not None and imported:
            try:
                with db.cursor() as cur:
                    copied=sync_dimensions(sink.client,cur)
                if copied:
                    print("ClickHouse: tabelas atualizadas %s" % ",".join(copied),flush=True)
            except Exception as exc:
                print("AVISO ClickHouse (tabelas auxiliares): %s" % str(exc)[:200],file=sys.stderr,flush=True)
        if db and retention_hours:
            removed=prune(db,retention_hours)
            if removed:
                print("RETENCAO removidas=%d linhas com mais de %dh" % (removed,retention_hours),flush=True)
    finally:
        if db: db.close()
        if enricher is None: geo.close()
    if failed:
        raise RuntimeError("%d arquivos falharam; verifique journalctl" % failed)
    return imported


def main(argv=None):
    ap=argparse.ArgumentParser(description="OrbyFlow fase 2 - IPs, ASN e interfaces")
    ap.add_argument("--source",choices=["huawei","mikrotik"],default="huawei")
    ap.add_argument("--max-files",type=int,default=20)
    ap.add_argument("--max-age-hours",type=int,default=1)
    ap.add_argument("--min-age",type=int,default=45)
    ap.add_argument("--dry-run",action="store_true")
    ap.add_argument("--time-budget",type=int,default=150,
                    help="segundos de importacao por execucao (abaixo do TimeoutStartSec=240)")
    ap.add_argument("--retention-hours",type=int,default=72,
                    help="apaga pares IP mais antigos que N horas (0 = nunca)")
    a=ap.parse_args(argv)
    if min(a.max_files,a.max_age_hours,a.min_age)<1 or a.retention_hours<0:
        ap.error("limites precisam ser positivos")
    try:
        run(source=a.source,max_files=a.max_files,max_age_hours=a.max_age_hours,
            min_age=a.min_age,dry_run=a.dry_run,retention_hours=a.retention_hours,
            time_budget=a.time_budget)
        return 0
    except Exception as exc:
        print("FALHA: %s" % exc,file=sys.stderr)
        return 1


if __name__=="__main__":
    sys.exit(main())
