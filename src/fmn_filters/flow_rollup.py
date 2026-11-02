"""Rollup bidirecional por minuto com identificacao do IP privado do assinante.

Le os mesmos arquivos nfcapd da fase 2, mas classifica cada fluxo:
  in  = origem externa  -> destino em nossa rede (ataque recebido)
  out = origem em nossa rede -> destino externo   (ataque originado)
Fluxos entre dois IPs nossos (internal) ou entre dois externos (transit) sao
descartados e contados. Para IPs de pool CGNAT, o IP interno do assinante e
obtido do log NAT do A10 (receptor a10_nat); sem mapeamento fica vazio e o
fluxo e contado como nao resolvido. Nunca se deduz assinante por aproximacao.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
import sys
import time

from .a10_nat import lookup_many
from .bidir_config import DEFAULT_CONFIG, build_scopes, keep_port_set, read_config
from .ingest_nfcapd import ROOT, candidates, decode_file
from .mysql_sink import connection_from_env
from .parsers import parse_record
from .scopes import SCOPE_POOL

INSERT_SQL = """INSERT INTO orby_flow_minute (source,bucket_utc,direction,scope,pool,local_ip,
subscriber_ip,remote_ip,protocol,local_port,remote_port,input_if,output_if,
packets,bytes,syn_packets,zero_port_packets,flows) VALUES (""" + ",".join(["%s"] * 18) + """)
ON DUPLICATE KEY UPDATE packets=packets+VALUES(packets),bytes=bytes+VALUES(bytes),
syn_packets=syn_packets+VALUES(syn_packets),zero_port_packets=zero_port_packets+VALUES(zero_port_packets),
flows=flows+VALUES(flows),pool=VALUES(pool)"""


AGG_SQL = {
    "agg": """INSERT INTO orby_flow_agg_minute (source,bucket_utc,direction,scope,protocol,edge_if,packets,bytes,
syn_packets,zero_port_packets,flows) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE
packets=packets+VALUES(packets),bytes=bytes+VALUES(bytes),syn_packets=syn_packets+VALUES(syn_packets),
zero_port_packets=zero_port_packets+VALUES(zero_port_packets),flows=flows+VALUES(flows)""",
    "ip": """INSERT INTO orby_flow_ip_minute (source,bucket_utc,direction,scope,local_ip,subscriber_ip,pool,packets,bytes,
flows,remotes) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE packets=packets+VALUES(packets),
bytes=bytes+VALUES(bytes),flows=flows+VALUES(flows),remotes=GREATEST(remotes,VALUES(remotes)),pool=VALUES(pool)""",
    "port": """INSERT INTO orby_flow_port_5m (source,bucket_utc,direction,protocol,local_port,remote_port,packets,bytes,
zero_port_packets,flows) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE packets=packets+VALUES(packets),
bytes=bytes+VALUES(bytes),zero_port_packets=zero_port_packets+VALUES(zero_port_packets),flows=flows+VALUES(flows)""",
    "remote": """INSERT INTO orby_flow_remote_5m (source,bucket_utc,direction,protocol,remote_ip,packets,bytes,flows,locals)
VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE packets=packets+VALUES(packets),bytes=bytes+VALUES(bytes),
flows=flows+VALUES(flows),locals=GREATEST(locals,VALUES(locals))""",
}
AGG_RETENTION_DAYS = {"orby_flow_agg_minute": 90, "orby_flow_ip_minute": 4, "orby_flow_port_5m": 30,
                      "orby_flow_remote_5m": 4}


def aggregates(rows):
    """Agregados para os dashboards a partir das linhas de um arquivo (mesma ordem de colunas do INSERT_SQL)."""
    agg, ip, port, rem = {}, {}, {}, {}
    ip_remotes, rem_locals = {}, {}
    for (src, bucket, direction, scope, pool, local_ip, sub, remote_ip, proto, lport, rport, in_if, out_if,
         packets, nbytes, syn, zero, flows) in rows:
        b5 = bucket.replace(minute=bucket.minute - bucket.minute % 5)
        edge = in_if if direction == "in" else out_if
        a = agg.setdefault((src, bucket, direction, scope, proto, edge), [0.0, 0.0, 0.0, 0.0, 0])
        a[0] += packets; a[1] += nbytes; a[2] += syn; a[3] += zero; a[4] += flows
        k = (src, bucket, direction, scope, local_ip, sub)
        i = ip.setdefault(k, [pool, 0.0, 0.0, 0])
        i[0] = pool or i[0]; i[1] += packets; i[2] += nbytes; i[3] += flows
        ip_remotes.setdefault(k, set()).add(remote_ip)
        p = port.setdefault((src, b5, direction, proto, lport, rport), [0.0, 0.0, 0.0, 0])
        p[0] += packets; p[1] += nbytes; p[2] += zero; p[3] += flows
        rk = (src, b5, direction, proto, remote_ip)
        r = rem.setdefault(rk, [0.0, 0.0, 0])
        r[0] += packets; r[1] += nbytes; r[2] += flows
        rem_locals.setdefault(rk, set()).add(local_ip)
    return {
        "agg": [k + tuple(v) for k, v in agg.items()],
        "ip": [k + tuple(v) + (len(ip_remotes[k]),) for k, v in ip.items()],
        "port": [k + tuple(v) for k, v in port.items()],
        "remote": [k + tuple(v) + (len(rem_locals[k]),) for k, v in rem.items()],
    }


def _public(ip):
    try:
        return ip_address(ip).is_global
    except ValueError:
        return False


def aggregate(records, source, scopes, cfg, resolve=None):
    """Retorna (linhas, estatisticas). ``resolve(keys)`` -> lista de [ip_interno, porta]|None."""
    keep = keep_port_set(cfg)
    mult = float(cfg["counter_multiplier"])
    obs = cfg["observation_ifindexes"]
    stats = defaultdict(int)
    pending = []
    wanted = {}
    for raw in records:
        if str(raw.get("type", "")).upper() == "EVENT" and "kind" not in raw:
            continue
        try:
            event = parse_record(raw, assume_utc=True)
        except (ValueError, TypeError):
            stats["registros_invalidos"] += 1
            continue
        if event is None or event.kind != "flow":
            continue
        stats["fluxos"] += 1
        src_scope, src_pool, _ = scopes.classify(event.src_ip)
        dst_scope, dst_pool, _ = scopes.classify(event.dst_ip)
        src_local, dst_local = scopes.is_local(event.src_ip), scopes.is_local(event.dst_ip)
        if src_local and dst_local:
            stats["internos_descartados"] += 1
            continue
        if not src_local and not dst_local:
            stats["transito_descartado"] += 1
            continue
        if dst_local:
            direction, local, remote = "in", (event.dst_ip, dst_scope, dst_pool, event.dst_port), \
                (event.src_ip, event.src_port)
        else:
            direction, local, remote = "out", (event.src_ip, src_scope, src_pool, event.src_port), \
                (event.dst_ip, event.dst_port)
        if not _public(remote[0]):
            # NAO descartar: flood com origem forjada usa justamente enderecos bogon/reservados.
            stats["remoto_nao_publico_mantido"] += 1
        # in: pacote ENTROU pelo uplink (input_if); out: pacote SAIU pelo uplink (output_if).
        # O Huawei exporta 0 no lado oposto (visto em producao), por isso nao usar input_if na saida.
        edge_if = event.input_if if direction == "in" else event.output_if
        if obs[direction] and edge_if not in obs[direction]:
            stats["filtrado_por_ifindex"] += 1
            continue
        local_ip, scope, pool, local_port = local
        resolve_key = None
        if scope == SCOPE_POOL and event.protocol in ("tcp", "udp") and local_port > 0:
            resolve_key = (local_ip, local_port, event.protocol, int(event.end // 5 * 5))
            wanted[resolve_key] = None
        pending.append((event, direction, local_ip, scope, pool, local_port, remote, resolve_key))
    if wanted and resolve is not None:
        keys = [list(k) for k in wanted]
        for key, found in zip(wanted, resolve(keys)):
            wanted[key] = found[0] if found else None
    groups = {}
    for event, direction, local_ip, scope, pool, local_port, remote, resolve_key in pending:
        if scope == SCOPE_POOL:
            subscriber = wanted.get(resolve_key) if resolve_key else None
            stats["nat_resolvido" if subscriber else "nat_nao_resolvido"] += 1
            subscriber = subscriber or ""
        else:
            subscriber = local_ip
        bucket = datetime.fromtimestamp(event.end, timezone.utc).replace(
            second=0, microsecond=0, tzinfo=None)
        remote_ip, remote_port = remote
        key = (source, bucket, direction, scope, local_ip, subscriber, remote_ip,
               event.protocol[:12], local_port if local_port in keep else 0,
               remote_port if remote_port in keep else 0, event.input_if, event.output_if)
        item = groups.setdefault(key, [pool, 0.0, 0.0, 0.0, 0.0, 0])
        item[1] += event.packets * mult
        item[2] += event.bytes * mult
        if event.protocol == "tcp" and event.tcp_flags == "S":
            item[3] += event.packets * mult
        if event.protocol in ("tcp", "udp") and (event.src_port == 0 or event.dst_port == 0):
            # Porta 0 real (ataque) ou fragmento nao inicial (sem cabecalho L4): os dois importam.
            item[4] += event.packets * mult
        item[5] += 1
    rows = [key[:4] + (v[0],) + key[4:] + (v[1], v[2], v[3], v[4], v[5]) for key, v in groups.items()]
    return rows, dict(stats)


def make_resolver(cfg):
    state = {"warned": False}

    def resolve(keys):
        try:
            return lookup_many(cfg["nat_socket"], keys)
        except (OSError, ValueError) as exc:
            if not state["warned"]:
                print("AVISO: consulta NAT indisponivel (%s); IPs de pool ficam nao resolvidos" % exc,
                      file=sys.stderr, flush=True)
                state["warned"] = True
            return [None] * len(keys)
    return resolve


def pending_files(db, source, files):
    if not files:
        return []
    saved = {}
    with db.cursor() as cur:
        for n in range(0, len(files), 200):
            part = files[n:n + 200]
            cur.execute("SELECT file_name,file_size,file_mtime_ns FROM orby_flow_ingested_files "
                        "WHERE source=%s AND file_name IN (" + ",".join(["%s"] * len(part)) + ")",
                        (source,) + tuple(p.name for p in part))
            for name, size, mtime in cur.fetchall():
                saved[name] = (int(size), int(mtime))
    out = []
    for path in files:
        old = saved.get(path.name)
        if old is None:
            out.append(path)
        else:
            st = path.stat()
            if old != (st.st_size, st.st_mtime_ns):
                raise ValueError("Arquivo previamente processado mudou: " + path.name)
    return out


def save_file(db, source, path, st, rows, stats):
    with db.cursor() as cur:
        cur.execute("""INSERT IGNORE INTO orby_flow_ingested_files
(source,file_name,file_size,file_mtime_ns,flow_count,nat_resolved,nat_unresolved)
VALUES (%s,%s,%s,%s,%s,%s,%s)""", (source, path.name, st.st_size, st.st_mtime_ns,
                                   stats.get("fluxos", 0), stats.get("nat_resolvido", 0),
                                   stats.get("nat_nao_resolvido", 0)))
        if not cur.rowcount:
            db.rollback()
            return False
        for n in range(0, len(rows), 500):
            cur.executemany(INSERT_SQL, rows[n:n + 500])
        if AGGREGATES["enabled"]:
            try:
                for name, items in aggregates(rows).items():
                    for n in range(0, len(items), 500):
                        cur.executemany(AGG_SQL[name], items[n:n + 500])
            except Exception as exc:              # tabelas ainda nao criadas: segue so com o detalhado
                if "orby_flow_" not in str(exc) or "doesn't exist" not in str(exc):
                    raise
                AGGREGATES["enabled"] = False
                print("AVISO: agregados dos dashboards desligados (rode scripts/setup-performance.sh)",
                      file=sys.stderr, flush=True)
    db.commit()
    return True


AGGREGATES = {"enabled": True}

B5 = "bucket_utc - INTERVAL MINUTE(bucket_utc) %% 5 MINUTE"
BACKFILL_SQL = (
    """INSERT INTO orby_flow_agg_minute (source,bucket_utc,direction,scope,protocol,edge_if,packets,bytes,syn_packets,
zero_port_packets,flows) SELECT source,bucket_utc,direction,scope,protocol,IF(direction='in',input_if,output_if),
SUM(packets),SUM(bytes),SUM(syn_packets),SUM(zero_port_packets),SUM(flows) FROM orby_flow_minute WHERE source=%s AND
bucket_utc>=%s AND bucket_utc<%s GROUP BY source,bucket_utc,direction,scope,protocol,IF(direction='in',input_if,output_if)
ON DUPLICATE KEY UPDATE packets=VALUES(packets),bytes=VALUES(bytes),syn_packets=VALUES(syn_packets),
zero_port_packets=VALUES(zero_port_packets),flows=VALUES(flows)""",
    """INSERT INTO orby_flow_ip_minute (source,bucket_utc,direction,scope,local_ip,subscriber_ip,pool,packets,bytes,flows,
remotes) SELECT source,bucket_utc,direction,scope,local_ip,subscriber_ip,MAX(pool),SUM(packets),SUM(bytes),SUM(flows),
COUNT(DISTINCT remote_ip) FROM orby_flow_minute WHERE source=%s AND bucket_utc>=%s AND bucket_utc<%s
GROUP BY source,bucket_utc,direction,scope,local_ip,subscriber_ip ON DUPLICATE KEY UPDATE pool=VALUES(pool),
packets=VALUES(packets),bytes=VALUES(bytes),flows=VALUES(flows),remotes=VALUES(remotes)""",
    """INSERT INTO orby_flow_port_5m (source,bucket_utc,direction,protocol,local_port,remote_port,packets,bytes,
zero_port_packets,flows) SELECT source,""" + B5 + """,direction,protocol,local_port,remote_port,SUM(packets),SUM(bytes),
SUM(zero_port_packets),SUM(flows) FROM orby_flow_minute WHERE source=%s AND bucket_utc>=%s AND bucket_utc<%s
GROUP BY source,""" + B5 + """,direction,protocol,local_port,remote_port ON DUPLICATE KEY UPDATE
packets=VALUES(packets),bytes=VALUES(bytes),zero_port_packets=VALUES(zero_port_packets),flows=VALUES(flows)""",
    """INSERT INTO orby_flow_remote_5m (source,bucket_utc,direction,protocol,remote_ip,packets,bytes,flows,locals)
SELECT source,""" + B5 + """,direction,protocol,remote_ip,SUM(packets),SUM(bytes),SUM(flows),COUNT(DISTINCT local_ip)
FROM orby_flow_minute WHERE source=%s AND bucket_utc>=%s AND bucket_utc<%s GROUP BY source,""" + B5 + """,direction,
protocol,remote_ip ON DUPLICATE KEY UPDATE packets=VALUES(packets),bytes=VALUES(bytes),flows=VALUES(flows),
locals=VALUES(locals)""")


def backfill(db, source, until, log=print):
    """Preenche os agregados a partir do detalhado ja gravado (antes de `until`), uma hora por vez.
    Recalcula (nao soma): pode rodar de novo sem duplicar. Horas multiplas de 5 min para nao cortar os 5m."""
    with db.cursor() as cur:
        cur.execute("SELECT MIN(bucket_utc) FROM orby_flow_minute WHERE source=%s", (source,))
        first = cur.fetchone()[0]
    if first is None:
        return 0
    hour = first.replace(minute=0, second=0, microsecond=0)
    until = until.replace(minute=until.minute - until.minute % 5, second=0, microsecond=0)
    hours = 0
    while hour < until:
        nxt = min(hour + timedelta(hours=1), until)
        with db.cursor() as cur:
            for sql in BACKFILL_SQL:
                cur.execute(sql, (source, hour, nxt))
        db.commit()
        hours += 1
        log("agregados: %s ate %s" % (hour, nxt))
        hour = nxt
    return hours


def prune(db, days):
    """Retencao do rollup e dos agregados NAT (eventos de ataque sao mantidos)."""
    with db.cursor() as cur:
        if AGGREGATES["enabled"]:
            for table, keep in AGG_RETENTION_DAYS.items():
                try:
                    cur.execute("DELETE FROM " + table + " WHERE bucket_utc < UTC_TIMESTAMP() - INTERVAL %s DAY "
                                "LIMIT 50000", (keep,))
                except Exception:
                    pass
        cur.execute("DELETE FROM orby_flow_minute WHERE bucket_utc < "
                    "UTC_TIMESTAMP() - INTERVAL %s DAY LIMIT 50000", (days,))
        cur.execute("DELETE FROM orby_nat_user_minute WHERE bucket_utc < "
                    "UTC_TIMESTAMP() - INTERVAL %s DAY LIMIT 50000", (days,))
        cur.execute("DELETE FROM orby_flow_ingested_files WHERE ingested_at < "
                    "UTC_TIMESTAMP() - INTERVAL %s DAY LIMIT 50000", (days,))
    db.commit()


def run(cfg, *, max_files=40, max_age_hours=2, min_age=45, dry_run=False, folder=None,
        scopes=None, resolve=None):
    source = cfg["source"]
    scopes = scopes or build_scopes(cfg)
    resolve = resolve or make_resolver(cfg)
    directory = folder if folder is not None else ROOT / source
    eligible = candidates(directory, time.time(), min_age, max_age_hours * 3600)
    db = None if dry_run or not eligible else connection_from_env()
    imported = failed = 0
    try:
        pending = eligible if db is None else pending_files(db, source, eligible)
        paths = pending[:max_files]
        print("fonte=%s elegiveis=%d pendentes=%d lote=%d dry_run=%s" %
              (source, len(eligible), len(pending), len(paths), dry_run), flush=True)
        for path in paths:
            try:
                st, records, _ = decode_file(path, time.time())
                rows, stats = aggregate(records, source, scopes, cfg, resolve)
                if dry_run:
                    print("DRY-RUN %s %s linhas=%d" % (path.name, stats, len(rows)), flush=True)
                else:
                    ok = save_file(db, source, path, st, rows, stats)
                    imported += int(ok)
                    print("%s %s %s" % ("IMPORTADO" if ok else "JA_IMPORTADO", path.name, stats),
                          flush=True)
            except Exception as exc:
                failed += 1
                if db:
                    db.rollback()
                print("ERRO %s: %s" % (path.name, exc), file=sys.stderr, flush=True)
        if db and not dry_run:
            prune(db, cfg["retention_days"])
    finally:
        if db:
            db.close()
    if failed:
        raise RuntimeError("%d arquivos falharam; verifique journalctl" % failed)
    return imported


def main(argv=None):
    ap = argparse.ArgumentParser(description="OrbyFlow F4: rollup bidirecional de fluxos")
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--max-files", type=int, default=40)
    ap.add_argument("--max-age-hours", type=int, default=2)
    ap.add_argument("--min-age", type=int, default=45)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--backfill-aggregates", action="store_true",
                    help="preenche as tabelas agregadas dos dashboards com o detalhado ja gravado e sai")
    args = ap.parse_args(argv)
    if args.backfill_aggregates:
        try:
            cfg = read_config(args.config)
            db = connection_from_env()
            try:
                n = backfill(db, cfg["source"], datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=10))
            finally:
                db.close()
            print("agregados preenchidos: %d hora(s)" % n)
            return 0
        except Exception as exc:
            print("FALHA backfill: %s" % exc, file=sys.stderr)
            return 1
    if min(args.max_files, args.max_age_hours, args.min_age) < 1:
        ap.error("limites precisam ser positivos")
    try:
        run(read_config(args.config), max_files=args.max_files, max_age_hours=args.max_age_hours,
            min_age=args.min_age, dry_run=args.dry_run)
        return 0
    except Exception as exc:
        print("FALHA rollup F4: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
