"""Detector PASSIVO de anomalias DDoS em rollups da fase 2.

Nenhuma acao em roteadores ou firewall. Regras AND/OR/NOT sao aplicadas aos
campos conhecidos de NetFlow; timestamps e volumes sao estimativas amostradas.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import json
from ipaddress import ip_address, ip_network
import math
from pathlib import Path
import sys

from .engine import validate_match
from .mysql_sink import connection_from_env, ALERT_SQL, alert_to_row

RULES_PATH = "/etc/orbymon/ddos-rules.json"
SUPPORTED_MATCH = frozenset({
    "src_cidrs", "dst_cidrs", "exclude_src_cidrs", "exclude_dst_cidrs",
    "protocols", "dst_ports", "src_asns", "dst_asns", "src_countries",
    "dst_countries", "input_interfaces", "output_interfaces",
    "all_of", "any_of", "not"
})
ALLOWED_PROTOCOLS = frozenset({"tcp", "udp", "icmp", "icmpv6", "esp", "gre", "47", "50"})
SEVERITIES = frozenset({"warning", "high", "critical"})


def validate_supported_match(match):
    validate_match(match)
    extra = set(match) - SUPPORTED_MATCH
    if extra:
        raise ValueError("filtros nao presentes no rollup IP: " + ",".join(sorted(extra)))
    for key in ("all_of", "any_of"):
        for child in match.get(key, []):
            validate_supported_match(child)
    if "not" in match:
        validate_supported_match(match["not"])


def validate_config(obj):
    if not isinstance(obj, dict):
        raise ValueError("configuracao JSON precisa ser objeto")
    config_keys = {"enabled", "source", "protected_cidrs", "excluded_destinations",
                   "settle_minutes", "consecutive_minutes", "cooldown_minutes",
                   "max_query_rows", "rules"}
    if set(obj) != config_keys:
        raise ValueError("campos de configuracao faltantes ou desconhecidos")
    if type(obj["enabled"]) is not bool or obj["source"] != "huawei":
        raise ValueError("enabled booleano e source huawei obrigatorios")
    for key in ("protected_cidrs", "excluded_destinations"):
        values = obj[key]
        if not isinstance(values, list):
            raise ValueError(key + " precisa ser lista CIDR")
        for item in values:
            if not isinstance(item, str):
                raise ValueError(key + " contem CIDR invalido")
            ip_network(item, strict=False)
    if obj["enabled"] and not obj["protected_cidrs"]:
        raise ValueError("adicione prefixos publicos protegidos antes de habilitar")
    for key, low, high in (("settle_minutes",1,20),
                           ("consecutive_minutes",2,5),
                           ("cooldown_minutes",1,1440),
                           ("max_query_rows",100,100000)):
        v=obj[key]
        if type(v) is not int or not low <= v <= high:
            raise ValueError(key + " fora dos limites")
    rules=obj["rules"]
    if not isinstance(rules,list) or not rules:
        raise ValueError("rules deve ter pelo menos uma regra")
    names=set()
    fields={"name","enabled","severity","match","group_by_port",
            "min_pps","min_mbps","min_sources","input_interfaces"}
    for r in rules:
        if not isinstance(r,dict) or set(r)!=fields:
            raise ValueError("regra possui campos faltantes ou desconhecidos")
        if not isinstance(r["name"],str) or not 1<=len(r["name"])<=95 or r["name"] in names:
            raise ValueError("nome de regra invalido, extenso ou duplicado")
        names.add(r["name"])
        if type(r["enabled"]) is not bool or type(r["group_by_port"]) is not bool:
            raise ValueError("enabled/group_by_port precisam ser booleanos")
        if r["severity"] not in SEVERITIES:
            raise ValueError("severity invalida")
        validate_supported_match(r["match"])
        # Um protocolo nao pode ser classificado como ataque sem escopo.
        if not any(k in json.dumps(r["match"]) for k in ("protocols","dst_ports","src_cidrs")):
            raise ValueError("regra precisa filtrar protocolo/porta/origem")
        vals=r["input_interfaces"]
        if not isinstance(vals,list) or any(type(v) is not int or v<0 or v>4294967295 for v in vals):
            raise ValueError("input_interfaces deve conter ifIndex numerico")
        for key in ("min_pps","min_mbps"):
            v=r[key]
            if type(v) not in (int,float) or not math.isfinite(v) or v<=0:
                raise ValueError(key + " deve ser positivo e finito")
        v=r["min_sources"]
        if type(v) is not int or not 1<=v<=100000:
            raise ValueError("min_sources precisa ser inteiro positivo")
    return obj


def read_config(path):
    return validate_config(json.loads(Path(path).read_text(encoding="utf-8")))


def _ip_in_net(value, networks):
    try:
        addr=ip_address(str(value))
        return any(addr in ip_network(cidr, strict=False) for cidr in networks)
    except ValueError:
        return False


def match_rollup(row, match):
    """Mesmo operador AND/OR/NOT do motor original, para campos suportados."""
    fields={
        "protocols":("protocol",str.lower),
        "dst_ports":("dst_port",int),
        "src_asns":("src_asn",int),
        "dst_asns":("dst_asn",int),
        "src_countries":("src_country",str.upper),
        "dst_countries":("dst_country",str.upper),
        "input_interfaces":("input_if",int),
        "output_interfaces":("output_if",int),
    }
    for k, (name, cast) in fields.items():
        if k in match:
            val=cast(row[name])
            if val not in [cast(x) for x in match[k]]:
                return False
    for k, name in (("src_cidrs","src_ip"),("dst_cidrs","dst_ip")):
        if k in match and not _ip_in_net(row[name],match[k]):
            return False
    for k, name in (("exclude_src_cidrs","src_ip"),("exclude_dst_cidrs","dst_ip")):
        if k in match and _ip_in_net(row[name],match[k]):
            return False
    if "all_of" in match and not all(match_rollup(row,m) for m in match["all_of"]):
        return False
    if "any_of" in match and not any(match_rollup(row,m) for m in match["any_of"]):
        return False
    if "not" in match:
        negate=match["not"]
        # Ausencia de ASN/pais nao prova que um IP seja de fora de um filtro.
        unknown=(("src_asns","src_asn"),("dst_asns","dst_asn"),
                 ("src_countries","src_country"),("dst_countries","dst_country"))
        if any(k in negate and not row[name] for k,name in unknown):
            return False
        if match_rollup(row,negate):
            return False
    return True


SQL_ROWS = """SELECT bucket_utc,src_ip,dst_ip,protocol,dst_port,input_if,output_if,
netflow_direction,src_asn,dst_asn,src_country,dst_country,total_packets,total_bytes,flow_records
FROM orby_ip_pairs_minute
WHERE source=%s AND bucket_utc >= %s AND bucket_utc < %s
ORDER BY bucket_utc LIMIT %s"""


def fetch_rows(cur, source, start, end, limit):
    cur.execute(SQL_ROWS,(source,start,end,limit+1))
    raw=cur.fetchall()
    if len(raw)>limit:
        raise RuntimeError("volume de linhas excede max_query_rows: nao ha analise parcial")
    result=[]
    for values in raw:
        result.append(dict(zip((
            "bucket_utc","src_ip","dst_ip","protocol","dst_port","input_if",
            "output_if","netflow_direction","src_asn","dst_asn","src_country","dst_country",
            "total_packets","total_bytes","flow_records"
        ),values)))
    return result


def evaluate(rows, rule, config, start):
    minutes=config["consecutive_minutes"]
    protected=config["protected_cidrs"]
    excluded=config["excluded_destinations"]
    aggregates=defaultdict(lambda: [0.0,0.0,set(),0])
    for row in rows:
        if not _ip_in_net(row["dst_ip"], protected):
            continue
        if _ip_in_net(row["dst_ip"], excluded):
            continue
        if rule["input_interfaces"] and row["input_if"] not in rule["input_interfaces"]:
            continue
        if not match_rollup(row,rule["match"]):
            continue
        port=int(row["dst_port"]) if rule["group_by_port"] else 0
        # Nunca misturar ifIndex de entrada/saida ou direcoes para mascarar duplicacao.
        key=(row["dst_ip"],row["protocol"],port,row["input_if"],row["output_if"],row["netflow_direction"])
        bucket=row["bucket_utc"]
        if not start<=bucket<start+timedelta(minutes=minutes):
            continue
        item=aggregates[(bucket,key)]
        item[0]+=float(row["total_packets"])
        item[1]+=float(row["total_bytes"])
        item[2].add(row["src_ip"])
        item[3]+=int(row["flow_records"])
    end=start+timedelta(minutes=minutes)
    results=[]
    for key in sorted(set(k for (_,k) in aggregates)):
        series=[aggregates.get((start+timedelta(minutes=i),key))
                for i in range(minutes)]
        if any(v is None for v in series):
            continue
        rates=[(v[0]/60,v[1]*8/60e6,len(v[2])) for v in series]
        if not all(pps>=rule["min_pps"] and mbps>=rule["min_mbps"] and
                   sources>=rule["min_sources"] for pps,mbps,sources in rates):
            continue
        results.append({
            "dst_ip":key[0],"protocol":key[1],"dst_port":key[2],
            "input_if":key[3],"output_if":key[4],"netflow_direction":key[5],
            "pps":round(max(v[0] for v in rates),2),
            "mbps":round(max(v[1] for v in rates),4),
            "unique_sources":min(v[2] for v in rates),
            "flow_records":sum(v[3] for v in series),
            "bucket":end-timedelta(minutes=1)
        })
    return results


def insert_alert(cur, source, rule, event, cooldown):
    key=(source,rule["name"],event["dst_ip"],event["protocol"],
         event["dst_port"],event["input_if"],event["output_if"],event["netflow_direction"])
    cur.execute("""INSERT IGNORE INTO orby_ddos_rule_state
(source,rule_name,dst_ip,protocol,dst_port,input_if,output_if,netflow_direction)
VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",key)
    cur.execute("""SELECT last_alert_utc FROM orby_ddos_rule_state
WHERE source=%s AND rule_name=%s AND dst_ip=%s AND protocol=%s AND
dst_port=%s AND input_if=%s AND output_if=%s AND netflow_direction=%s FOR UPDATE""",key)
    old=cur.fetchone()
    if old is None:
        raise RuntimeError("nao foi possivel consultar cooldown da regra")
    if old[0] is not None and event["bucket"] < old[0]+timedelta(minutes=cooldown):
        return False
    group={
        "dst_ip":event["dst_ip"],"protocol":event["protocol"],
        "dst_port":event["dst_port"],"input_if":event["input_if"],
        "output_if":event["output_if"],"netflow_direction":event["netflow_direction"],"exporter":source,
    }
    alert={
        "action":"alert_only",
        "rule":"OrbyMon F3: "+rule["name"],
        "severity":rule["severity"],
        "kind":"flow",
        "time_unix":event["bucket"].replace(tzinfo=timezone.utc).timestamp(),
        "group":group,
        "context":{},
        "metrics_estimated":{
            "pps":event["pps"],"mbps":event["mbps"],
            "unique_sources":event["unique_sources"],"rps":0,
        }
    }
    cur.execute(ALERT_SQL,alert_to_row(alert))
    cur.execute("""UPDATE orby_ddos_rule_state SET last_alert_utc=%s
WHERE source=%s AND rule_name=%s AND dst_ip=%s AND protocol=%s AND
dst_port=%s AND input_if=%s AND output_if=%s AND netflow_direction=%s""",(event["bucket"],)+key)
    return True


def run(config, now=None, dry_run=False):
    config=validate_config(config)
    if not config["enabled"]:
        print("Fase 3 desativada: ative enabled=true apos validar limites")
        return 0
    when=now if now is not None else datetime.now(timezone.utc)
    utc=when.astimezone(timezone.utc).replace(tzinfo=None,second=0,microsecond=0)
    end=utc-timedelta(minutes=config["settle_minutes"])
    start=end-timedelta(minutes=config["consecutive_minutes"])
    db=connection_from_env()
    signals=0
    written=0
    try:
        with db.cursor() as cur:
            rows=fetch_rows(cur,config["source"],start,end,config["max_query_rows"])
            for rule in config["rules"]:
                if not rule["enabled"]:
                    continue
                alerts=evaluate(rows,rule,config,start)
                signals+=len(alerts)
                for item in alerts:
                    if dry_run:
                        print("DRY RUN %s: destino=%s protocolo=%s porta=%d "
                              "ifIndex=%d/%d Mbps=%.2f PPS=%.2f fontes=%d" %
                              (rule["name"],item["dst_ip"],item["protocol"],
                               item["dst_port"],item["input_if"],item["output_if"],
                               item["mbps"],item["pps"],item["unique_sources"]))
                    else:
                        written+=int(insert_alert(cur,config["source"],rule,item,
                                                  config["cooldown_minutes"]))
            if not dry_run:
                cur.execute("""INSERT INTO orby_ddos_checks
(source,last_checked_at,latest_bucket_utc,status,signals,alerts)
VALUES (%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE
last_checked_at=VALUES(last_checked_at),
latest_bucket_utc=VALUES(latest_bucket_utc),
status=VALUES(status),signals=VALUES(signals),alerts=VALUES(alerts)""",
                            (config["source"],utc,end-timedelta(minutes=1),
                             "passive",signals,written))
        if not dry_run:
            db.commit()
        print("Fase3 janela=%s ate %s sinais=%d novos_alertas=%d dry_run=%s"%
              (start,end,signals,written,dry_run))
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    return written


def main(argv=None):
    p=argparse.ArgumentParser(description="OrbyMon fase 3 passiva - sem bloqueio")
    p.add_argument("--config",default=RULES_PATH)
    p.add_argument("--validate",action="store_true")
    p.add_argument("--dry-run",action="store_true")
    a=p.parse_args(argv)
    try:
        config=read_config(a.config)
        if a.validate:
            print("Regras validas=%d, ativo=%s, prefixos=%d"%
                  (len(config["rules"]),config["enabled"],len(config["protected_cidrs"])))
        else:
            run(config,dry_run=a.dry_run)
        return 0
    except Exception as exc:
        print("FALHA F3: "+str(exc),file=sys.stderr)
        return 1


if __name__=="__main__":
    sys.exit(main())
