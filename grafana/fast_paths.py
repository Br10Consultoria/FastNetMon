"""Caminho rapido do dashboard "Ataques e investigacao por IP": sem filtro de IP/remoto/porta, os paineis leem as
tabelas agregadas (sql/flow_aggregates.sql) em vez de orby_flow_minute. Com filtro, continua o detalhado (rapido por
indice). Cada consulta vira "(rapida) UNION ALL (detalhada)" com condicoes que se excluem; o MariaDB descarta a parte
cuja condicao constante e falsa sem ler a tabela.

Aplicar (idempotente) no export e regenerar:  python3 grafana/fast_paths.py && python3 grafana/import_v2.py
"""
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
EXPORT = ROOT / "exports" / "orbyflow-f4-ataques.v2.json"
MARK = "/*fast*/"
V = lambda n: "${%s:sqlstring}" % n
NO_IP, NO_REM, NO_PORT, ALL_PROTO = (V("ip") + "=''", V("remoto") + "=''", V("porta") + "=''", V("proto") + "='all'")
DIR = "(%s='all' OR direction=%s)" % (V("direcao"), V("direcao"))
PROTO = "(%s='all' OR protocol=%s)" % (V("proto"), V("proto"))
SENT = "CASE direction WHEN 'in' THEN 'recebido' ELSE 'originado' END"
IPF = "(%s='' OR local_ip=%s OR subscriber_ip=%s)" % (V("ip"), V("ip"), V("ip"))
PORTF = "(%s='' OR local_port=%s OR remote_port=%s)" % (V("porta"), V("porta"), V("porta"))
REMF = "(%s='' OR remote_ip=%s)" % (V("remoto"), V("remoto"))

FAST = {
    "Pico de taxa no filtro (1 min)": (
        [NO_IP, NO_REM, NO_PORT],
        "SELECT COALESCE(MAX(v),0) AS value FROM (SELECT SUM(bytes)*8/60 AS v FROM orby_flow_agg_minute WHERE "
        "source='huawei' AND $__timeFilter(bucket_utc) AND %s AND %s GROUP BY bucket_utc) t" % (DIR, PROTO)),
    "Pico de pacotes/s no filtro (1 min)": (
        [NO_IP, NO_REM, NO_PORT],
        "SELECT COALESCE(MAX(v),0) AS value FROM (SELECT SUM(packets)/60 AS v FROM orby_flow_agg_minute WHERE "
        "source='huawei' AND $__timeFilter(bucket_utc) AND %s AND %s GROUP BY bucket_utc) t" % (DIR, PROTO)),
    "Taxa por sentido e tipo de IP": (
        [NO_IP, NO_REM, NO_PORT],
        "SELECT $__timeGroupAlias(bucket_utc,'1m'),CONCAT(%s,' / ',scope) AS metric,SUM(bytes)*8/60 AS value FROM "
        "orby_flow_agg_minute WHERE source='huawei' AND $__timeFilter(bucket_utc) AND %s AND %s "
        "GROUP BY 1,direction,scope ORDER BY 1" % (SENT, DIR, PROTO)),
    "Pacotes/s por sentido, com SYN e porta 0": (
        [NO_IP, NO_REM, NO_PORT],
        "SELECT * FROM (SELECT $__timeGroupAlias(bucket_utc,'1m'),%s AS metric,SUM(packets)/60 AS value FROM "
        "orby_flow_agg_minute WHERE source='huawei' AND $__timeFilter(bucket_utc) AND %s AND %s GROUP BY 1,direction "
        "UNION ALL SELECT $__timeGroupAlias(bucket_utc,'1m'),CONCAT(%s,' SYN'),SUM(syn_packets)/60 FROM "
        "orby_flow_agg_minute WHERE source='huawei' AND $__timeFilter(bucket_utc) AND %s AND %s GROUP BY 1,direction "
        "UNION ALL SELECT $__timeGroupAlias(bucket_utc,'1m'),CONCAT(%s,' porta 0/fragmentos'),SUM(zero_port_packets)/60 "
        "FROM orby_flow_agg_minute WHERE source='huawei' AND $__timeFilter(bucket_utc) AND %s AND %s GROUP BY 1,direction"
        ") x ORDER BY 1" % (SENT, DIR, PROTO, SENT, DIR, PROTO, SENT, DIR, PROTO)),
    "IPs da rede com maior pico (público, pool ou assinante)": (
        [NO_REM, NO_PORT, ALL_PROTO],
        "SELECT %s AS 'Sentido',scope AS 'Tipo',MAX(pool) AS 'Pool',local_ip AS 'IP público/local',subscriber_ip AS "
        "'IP assinante',MAX(bytes)*8/60 AS 'Pico',MAX(packets)/60 AS 'Pico pacotes/s',SUM(bytes) AS 'Volume',"
        "MAX(remotes) AS 'IPs remotos (pico)' FROM orby_flow_ip_minute WHERE source='huawei' AND "
        "$__timeFilter(bucket_utc) AND %s AND %s GROUP BY direction,scope,local_ip,subscriber_ip "
        "ORDER BY MAX(bytes) DESC LIMIT 50" % (SENT, IPF, DIR)),
    "IPs remotos (quem ataca ou é atacado)": (
        [NO_IP, NO_PORT],
        "SELECT remote_ip AS 'IP remoto',%s AS 'Sentido',protocol AS 'Proto',MAX(locals) AS 'IPs nossos envolvidos',"
        "SUM(bytes) AS 'Volume',SUM(packets)/GREATEST(1,$__unixEpochTo()-$__unixEpochFrom()) AS 'Pacotes/s médio' "
        "FROM orby_flow_remote_5m WHERE source='huawei' AND $__timeFilter(bucket_utc) AND %s AND %s AND %s "
        "GROUP BY remote_ip,direction,protocol ORDER BY SUM(bytes) DESC LIMIT 50" % (SENT, REMF, DIR, PROTO)),
    "Protocolos e portas de serviço": (
        [NO_IP, NO_REM],
        "SELECT %s AS 'Sentido',protocol AS 'Proto',local_port AS 'Porta local',remote_port AS 'Porta remota',"
        "SUM(bytes) AS 'Volume',SUM(packets)/GREATEST(1,$__unixEpochTo()-$__unixEpochFrom()) AS 'Pacotes/s médio',"
        "SUM(zero_port_packets)/GREATEST(1,SUM(packets)) AS 'Porta 0/frag.' FROM orby_flow_port_5m WHERE "
        "source='huawei' AND $__timeFilter(bucket_utc) AND %s AND %s AND %s GROUP BY direction,protocol,local_port,"
        "remote_port ORDER BY SUM(bytes) DESC LIMIT 50" % (SENT, PORTF, DIR, PROTO)),
    "CGNAT: assinantes por trás de cada IP público do pool": (
        [NO_REM, NO_PORT, ALL_PROTO],
        "SELECT local_ip AS 'IP público (pool)',MAX(pool) AS 'Pool',subscriber_ip AS 'IP assinante',%s AS 'Sentido',"
        "SUM(bytes) AS 'Volume',SUM(packets) AS 'Pacotes' FROM orby_flow_ip_minute WHERE source='huawei' AND "
        "$__timeFilter(bucket_utc) AND %s AND %s AND scope='cgnat_pool' AND subscriber_ip<>'' GROUP BY local_ip,"
        "subscriber_ip,direction ORDER BY SUM(bytes) DESC LIMIT 50" % (SENT, IPF, DIR)),
    "Taxa por interface de borda (trânsito, PTT, CDN, peers)": (
        [NO_IP, NO_REM, NO_PORT],
        "SELECT $__timeGroupAlias(f.bucket_utc,'1m'),CONCAT(%s,' · ',CASE WHEN f.edge_if=0 THEN 'sem interface (0)' "
        "ELSE COALESCE(MAX(im.if_name),CONCAT('ifIndex ',f.edge_if,' (sem nome)')) END) AS metric,SUM(f.bytes)*8/60 AS "
        "value FROM orby_flow_agg_minute AS f LEFT JOIN orby_interface_names AS im ON im.source='huawei' AND "
        "im.if_index=f.edge_if WHERE f.source='huawei' AND $__timeFilter(f.bucket_utc) AND %s AND %s "
        "GROUP BY 1,direction,f.edge_if ORDER BY 1" % (SENT, DIR, PROTO)),
}


def combine(raw, conds, fast):
    """(rapida se conds) UNION ALL (detalhada se nao conds)."""
    on = " AND ".join(conds)
    raw_where = re.sub(r"WHERE (f\.)?source='huawei'", lambda m: "WHERE NOT (%s) AND %ssource='huawei'" % (on, m.group(1) or ""), raw)
    fast_where = re.sub(r"WHERE (f\.)?source='huawei'", lambda m: "WHERE (%s) AND %ssource='huawei'" % (on, m.group(1) or ""), fast)
    if fast.startswith("SELECT COALESCE(MAX(v),0) AS value"):      # estatistica: a parte desligada devolve 0
        return "%s SELECT MAX(value) AS value FROM ((%s) UNION ALL (%s)) u" % (MARK, fast_where, raw_where)
    return "%s SELECT * FROM ((%s) UNION ALL (%s)) u%s" % (MARK, fast_where, raw_where,
                                                           " ORDER BY 1" if "ORDER BY 1" in fast else "")


def main():
    doc = json.loads(EXPORT.read_text(encoding="utf-8"))
    done = 0
    for el in doc["spec"]["elements"].values():
        title = el["spec"].get("title", "")
        if title not in FAST:
            continue
        for q in el["spec"]["data"]["spec"]["queries"]:
            spec = q["spec"]["query"]["spec"]
            raw = spec.get("rawSql", "")
            if raw.startswith(MARK):
                raw = spec.get("rawSqlDetalhado", raw)
            spec["rawSqlDetalhado"] = raw                     # guarda a consulta original para reaplicar
            conds, fast = FAST[title]
            spec["rawSql"] = combine(raw, conds, fast)
            done += 1
    EXPORT.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("paineis com caminho rapido: %d de %d" % (done, len(FAST)))


if __name__ == "__main__":
    main()
