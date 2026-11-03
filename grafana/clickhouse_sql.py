"""Versao ClickHouse dos dashboards que leem os pares de IP (Huawei ao vivo, IPs/redes, CGNAT, Visao geral).

Os paineis que consultam orby_ip_pairs_minute passam a usar o datasource ClickHouse (plugin
grafana-clickhouse-datasource); os demais (alertas, arquivos importados) continuam no MariaDB.
O ClickHouse tem copias das tabelas pequenas (nomes de interface, paises, blocos do provedor) com os mesmos nomes,
entao o SQL muda pouco: apelidos entre aspas duplas, macros do plugin e funcoes equivalentes.

Gerado a partir de grafana/dashboards/<nome>.json (ja convertidos pelo import_v2.py):
  python3 grafana/clickhouse_sql.py        -> grafana/dashboards-clickhouse/<nome>.json
O deploy-live-dashboards.sh instala esta versao quando o datasource ClickHouse esta configurado.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
DASHBOARDS = ("orbyflow-huawei-live", "orbyflow-ip-analytics", "orbyflow-cgnat", "orbyflow-overview")
DS = {"type": "grafana-clickhouse-datasource", "uid": "orbyflow-clickhouse"}
CH_TABLES = ("orby_ip_pairs_minute",)
MARIADB_ONLY = ("orby_alerts", "orby_ip_ingested_files", "orby_attack_events", "orby_flow_minute")

IP4 = "IPv4StringToNumOrDefault(%s)"


def _exists_prefix(m):
    kind, col = m.group(1), m.group(2)
    return ("arrayExists(r -> %s BETWEEN r.1 AND r.2, (SELECT groupArray((v_start, v_end)) FROM orby_net_prefixes "
            "WHERE kind='%s'))" % (IP4 % col, kind))


def _pool_name(m):
    return ("nullIf(arrayFirst(r -> %s BETWEEN r.1 AND r.2, (SELECT groupArray((v_start, v_end, name)) "
            "FROM orby_net_prefixes WHERE kind='pool')).3, '')" % (IP4 % m.group(1)))


def _group_concat(m):
    expr, sep, limit = m.group(1), m.group(3), m.group(4)
    expr = re.sub(r"NULLIF\((\w+),''\)", r"nullIf(\1,'')", expr)
    return "arrayStringConcat(arraySlice(arraySort(groupUniqArray(%s)), 1, %s), '%s')" % (expr, limit, sep)


RULES = [
    # correlacionadas (o ClickHouse nao tem): lista de faixas como subconsulta constante
    (re.compile(r"EXISTS \(SELECT 1 FROM orby_net_prefixes np WHERE np\.kind='(\w+)' AND INET_ATON\(([\w.]+)\) "
                r"BETWEEN np\.v_start AND np\.v_end\)"),
     _exists_prefix),
    (re.compile(r"\(SELECT np\.name FROM orby_net_prefixes np WHERE np\.kind='pool' AND INET_ATON\(([\w.]+)\) "
                r"BETWEEN np\.v_start AND np\.v_end LIMIT 1\)"), _pool_name),
    (re.compile(r"GROUP_CONCAT\(DISTINCT (NULLIF\(\w+,''\)|\w+) ORDER BY (\w+) SEPARATOR '([^']*)' LIMIT (\d+)\)"),
     _group_concat),
    (re.compile(r"\$__timeGroupAlias\(([\w.]+),'1m'\)"), r"toStartOfMinute(\1) AS time"),
    (re.compile(r"\$__unixEpochFrom\(\)"), "toUnixTimestamp($__fromTime)"),
    (re.compile(r"\$__unixEpochTo\(\)"), "toUnixTimestamp($__toTime)"),
    (re.compile(r"TIMESTAMPDIFF\(SECOND,([^,]+),UTC_TIMESTAMP\(\)\)"), r"dateDiff('second',\1,now('UTC'))"),
    (re.compile(r"TIMESTAMPDIFF\(MINUTE,([^,]+),UTC_TIMESTAMP\(\)\)"), r"dateDiff('minute',\1,now('UTC'))"),
    (re.compile(r"UTC_TIMESTAMP\(\)"), "now('UTC')"),
    (re.compile(r"CAST\(([\w.]+) AS CHAR\)"), r"toString(\1)"),
    (re.compile(r"INET_ATON\(([\w.]+)\)"), lambda m: IP4 % m.group(1)),
    (re.compile(r"\bNULLIF\("), "nullIf("),
    # apelidos 'texto' -> "texto" (no ClickHouse aspas simples sao so texto)
    (re.compile(r"\bAS '([^']*)'"), r'AS "\1"'),
]


def convert_sql(sql):
    for rx, rep in RULES:
        sql = rx.sub(rep, sql)
    left = [w for w in ("INET_ATON", "GROUP_CONCAT", "TIMESTAMPDIFF", "UTC_TIMESTAMP", "$__timeGroup",
                        "$__unixEpoch") if w in sql]
    if left:
        raise ValueError("construcao MySQL sem equivalente: %s" % ", ".join(left))
    return sql


def uses_clickhouse(sql):
    return any(t in sql for t in CH_TABLES) and not any(t in sql for t in MARIADB_ONLY)


def convert_panel(p):
    targets = p.get("targets") or []
    if not targets or not all(uses_clickhouse(t.get("rawSql", "")) for t in targets):
        return False
    for t in targets:
        series = t.get("format") == "time_series"
        sql = convert_sql(t["rawSql"])
        for k in ("editorMode", "format", "rawQuery", "sql"):
            t.pop(k, None)
        t.update({"datasource": dict(DS), "editorType": "sql", "rawSql": sql, "queryType":
                  "timeseries" if series else "table", "format": 0 if series else 1})
        if series and " AS metric" in sql:
            # formato longo (time, metric, value): o plugin vira uma serie por metric
            p.setdefault("fieldConfig", {}).setdefault("defaults", {}).setdefault(
                "displayName", "${__field.labels.metric}")
    p["datasource"] = dict(DS)
    return True


def convert_dashboard(dash):
    out = copy.deepcopy(dash)
    n = sum(convert_panel(p) for p in out["panels"])
    out["description"] = (out.get("description", "") + " Dados de tráfego no ClickHouse.").strip()
    return out, n


def main():
    target = ROOT / "grafana" / "dashboards-clickhouse"
    target.mkdir(exist_ok=True)
    for name in DASHBOARDS:
        src = ROOT / "grafana" / "dashboards" / (name + ".json")
        dash, n = convert_dashboard(json.loads(src.read_text(encoding="utf-8")))
        (target / (name + ".json")).write_text(json.dumps(dash, ensure_ascii=False, indent=2) + "\n",
                                                encoding="utf-8")
        print("%s: %d de %d paineis no ClickHouse" % (name, n, len(dash["panels"])))


if __name__ == "__main__":
    sys.exit(main())
