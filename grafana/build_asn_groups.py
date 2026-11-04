"""Gera o dashboard "Tráfego por grupo de ASN/CDN" nas duas versões:
  grafana/dashboards/orbyflow-grupos-asn.json             (MariaDB: pares de IP das últimas 24 h)
  grafana/dashboards-clickhouse/orbyflow-grupos-asn.json  (ClickHouse: retenção longa)

Os grupos (Google, Meta, Netflix, caches...) são editados no painel web (Monitoramento > Grupos de ASN):
ASNs em orby_asn_group_members e blocos IPv4 em orby_net_prefixes (kind='group'); o bloco ganha do ASN.
O lado remoto da conversa é escolhido no filtro "Sentido": recebido = origem remota (download dos clientes),
enviado = destino remoto (upload).
  python3 grafana/build_asn_groups.py
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAME = "orbyflow-grupos-asn.json"
MY = {"type": "mysql", "uid": "orbyflow-mysql"}
CH = {"type": "grafana-clickhouse-datasource", "uid": "orbyflow-clickhouse"}
R = "p.${lado}"          # lado remoto: src_* ou dst_*


def dialect(ch):
    """Expressoes do grupo, filtro "remoto nao e nosso", tempo e taxa em cada banco."""
    if ch:
        ip4 = "IPv4StringToNumOrDefault(%s_ip)" % R
        group = ("coalesce(nullIf(arrayFirst(r -> %s BETWEEN r.1 AND r.2, (SELECT groupArray((v_start, v_end, name)) "
                 "FROM orby_net_prefixes WHERE kind='group')).3, ''), nullIf(g.name, ''), 'Outros')" % ip4)
        remote = ("NOT arrayExists(r -> %s BETWEEN r.1 AND r.2, (SELECT groupArray((v_start, v_end)) FROM "
                  "orby_net_prefixes WHERE kind IN ('protected','private','infra')))" % ip4)
        return {"group": group, "remote": remote, "time": "$__timeFilter(p.bucket_utc)",
                "bucket": "toStartOfInterval(p.bucket_utc, INTERVAL $__interval_s second) AS time",
                "secs": "$__interval_s", "span": "greatest(1, dateDiff('second', $__fromTime, $__toTime))",
                "join": "LEFT JOIN orby_asn_group_members g ON g.asn = %s_asn" % R,
                "asname": "anyIf(%s_asn_name, %s_asn_name != '')" % (R, R), "uniq": "uniqExact(%s_ip)" % R,
                "pct": "round(100 * sum(p.total_bytes) / greatest(1, sum(sum(p.total_bytes)) OVER ()), 1)"}
    group = ("COALESCE((SELECT np.name FROM orby_net_prefixes np WHERE np.kind='group' AND INET_ATON(%s_ip) BETWEEN "
             "np.v_start AND np.v_end ORDER BY np.v_end-np.v_start LIMIT 1),g.name,'Outros')" % R)
    remote = ("NOT EXISTS (SELECT 1 FROM orby_net_prefixes np WHERE np.kind IN ('protected','private','infra') AND "
              "INET_ATON(%s_ip) BETWEEN np.v_start AND np.v_end)" % R)
    return {"group": group, "remote": remote, "time": "$__timeFilter(p.bucket_utc)",
            "bucket": "$__timeGroupAlias(p.bucket_utc,'5m')", "secs": "300",
            "span": "GREATEST(1,$__unixEpochTo()-$__unixEpochFrom())",
            "join": "LEFT JOIN orby_asn_group_members g ON g.asn=%s_asn" % R,
            "asname": "MAX(NULLIF(%s_asn_name,''))" % (R,), "uniq": "COUNT(DISTINCT %s_ip)" % R,
            "pct": "ROUND(100*SUM(p.total_bytes)/GREATEST(1,SUM(SUM(p.total_bytes)) OVER ()),1)"}


def q(d, sql):
    return sql.format(**d)


def target(ds, sql, series=False):
    if ds is CH:
        return [{"refId": "A", "datasource": dict(CH), "editorType": "sql", "rawSql": sql,
                 "queryType": "timeseries" if series else "table", "format": 0 if series else 1}]
    return [{"refId": "A", "datasource": dict(MY), "editorMode": "code", "format": "time_series" if series else "table",
             "rawQuery": True, "rawSql": sql}]


def panels(ch):
    d = dialect(ch)
    ds = CH if ch else MY
    base = "FROM orby_ip_pairs_minute p {join} WHERE p.source='huawei' AND {time} AND {remote}"
    series_sql = q(d, "SELECT {bucket},{group} AS metric,SUM(p.total_bytes)*8/{secs} AS value " + base +
                   " GROUP BY 1,2 HAVING metric<>'Outros' ORDER BY 1")
    share_sql = q(d, "SELECT {group} AS grupo,SUM(p.total_bytes) AS volume " + base + " GROUP BY 1 ORDER BY 2 DESC")
    table_sql = q(d, "SELECT {group} AS \"Grupo\",SUM(p.total_bytes) AS \"Volume\",SUM(p.total_bytes)*8/{span} AS "
                     "\"Taxa média\",{pct} AS \"% do total\",{uniq} AS \"IPs remotos\" " + base +
                  " GROUP BY 1 ORDER BY 2 DESC LIMIT 50")
    others_sql = q(d, "SELECT " + R.replace("{", "{{").replace("}", "}}") + "_asn AS \"ASN\",{asname} AS \"Nome\",SUM(p.total_bytes) AS \"Volume\","
                      "SUM(p.total_bytes)*8/{span} AS \"Taxa média\",{uniq} AS \"IPs remotos\" " + base +
                   " AND {group}='Outros' GROUP BY 1 ORDER BY 3 DESC LIMIT 30")
    if not ch:      # MariaDB: apelidos com aspas simples (como nos outros dashboards)
        table_sql = table_sql.replace('"', "'")
        others_sql = others_sql.replace('"', "'")
    units = {"Volume": "decbytes", "Taxa média": "bps", "% do total": "percent"}

    def overrides():
        return [{"matcher": {"id": "byName", "options": k}, "properties": [{"id": "unit", "value": v}]}
                for k, v in units.items()]

    return [
        {"id": 1, "type": "timeseries", "title": "Banda por grupo", "datasource": dict(ds),
         "description": "Taxa de cada grupo ao longo do tempo (só os grupos cadastrados; o resto fica em 'Outros' "
                        "na tabela). Recebido = download dos clientes.",
         "gridPos": {"x": 0, "y": 0, "w": 24, "h": 9}, "targets": target(ds, series_sql, True),
         "options": {"legend": {"displayMode": "table", "placement": "right", "calcs": ["mean", "max"],
                                "showLegend": True, "sortBy": "Mean", "sortDesc": True},
                     "tooltip": {"mode": "multi", "sort": "desc"}},
         "fieldConfig": {"defaults": {"unit": "bps", "custom": {"lineWidth": 1, "fillOpacity": 25, "stacking":
                                                                {"mode": "normal", "group": "A"}, "showPoints": "never"},
                                      **({"displayName": "${__field.labels.metric}"} if ch else {})},
                         "overrides": []}},
        {"id": 2, "type": "piechart", "title": "Participação no volume", "datasource": dict(ds),
         "gridPos": {"x": 0, "y": 9, "w": 9, "h": 10}, "targets": target(ds, share_sql),
         "options": {"pieType": "donut", "reduceOptions": {"values": True, "calcs": ["lastNotNull"], "fields": ""},
                     "legend": {"displayMode": "table", "placement": "right", "values": ["percent"], "showLegend": True},
                     "displayLabels": []},
         "fieldConfig": {"defaults": {"unit": "decbytes"}, "overrides": []}},
        {"id": 3, "type": "table", "title": "Grupos no período", "datasource": dict(ds),
         "gridPos": {"x": 9, "y": 9, "w": 15, "h": 10}, "targets": target(ds, table_sql),
         "options": {"showHeader": True, "cellHeight": "sm"},
         "fieldConfig": {"defaults": {"custom": {"align": "auto", "filterable": True}}, "overrides": overrides()}},
        {"id": 4, "type": "table", "title": "Maiores ASNs fora dos grupos ('Outros')", "datasource": dict(ds),
         "description": "Candidatos a virar grupo: cadastre no painel web (Monitoramento > Grupos de ASN). Caches de "
                        "CDN dentro do transito entram por bloco IP.",
         "gridPos": {"x": 0, "y": 19, "w": 24, "h": 10}, "targets": target(ds, others_sql),
         "options": {"showHeader": True, "cellHeight": "sm"},
         "fieldConfig": {"defaults": {"custom": {"align": "auto", "filterable": True}}, "overrides": overrides()}},
    ]


def build(ch=False):
    var = {"type": "custom", "name": "lado", "label": "Sentido", "query": "Recebido (origem remota) : src,Enviado (destino remoto) : dst",
           "options": [{"text": "Recebido (origem remota)", "value": "src", "selected": True},
                       {"text": "Enviado (destino remoto)", "value": "dst", "selected": False}],
           "current": {"text": "Recebido (origem remota)", "value": "src"}, "hide": 0, "multi": False,
           "includeAll": False, "skipUrlSync": False}
    return {"id": None, "uid": "orbyflow-grupos-asn", "title": "Tráfego por grupo de ASN/CDN",
            "description": "Banda por grupo de ASN/CDN (Google, Meta, Netflix, caches...). Grupos editáveis no painel web." +
                           (" Dados de tráfego no ClickHouse." if ch else " Pares de IP das últimas 24 h."),
            "tags": ["orbyflow", "trafego", "asn", "cdn"], "editable": True, "schemaVersion": 41, "version": 1,
            "graphTooltip": 1, "links": [], "liveNow": False, "timezone": "browser",
            "time": {"from": "now-6h", "to": "now"}, "refresh": "5m", "fiscalYearStartMonth": 0,
            "timepicker": {"refresh_intervals": ["1m", "5m", "15m"]},
            "annotations": {"list": [{"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"},
                                      "enable": True, "hide": True, "iconColor": "rgba(0, 211, 255, 1)",
                                      "name": "Annotations & Alerts", "type": "dashboard"}]},
            "templating": {"list": [var]}, "panels": panels(ch)}


if __name__ == "__main__":
    for ch, folder in ((False, "dashboards"), (True, "dashboards-clickhouse")):
        out = ROOT / "grafana" / folder / NAME
        out.write_text(json.dumps(build(ch), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(out.relative_to(ROOT))
