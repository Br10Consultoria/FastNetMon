"""Gera o dashboard "CGNAT - Portas por IP publico" (grafana/dashboards/orbyflow-cgnat-portas.json).

Fonte: orby_nat_public_minute (receptor A10, foto da tabela NAT a cada minuto) e orby_nat_user_minute
(portas por assinante). Dados do log NAT do A10: contagem real, sem amostragem.
  python3 grafana/build_cgnat_ports.py
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "grafana" / "dashboards" / "orbyflow-cgnat-portas.json"
DS = {"type": "mysql", "uid": "orbyflow-mysql"}
PCT = "100*GREATEST(tcp_ports,udp_ports)/capacity"
LAST = "bucket_utc=(SELECT MAX(bucket_utc) FROM orby_nat_public_minute WHERE $__timeFilter(bucket_utc))"
STEPS = [{"value": None, "color": "green"}, {"value": 60, "color": "yellow"}, {"value": 80, "color": "orange"},
         {"value": 95, "color": "red"}]


def target(sql, fmt="table"):
    return [{"refId": "A", "datasource": dict(DS), "editorMode": "code", "format": fmt, "rawQuery": True,
             "rawSql": sql}]


def stat(pid, title, sql, x, w, unit="none", steps=None, desc=""):
    return {"id": pid, "type": "stat", "title": title, "description": desc, "datasource": dict(DS),
            "gridPos": {"x": x, "y": 0, "w": w, "h": 5}, "targets": target(sql),
            "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                        "colorMode": "background", "graphMode": "none", "textMode": "value"},
            "fieldConfig": {"defaults": {"unit": unit, "decimals": 0, "thresholds": {"mode": "absolute", "steps":
                                         steps or [{"value": None, "color": "blue"}]}}, "overrides": []}}


def series(pid, title, sql, y, unit="none", desc="", steps=None, maxv=None):
    fc = {"unit": unit, "decimals": 0, "custom": {"lineWidth": 2, "fillOpacity": 8, "showPoints": "never",
                                                     "spanNulls": True}}
    if steps:
        fc["thresholds"] = {"mode": "absolute", "steps": steps}
        fc["custom"]["thresholdsStyle"] = {"mode": "line+area"}
    if maxv is not None:
        fc["max"], fc["min"] = maxv, 0
    return {"id": pid, "type": "timeseries", "title": title, "description": desc, "datasource": dict(DS),
            "gridPos": {"x": 0, "y": y, "w": 24, "h": 8}, "targets": target(sql, "time_series"),
            "options": {"legend": {"displayMode": "table", "placement": "right", "calcs": ["max", "lastNotNull"],
                                   "showLegend": True},
                        "tooltip": {"mode": "multi", "sort": "desc"}},
            "fieldConfig": {"defaults": fc, "overrides": []}}


def table(pid, title, sql, y, h=10, desc="", pct_col=None):
    overrides = []
    if pct_col:
        overrides.append({"matcher": {"id": "byName", "options": pct_col}, "properties": [
            {"id": "unit", "value": "percent"}, {"id": "decimals", "value": 1},
            {"id": "custom.cellOptions", "value": {"type": "color-background", "mode": "gradient"}},
            {"id": "thresholds", "value": {"mode": "absolute", "steps": STEPS}}]})
    return {"id": pid, "type": "table", "title": title, "description": desc, "datasource": dict(DS),
            "gridPos": {"x": 0, "y": y, "w": 24, "h": h}, "targets": target(sql),
            "options": {"showHeader": True, "cellHeight": "sm", "sortBy": []},
            "fieldConfig": {"defaults": {"custom": {"filterable": True, "align": "auto"}}, "overrides": overrides}}


def build():
    panels = [
        stat(1, "Maior uso de portas agora", "SELECT MAX(%s) AS value FROM orby_nat_public_minute WHERE %s" % (PCT, LAST),
             0, 6, "percent", STEPS, "IP público do pool com mais portas em uso (TCP ou UDP) sobre a capacidade."),
        stat(2, "IPs públicos acima de 80%", "SELECT COUNT(*) AS value FROM orby_nat_public_minute WHERE %s AND %s>=80"
             % (LAST, PCT), 6, 6, "none",
             [{"value": None, "color": "green"}, {"value": 1, "color": "red"}]),
        stat(3, "Portas NAT em uso (total)", "SELECT SUM(tcp_ports+udp_ports+other_ports) AS value FROM "
             "orby_nat_public_minute WHERE %s" % LAST, 12, 6),
        stat(4, "Assinantes com portas abertas", "SELECT SUM(subscribers) AS value FROM orby_nat_public_minute WHERE %s"
             % LAST, 18, 6),
        series(5, "Uso máximo de portas por pool (%)",
               "SELECT $__timeGroupAlias(bucket_utc,'1m'),pool AS metric,MAX(%s) AS value FROM orby_nat_public_minute "
               "WHERE $__timeFilter(bucket_utc) GROUP BY 1,pool ORDER BY 1" % PCT, 5, "percent",
               "O IP público mais cheio de cada pool, minuto a minuto. Acima de 80% a página Saúde avisa.", STEPS, 100),
        series(6, "Portas em uso por pool (TCP + UDP)",
               "SELECT $__timeGroupAlias(bucket_utc,'1m'),pool AS metric,SUM(tcp_ports+udp_ports+other_ports) AS value "
               "FROM orby_nat_public_minute WHERE $__timeFilter(bucket_utc) GROUP BY 1,pool ORDER BY 1", 13),
        series(7, "10 IPs públicos mais cheios (%)",
               "SELECT $__timeGroupAlias(p.bucket_utc,'1m'),p.public_ip AS metric,%s AS value FROM "
               "orby_nat_public_minute p JOIN (SELECT public_ip FROM orby_nat_public_minute WHERE "
               "$__timeFilter(bucket_utc) GROUP BY public_ip ORDER BY MAX(GREATEST(tcp_ports,udp_ports)/capacity) DESC "
               "LIMIT 10) t ON t.public_ip=p.public_ip WHERE $__timeFilter(p.bucket_utc) ORDER BY 1"
               % PCT.replace("tcp_ports", "p.tcp_ports").replace("udp_ports", "p.udp_ports").replace("capacity",
                                                                                                    "p.capacity"),
               21, "percent", steps=STEPS, maxv=100),
        table(8, "IPs públicos — uso atual",
              "SELECT public_ip AS 'IP público',pool AS 'Pool',tcp_ports AS 'Portas TCP',udp_ports AS 'Portas UDP',"
              "%s AS 'Uso (%%)',subscribers AS 'Assinantes',allocs AS 'Alocações/min',capacity AS 'Capacidade' FROM "
              "orby_nat_public_minute WHERE %s ORDER BY GREATEST(tcp_ports,udp_ports) DESC LIMIT 300" % (PCT, LAST),
              29, 12, "Último minuto do período. Capacidade = portas por protocolo em cada IP público.", "Uso (%)"),
        table(9, "Pico de uso no período por IP público",
              "SELECT public_ip AS 'IP público',MAX(pool) AS 'Pool',MAX(%s) AS 'Pico de uso (%%)',MAX(subscribers) AS "
              "'Assinantes (máx)',MAX(allocs) AS 'Alocações/min (máx)' FROM orby_nat_public_minute WHERE "
              "$__timeFilter(bucket_utc) GROUP BY public_ip ORDER BY 3 DESC LIMIT 50" % PCT,
              41, 10, "", "Pico de uso (%)"),
        table(10, "Quem está ocupando cada IP público (pico no período)",
              "SELECT public_ip AS 'IP público',MAX(pool) AS 'Pool',inside_ip AS 'Assinante (IP privado)',"
              "MAX(share_pct) AS 'Ocupa do IP (%%)',MAX(GREATEST(tcp_ports,udp_ports)) AS 'Portas (máx)' FROM "
              "orby_nat_heavy_minute WHERE $__timeFilter(bucket_utc) GROUP BY public_ip,inside_ip "
              "ORDER BY 4 DESC LIMIT 30",
              51, 10, "Assinantes com 1.000+ portas e quanto do IP público eles ocupam sozinhos. Sem cota por "
              "assinante no A10, um só cliente pode esgotar o IP dos vizinhos. Detalhe: dashboard CGNAT - Assinantes.",
              "Ocupa do IP (%)"),
        series(11, "Alocações de portas por minuto (por pool)",
               "SELECT $__timeGroupAlias(bucket_utc,'1m'),pool AS metric,SUM(allocs) AS value FROM orby_nat_public_minute "
               "WHERE $__timeFilter(bucket_utc) GROUP BY 1,pool ORDER BY 1", 61),
    ]
    return {"id": None, "uid": "orbyflow-cgnat-portas", "title": "CGNAT - Portas por IP público",
            "description": "Capacidade: uso de portas NAT por IP público do pool (log do A10, sem amostragem). Um IP público com "
                           "portas esgotadas faz as novas conexões dos assinantes que o compartilham falharem.",
            "tags": ["orbyflow", "cgnat", "a10", "portas"], "editable": True, "schemaVersion": 41, "version": 1,
            "graphTooltip": 1, "links": [], "liveNow": False, "timezone": "browser",
            "time": {"from": "now-6h", "to": "now"}, "refresh": "1m", "fiscalYearStartMonth": 0,
            "timepicker": {"refresh_intervals": ["1m", "5m", "15m"]},
            "annotations": {"list": [{"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"},
                                      "enable": True, "hide": True, "iconColor": "rgba(0, 211, 255, 1)",
                                      "name": "Annotations & Alerts", "type": "dashboard"}]},
            "templating": {"list": []}, "panels": panels}


if __name__ == "__main__":
    OUT.write_text(json.dumps(build(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(OUT.name)
