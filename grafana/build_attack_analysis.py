"""Gera o dashboard "Análise de ataques" (grafana/dashboards/orbyflow-analise-ataques.json).

Vetores identificados pela análise automática (fmn_filters.attack_analysis), quem mais ataca (redes de origem),
quem mais é atacado, ataques analisados um a um e os clientes suspeitos (ataques originados, C2/botnet,
IPs de má reputação e abuso de portas NAT somados numa pontuação).
Fontes: orby_attack_analysis, orby_attack_events, orby_threat_hits.
  python3 grafana/build_attack_analysis.py
"""
from __future__ import annotations

import json
from pathlib import Path

from build_cgnat_ports import series, stat, table

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "grafana" / "dashboards" / "orbyflow-analise-ataques.json"
DIR = "('${sentido}'='all' OR %sdirection='${sentido}')"
SENT = "IF(%sdirection='in','recebido','originado')"


def at(panel, y, x=0, w=24, h=None):
    panel["gridPos"].update({"y": y, "x": x, "w": w})
    if h:
        panel["gridPos"]["h"] = h
    return panel


def units(panel, mapping):
    for col, unit in mapping.items():
        panel["fieldConfig"]["overrides"].append({"matcher": {"id": "byName", "options": col},
                                                  "properties": [{"id": "unit", "value": unit}]})
    return panel


def build():
    orange = [{"value": None, "color": "green"}, {"value": 1, "color": "orange"}]
    red = [{"value": None, "color": "green"}, {"value": 1, "color": "red"}]
    by_vector = series(6, "Detecções por vetor (por hora)",
                       "SELECT $__timeGroupAlias(a.event_time,'1h'),a.main_vector AS metric,COUNT(*) AS value FROM "
                       "orby_attack_analysis a WHERE $__timeFilter(a.event_time) AND " + DIR % "a." +
                       " GROUP BY 1,2 ORDER BY 1", 5, "none",
                       "Vetor identificado nos fluxos brutos de cada detecção (porta real, flags TCP, tamanho do pacote).")
    by_vector["fieldConfig"]["defaults"]["custom"].update({"drawStyle": "bars", "fillOpacity": 70,
                                                           "stacking": {"mode": "normal", "group": "A"}})
    p = [
        at(stat(1, "Ataques recebidos (detecções)", "SELECT COUNT(*) AS value FROM orby_attack_events WHERE "
                "direction='in' AND detection IN ('flow','filter') AND $__timeFilter(event_time)", 0, 6, "none", orange),
           0, 0, 6),
        at(stat(2, "Ataques originados por clientes", "SELECT COUNT(*) AS value FROM orby_attack_events WHERE "
                "direction='out' AND detection IN ('flow','filter') AND $__timeFilter(event_time)", 6, 6, "none", red),
           0, 6, 6),
        at(stat(3, "IPs nossos atacados", "SELECT COUNT(DISTINCT local_ip) AS value FROM orby_attack_events WHERE "
                "direction='in' AND $__timeFilter(event_time)", 12, 6), 0, 12, 6),
        at(stat(4, "Maior ataque recebido", "SELECT MAX(mbps)*1000000 AS value FROM orby_attack_events WHERE "
                "direction='in' AND $__timeFilter(event_time)", 18, 6, "bps"), 0, 18, 6),
        by_vector,
        units(at(table(7, "Vetores no período",
                       "SELECT a.main_vector AS 'Vetor'," + SENT % "a." + " AS 'Sentido',COUNT(*) AS 'Detecções',"
                       "COUNT(DISTINCT a.local_ip) AS 'Alvos',MAX(e.mbps)*1000000 AS 'Pico',ROUND(AVG(a.bytes_per_packet)) "
                       "AS 'Bytes/pacote (média)',MAX(a.block_ips_hit) AS 'IPs do /24 (máx)' FROM orby_attack_analysis a "
                       "LEFT JOIN orby_attack_events e ON e.event_id=a.event_id WHERE $__timeFilter(a.event_time) AND " +
                       DIR % "a." + " GROUP BY 1,2 ORDER BY 3 DESC LIMIT 50", 13, 9,
                       "IPs do /24 = quantos IPs do mesmo bloco receberam o mesmo vetor na mesma janela (carpet "
                       "bombing quando são muitos)."), 13, 0, 12, 9), {"Pico": "bps"}),
        at(table(8, "Redes que mais atacam (origem dos ataques recebidos)",
                 "SELECT CONCAT('AS',a.top_asn) AS 'ASN',MAX(a.top_asn_name) AS 'Nome',MAX(a.top_country) AS 'País',"
                 "COUNT(*) AS 'Detecções',COUNT(DISTINCT a.local_ip) AS 'Alvos',GROUP_CONCAT(DISTINCT a.main_vector "
                 "ORDER BY a.main_vector SEPARATOR ', ') AS 'Vetores' FROM orby_attack_analysis a WHERE "
                 "a.direction='in' AND a.top_asn>0 AND $__timeFilter(a.event_time) GROUP BY a.top_asn ORDER BY 4 DESC "
                 "LIMIT 30", 13, 9, "Rede (ASN) com mais volume em cada ataque recebido. Em amplificação são os "
                 "refletores (servidores abertos), não o atacante real."), 13, 12, 12, 9),
        units(at(table(9, "IPs nossos mais atacados",
                       "SELECT e.local_ip AS 'IP',MAX(e.pool) AS 'Pool',COUNT(*) AS 'Detecções',MAX(e.mbps)*1000000 AS "
                       "'Pico',GROUP_CONCAT(DISTINCT COALESCE(a.main_vector,e.rule_name) ORDER BY 1 SEPARATOR ', ') AS "
                       "'Vetores',MAX(e.event_time) AS 'Último (UTC)' FROM orby_attack_events e LEFT JOIN "
                       "orby_attack_analysis a ON a.event_id=e.event_id WHERE e.direction='in' AND "
                       "$__timeFilter(e.event_time) GROUP BY e.local_ip ORDER BY 3 DESC LIMIT 30", 22, 9),
                 22, 0, 12, 9), {"Pico": "bps"}),
        units(at(table(10, "Clientes suspeitos (pontuação)",
                       "SELECT ent AS 'Cliente',SUM(o) AS 'Ataques originados',SUM(c) AS 'Contatos C2',SUM(r) AS "
                       "'Má reputação',SUM(n) AS 'Alertas NAT',SUM(o)*3+SUM(c)*5+SUM(r)+SUM(n)*2 AS 'Pontuação',"
                       "MAX(t) AS 'Último (UTC)' FROM ("
                       "SELECT IF(subscriber_ip<>'',subscriber_ip,local_ip) AS ent,COUNT(*) AS o,0 AS c,0 AS r,0 AS n,"
                       "MAX(event_time) AS t FROM orby_attack_events WHERE direction='out' AND detection IN "
                       "('flow','filter') AND $__timeFilter(event_time) GROUP BY 1 "
                       "UNION ALL SELECT IF(subscriber_ip<>'',subscriber_ip,local_ip),0,0,0,COUNT(*),MAX(event_time) "
                       "FROM orby_attack_events WHERE detection='nat' AND $__timeFilter(event_time) GROUP BY 1 "
                       "UNION ALL SELECT cpe_ip,0,COUNT(*),0,0,MAX(last_seen) FROM orby_threat_hits WHERE "
                       "category='bot' AND last_seen>=$__timeFrom() GROUP BY 1 "
                       "UNION ALL SELECT cpe_ip,0,0,COUNT(*),0,MAX(last_seen) FROM orby_threat_hits WHERE "
                       "category='reputacao' AND last_seen>=$__timeFrom() GROUP BY 1) x GROUP BY ent ORDER BY 6 DESC "
                       "LIMIT 50", 22, 9,
                       "Soma dos sinais de equipamento infectado ou abusivo por cliente (assinante do CGNAT ou IP "
                       "dedicado): ataque originado vale 3, contato com C2 vale 5, alerta de NAT vale 2, IP de má "
                       "reputação vale 1. Primeiros da lista = candidatos a contato do suporte."),
                 22, 12, 12, 9), {}),
        units(at(table(11, "Ataques analisados",
                       "SELECT a.event_time AS 'Quando (UTC)'," + SENT % "a." + " AS 'Sentido',IF(a.subscriber_ip<>'',"
                       "a.subscriber_ip,a.local_ip) AS 'IP nosso',a.vector AS 'Vetor',a.remote_ips AS 'Origens',"
                       "IF(a.top_asn>0,CONCAT('AS',a.top_asn,' ',a.top_asn_name,IF(a.top_country<>'',CONCAT(' (',"
                       "a.top_country,')'),'')),'') AS 'Rede principal',a.bytes_per_packet AS 'Bytes/pacote',"
                       "ROUND(100*a.fragment_share) AS 'Fragmentos (%)',e.mbps*1000000 AS 'Taxa',e.rule_name AS 'Regra' "
                       "FROM orby_attack_analysis a LEFT JOIN orby_attack_events e ON e.event_id=a.event_id WHERE "
                       "$__timeFilter(a.event_time) AND " + DIR % "a." + " ORDER BY a.event_time DESC LIMIT 300", 31, 11,
                       "Detalhe completo (origens, redes, flags TCP): painel web > Ataques > detalhe."),
                 31, h=11), {"Taxa": "bps"}),
    ]
    var = {"type": "custom", "name": "sentido", "label": "Sentido",
           "query": "Todos : all,Recebidos : in,Originados : out",
           "options": [{"text": "Todos", "value": "all", "selected": True},
                       {"text": "Recebidos", "value": "in", "selected": False},
                       {"text": "Originados", "value": "out", "selected": False}],
           "current": {"text": "Todos", "value": "all"}, "hide": 0, "multi": False, "includeAll": False,
           "skipUrlSync": False}
    return {"id": None, "uid": "orbyflow-analise-ataques", "title": "Análise de ataques",
            "description": "Vetores identificados automaticamente em cada ataque, redes de origem, IPs mais atacados "
                           "e clientes suspeitos.",
            "tags": ["orbyflow", "ataques", "analise"], "editable": True, "schemaVersion": 41, "version": 1,
            "graphTooltip": 1, "links": [], "liveNow": False, "timezone": "browser",
            "time": {"from": "now-7d", "to": "now"}, "refresh": "5m", "fiscalYearStartMonth": 0,
            "timepicker": {"refresh_intervals": ["1m", "5m", "15m"]},
            "annotations": {"list": [{"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"},
                                      "enable": True, "hide": True, "iconColor": "rgba(0, 211, 255, 1)",
                                      "name": "Annotations & Alerts", "type": "dashboard"}]},
            "templating": {"list": [var]}, "panels": p}


if __name__ == "__main__":
    OUT.write_text(json.dumps(build(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(OUT.name)
