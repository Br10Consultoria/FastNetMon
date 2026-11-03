"""Gera o dashboard "CGNAT - Assinantes (portas e abuso)" (grafana/dashboards/orbyflow-cgnat-assinantes.json).

Separado do dashboard de capacidade dos IPs publicos: aqui o foco e o ASSINANTE (IP privado).
  - quem ocupa muitas portas e quanto do IP publico dele isso representa (sem cota no A10, esgota os vizinhos);
  - rotatividade (alocacoes/min sobre portas abertas): alta = abre e fecha sem parar (bot, varredura);
    baixa com muitas portas = conexoes longas (P2P, muitos dispositivos);
  - alertas de NAT da deteccao;
  - um assinante escolhido no filtro: portas, alocacoes e para quais portas/destinos ele sai (fluxos amostrados).
Fontes: orby_nat_heavy_minute, orby_nat_user_minute, orby_attack_events (detection='nat') e orby_flow_minute.
  python3 grafana/build_cgnat_subscribers.py
"""
from __future__ import annotations

import json
from pathlib import Path

from build_cgnat_ports import DS, STEPS, series, stat, table

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "grafana" / "dashboards" / "orbyflow-cgnat-assinantes.json"
SUB = "${assinante:sqlstring}"
LAST_H = "bucket_utc=(SELECT MAX(bucket_utc) FROM orby_nat_heavy_minute WHERE $__timeFilter(bucket_utc))"
SHARE_STEPS = [{"value": None, "color": "green"}, {"value": 15, "color": "yellow"}, {"value": 30, "color": "orange"},
               {"value": 50, "color": "red"}]


def at(panel, y, x=0, w=24, h=None):
    panel["gridPos"].update({"y": y, "x": x, "w": w})
    if h:
        panel["gridPos"]["h"] = h
    return panel


def build():
    p = [
        at(stat(1, "Assinantes com 10 mil+ portas agora",
                "SELECT COUNT(*) AS value FROM orby_nat_heavy_minute WHERE %s AND GREATEST(tcp_ports,udp_ports)>=10000"
                % LAST_H, 0, 6, "none", [{"value": None, "color": "green"}, {"value": 1, "color": "orange"}],
                "Um assinante com 10 mil portas ocupa ~15% de um IP público inteiro."), 0, 0, 6),
        at(stat(2, "Maior fatia de um IP ocupada por 1 assinante",
                "SELECT MAX(share_pct) AS value FROM orby_nat_heavy_minute WHERE %s" % LAST_H, 6, 6, "percent",
                SHARE_STEPS), 0, 6, 6),
        at(stat(3, "Assinantes com 1.000+ portas agora",
                "SELECT COUNT(*) AS value FROM orby_nat_heavy_minute WHERE %s" % LAST_H, 12, 6), 0, 12, 6),
        at(stat(4, "Alertas de NAT no período",
                "SELECT COUNT(*) AS value FROM orby_attack_events WHERE detection='nat' AND $__timeFilter(event_time)",
                18, 6, "none", [{"value": None, "color": "green"}, {"value": 1, "color": "orange"}]), 0, 18, 6),
        at(table(5, "Assinantes que mais ocupam portas — agora",
                 "SELECT h.inside_ip AS 'Assinante (IP privado)',h.public_ip AS 'IP público',h.pool AS 'Pool',"
                 "h.tcp_ports AS 'Portas TCP',h.udp_ports AS 'Portas UDP',h.share_pct AS 'Ocupa do IP (%%)',"
                 "u.allocs AS 'Alocações/min',ROUND(u.allocs/GREATEST(1,u.active_ports)*100,1) AS 'Rotatividade (%%/min)' "
                 "FROM orby_nat_heavy_minute h LEFT JOIN orby_nat_user_minute u ON u.inside_ip=h.inside_ip AND "
                 "u.bucket_utc=h.bucket_utc WHERE h.%s ORDER BY GREATEST(h.tcp_ports,h.udp_ports) DESC LIMIT 50"
                 % LAST_H, 0, 10,
                 "Rotatividade = portas novas por minuto sobre as portas abertas. Alta (dezenas de %) = abre e fecha "
                 "sem parar: típico de bot/varredura. Baixa com muitas portas = conexões longas (P2P, muitos "
                 "aparelhos). Para ver um assinante, digite o IP no filtro do topo.", "Ocupa do IP (%)"), 5, h=10),
        at(table(6, "Pico no período por assinante",
                 "SELECT inside_ip AS 'Assinante (IP privado)',MAX(public_ip) AS 'IP público',"
                 "MAX(GREATEST(tcp_ports,udp_ports)) AS 'Portas (máx)',MAX(share_pct) AS 'Ocupa do IP (máx %%)',"
                 "SUM(GREATEST(tcp_ports,udp_ports)>=10000) AS 'Minutos com 10 mil+',COUNT(*) AS 'Minutos com 1.000+' "
                 "FROM orby_nat_heavy_minute WHERE $__timeFilter(bucket_utc) GROUP BY inside_ip ORDER BY 3 DESC LIMIT 50",
                 0, 10, "Quem passa mais tempo com muitas portas: candidato a contato do suporte (equipamento "
                 "infectado, P2P) ou a uma cota por assinante no A10.", "Ocupa do IP (máx %)"), 15, h=10),
        series(7, "Portas abertas — 10 assinantes que mais ocupam",
               "SELECT $__timeGroupAlias(h.bucket_utc,'1m'),h.inside_ip AS metric,GREATEST(h.tcp_ports,h.udp_ports) "
               "AS value FROM orby_nat_heavy_minute h JOIN (SELECT inside_ip FROM orby_nat_heavy_minute WHERE "
               "$__timeFilter(bucket_utc) GROUP BY inside_ip ORDER BY MAX(GREATEST(tcp_ports,udp_ports)) DESC LIMIT 10) t "
               "ON t.inside_ip=h.inside_ip WHERE $__timeFilter(h.bucket_utc) ORDER BY 1", 25),
        series(8, "Alocações de portas por minuto — 10 assinantes mais ativos",
               "SELECT $__timeGroupAlias(u.bucket_utc,'1m'),u.inside_ip AS metric,u.allocs AS value FROM "
               "orby_nat_user_minute u JOIN (SELECT inside_ip FROM orby_nat_user_minute WHERE $__timeFilter(bucket_utc) "
               "GROUP BY inside_ip ORDER BY SUM(allocs) DESC LIMIT 10) t ON t.inside_ip=u.inside_ip WHERE "
               "$__timeFilter(u.bucket_utc) ORDER BY 1", 33,
               desc="Muitas alocações por minuto, sustentadas, indicam conexões novas em massa (varredura, bot)."),
        at(table(9, "Alertas de NAT (detecção)",
                 "SELECT event_time AS 'Hora',rule_name AS 'Regra',severity AS 'Severidade',subscriber_ip AS "
                 "'Assinante',COALESCE(JSON_VALUE(details,'$.public_ips[0]'),'') AS 'IP público',"
                 "CAST(JSON_VALUE(details,'$.allocs_per_min') AS UNSIGNED) AS 'Alocações/min',"
                 "CAST(JSON_VALUE(details,'$.active_ports') AS UNSIGNED) AS 'Portas ativas',"
                 "COALESCE(CONCAT(JSON_VALUE(details,'$.top_portas[0].protocolo'),'/',JSON_VALUE(details,"
                 "'$.top_portas[0].porta'),' → ',JSON_VALUE(details,'$.top_portas[0].destinos'),' destinos'),'') AS "
                 "'Principal saída' FROM orby_attack_events WHERE detection='nat' AND $__timeFilter(event_time) "
                 "ORDER BY event_time DESC LIMIT 200", 0, 9), 41, h=9),
        series(10, "Assinante selecionado: portas abertas e alocações/min",
               "SELECT $__timeGroupAlias(bucket_utc,'1m'),'portas abertas' AS metric,active_ports AS value FROM "
               "orby_nat_user_minute WHERE inside_ip=%s AND $__timeFilter(bucket_utc) UNION ALL SELECT "
               "$__timeGroupAlias(bucket_utc,'1m'),'alocações/min',allocs FROM orby_nat_user_minute WHERE inside_ip=%s "
               "AND $__timeFilter(bucket_utc) ORDER BY 1" % (SUB, SUB), 50,
               desc="Digite o IP privado no filtro 'Assinante' no topo."),
        at(table(11, "Assinante selecionado: IP público, TCP e UDP (quando passa de 1.000 portas)",
                 "SELECT bucket_utc AS 'Minuto',public_ip AS 'IP público',tcp_ports AS 'TCP',udp_ports AS 'UDP',"
                 "share_pct AS 'Ocupa do IP (%%)' FROM orby_nat_heavy_minute WHERE inside_ip=%s AND "
                 "$__timeFilter(bucket_utc) ORDER BY bucket_utc DESC LIMIT 300" % SUB, 0, 9, "",
                 "Ocupa do IP (%)"), 58, 0, 12, 9),
        at(table(12, "Assinante selecionado: para onde ele sai (fluxos amostrados, últimos 2 dias)",
                 "SELECT protocol AS 'Proto',remote_port AS 'Porta destino',COUNT(DISTINCT remote_ip) AS "
                 "'Destinos distintos',SUM(packets) AS 'Pacotes (estim.)',SUM(bytes) AS 'Bytes (estim.)' FROM "
                 "orby_flow_minute WHERE subscriber_ip=%s AND direction='out' AND $__timeFilter(bucket_utc) "
                 "GROUP BY protocol,remote_port ORDER BY 3 DESC LIMIT 20" % SUB, 0, 9,
                 "Muitos destinos distintos na mesma porta (23, 22, 445, 3389) = varredura. Portas altas e "
                 "variadas com poucos destinos = P2P."), 58, 12, 12, 9),
    ]
    for panel in p:
        if panel["type"] == "timeseries" and "Assinante selecionado" not in panel["title"]:
            panel["fieldConfig"]["defaults"].pop("max", None)
    var = {"type": "textbox", "name": "assinante", "label": "Assinante (IP privado)", "query": "",
           "current": {"text": "", "value": ""}, "hide": 0, "skipUrlSync": False,
           "description": "IP privado do assinante (100.64.x.x) para os painéis de baixo"}
    return {"id": None, "uid": "orbyflow-cgnat-assinantes", "title": "CGNAT - Assinantes (portas e abuso)",
            "description": "Uso de portas NAT por assinante (log do A10, sem amostragem): quem ocupa o IP público dos "
                           "vizinhos, quem abre conexões em massa e os alertas de NAT. Capacidade dos IPs públicos: "
                           "dashboard CGNAT - Portas por IP público.",
            "tags": ["orbyflow", "cgnat", "a10", "assinantes"], "editable": True, "schemaVersion": 41, "version": 1,
            "graphTooltip": 1, "links": [], "liveNow": False, "timezone": "browser",
            "time": {"from": "now-6h", "to": "now"}, "refresh": "1m", "fiscalYearStartMonth": 0,
            "timepicker": {"refresh_intervals": ["1m", "5m", "15m"]},
            "annotations": {"list": [{"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"},
                                      "enable": True, "hide": True, "iconColor": "rgba(0, 211, 255, 1)",
                                      "name": "Annotations & Alerts", "type": "dashboard"}]},
            "templating": {"list": [var]}, "panels": p}


if __name__ == "__main__":
    OUT.write_text(json.dumps(build(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(OUT.name)
