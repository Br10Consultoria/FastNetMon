"""Gera o dashboard "C2 e botnets" (grafana/dashboards/orbyflow-c2-botnets.json).

Clientes que enviaram trafego para IPs de listas publicas de ameacas (fmn_filters.threat_intel): C2/botnet
(equipamento provavelmente infectado) e IPs de ma reputacao. Mesmo conteudo da pagina "C2 e botnets" do painel.
Fontes: orby_threat_hits, orby_threat_sources.
  python3 grafana/build_c2.py
"""
from __future__ import annotations

import json
from pathlib import Path

from build_cgnat_ports import DS, stat, table

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "grafana" / "dashboards" / "orbyflow-c2-botnets.json"
IP = "${ip:sqlstring}"
WHERE = ("last_seen>=$__timeFrom() AND first_seen<=$__timeTo() AND (%s='' OR cpe_ip=%s OR remote_ip=%s OR public_ip=%s)"
         % (IP, IP, IP, IP))
COLS = ("cpe_ip AS 'Cliente',NULLIF(public_ip,cpe_ip) AS 'IP público',NULLIF(pool,'') AS 'Pool',remote_ip AS 'IP listado',"
        "CONCAT(UPPER(CONVERT(protocol USING utf8mb4)),'/',IF(remote_port>0,remote_port,IF(listed_port>0,listed_port,'—'))) AS 'Porta',"
        "sources AS 'Listas',NULLIF(malware,'') AS 'Malware',flows AS 'Fluxos',bytes AS 'Volume (estim.)',"
        "first_seen AS 'Primeiro contato (UTC)',last_seen AS 'Último contato (UTC)'")


def at(panel, y, x=0, w=24, h=None):
    panel["gridPos"].update({"y": y, "x": x, "w": w})
    if h:
        panel["gridPos"]["h"] = h
    return panel


def bytes_col(panel):
    panel["fieldConfig"]["overrides"].append({"matcher": {"id": "byName", "options": "Volume (estim.)"},
                                              "properties": [{"id": "unit", "value": "decbytes"}]})
    return panel


def build():
    red = [{"value": None, "color": "green"}, {"value": 1, "color": "red"}]
    orange = [{"value": None, "color": "green"}, {"value": 1, "color": "orange"}]
    bot = bytes_col(table(5, "Clientes falando com C2/botnet",
                          "SELECT " + COLS + " FROM orby_threat_hits WHERE category='bot' AND " + WHERE +
                          " ORDER BY last_seen DESC LIMIT 500", 5, 10,
                          "Servidor de comando de malware: o equipamento do cliente (roteador, câmera, PC) provavelmente "
                          "está infectado. Também vira alerta em Ataques e no Telegram (uma vez por dia por par)."))
    rep = bytes_col(table(6, "Clientes falando com IP de má reputação",
                          "SELECT " + COLS + " FROM orby_threat_hits WHERE category='reputacao' AND " + WHERE +
                          " ORDER BY bytes DESC LIMIT 500", 15, 10,
                          "IP em listas de varredura, spam ou rede criminosa (IPsum, Spamhaus DROP...). Vale olhar, "
                          "nem sempre é infecção."))
    p = [
        at(stat(1, "Clientes falando com C2/botnet", "SELECT COUNT(DISTINCT cpe_ip) AS value FROM orby_threat_hits "
                "WHERE category='bot' AND " + WHERE, 0, 6, "none", red,
                "Clientes (assinante do CGNAT ou IP dedicado) que enviaram tráfego para um IP de comando de botnet."),
           0, 0, 6),
        at(stat(2, "IPs de C2 contactados", "SELECT COUNT(DISTINCT remote_ip) AS value FROM orby_threat_hits WHERE "
                "category='bot' AND " + WHERE, 6, 6, "none", red), 0, 6, 6),
        at(stat(3, "Clientes falando com IP de má reputação", "SELECT COUNT(DISTINCT cpe_ip) AS value FROM "
                "orby_threat_hits WHERE category='reputacao' AND " + WHERE, 12, 6, "none", orange), 0, 12, 6),
        at(stat(4, "Listas com falha", "SELECT COUNT(*) AS value FROM orby_threat_sources WHERE status<>'ok'", 18, 6,
                "none", orange, "Lista que não baixou na última tentativa (a cópia anterior continua valendo). "
                "ThreatFox sem Auth-Key aparece aqui."), 0, 18, 6),
        bot,
        rep,
        at(table(7, "Malware mais visto",
                 "SELECT COALESCE(NULLIF(malware,''),'(sem família informada)') AS 'Malware',COUNT(DISTINCT cpe_ip) AS "
                 "'Clientes',COUNT(DISTINCT remote_ip) AS 'IPs de C2',MAX(last_seen) AS 'Último contato (UTC)' FROM "
                 "orby_threat_hits WHERE category='bot' AND " + WHERE + " GROUP BY 1 ORDER BY 2 DESC LIMIT 30", 25, 8),
           25, 0, 12, 8),
        at(table(8, "Listas",
                 "SELECT label AS 'Lista',IF(category='bot','C2/botnet','reputação') AS 'Categoria',status AS "
                 "'Situação',last_ok AS 'Última atualização (UTC)',entries AS 'Entradas',NULLIF(error,'') AS 'Erro' "
                 "FROM orby_threat_sources ORDER BY category,label", 25, 8,
                 "Configuração e Auth-Key do ThreatFox: painel web > Investigação > C2 e botnets."), 25, 12, 12, 8),
    ]
    var = {"type": "textbox", "name": "ip", "label": "IP (cliente, público ou listado)", "query": "",
           "current": {"text": "", "value": ""}, "hide": 0, "skipUrlSync": False}
    return {"id": None, "uid": "orbyflow-c2-botnets", "title": "C2 e botnets",
            "description": "Clientes que enviaram tráfego para IPs de listas públicas de ameaças: C2/botnet e má "
                           "reputação, com o assinante do CGNAT. O NetStream é amostrado: contato curto com C2 só aparece "
                           "quando algum pacote cai na amostra.",
            "tags": ["orbyflow", "seguranca", "botnet", "c2"], "editable": True, "schemaVersion": 41, "version": 1,
            "graphTooltip": 1, "links": [], "liveNow": False, "timezone": "browser",
            "time": {"from": "now-7d", "to": "now"}, "refresh": "5m", "fiscalYearStartMonth": 0,
            "timepicker": {"refresh_intervals": ["5m", "15m", "1h"]},
            "annotations": {"list": [{"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"},
                                      "enable": True, "hide": True, "iconColor": "rgba(0, 211, 255, 1)",
                                      "name": "Annotations & Alerts", "type": "dashboard"}]},
            "templating": {"list": [var]}, "panels": p}


if __name__ == "__main__":
    OUT.write_text(json.dumps(build(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(OUT.name)
