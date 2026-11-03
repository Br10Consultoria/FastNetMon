"""Gera o dashboard "Alarmes por filtro" (grafana/dashboards/orbyflow-alarmes.json).

Mostra o que os alarmes ligados no painel web (pagina Alarmes) estao medindo e os incidentes que abriram:
situacao de cada alarme agora, incidentes com pico e quem apareceu no top, e a medida minuto a minuto de cada
alarme (Mbps, pacotes/s, fluxos) com os minutos em que a condicao casou.
Fontes: orby_filter_rules, orby_filter_rule_state, orby_filter_incidents, orby_filter_rule_samples.
  python3 grafana/build_alarms.py
"""
from __future__ import annotations

import json
from pathlib import Path

from build_cgnat_ports import DS, series, stat, table

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "grafana" / "dashboards" / "orbyflow-alarmes.json"
RULES = "r.id IN (${alarme:csv})"


def at(panel, y, x=0, w=24, h=None):
    panel["gridPos"].update({"y": y, "x": x, "w": w})
    if h:
        panel["gridPos"]["h"] = h
    return panel


def unit_override(panel, column, unit):
    panel["fieldConfig"]["overrides"].append({"matcher": {"id": "byName", "options": column},
                                              "properties": [{"id": "unit", "value": unit}]})
    return panel


def build():
    red = [{"value": None, "color": "green"}, {"value": 1, "color": "red"}]
    state = table(5, "Alarmes agora",
                  "SELECT r.name AS 'Alarme',IF(r.enabled,'ligado','desligado') AS 'Ligado',"
                  "CASE WHEN NOT r.enabled THEN '—' WHEN s.status='open' THEN 'INCIDENTE' WHEN s.status='cooling' "
                  "THEN 'resfriando' WHEN s.last_bucket IS NULL THEN 'aguardando' ELSE 'normal' END AS 'Situação',"
                  "CASE r.direction WHEN 'in' THEN 'recebido' WHEN 'out' THEN 'originado' ELSE 'ambos' END AS 'Sentido',"
                  "r.severity AS 'Severidade',s.last_bucket AS 'Último minuto (UTC)',s.last_bps AS 'Taxa',"
                  "s.last_pps AS 'Pacotes/s',s.last_flows AS 'Fluxos/min',NULLIF(s.last_error,'') AS 'Erro',"
                  "r.expr AS 'Filtro' FROM orby_filter_rules r LEFT JOIN orby_filter_rule_state s ON s.rule_id=r.id "
                  "ORDER BY r.enabled DESC,(s.status='open') DESC,r.name", 5, 9,
                  "Liga/desliga e limites: painel web > Alarmes. Cada alarme ligado é avaliado a cada minuto (24x7).")
    unit_override(state, "Taxa", "bps")
    unit_override(state, "Pacotes/s", "pps")
    incidents = table(6, "Incidentes no período",
                      "SELECT i.rule_name AS 'Alarme',i.severity AS 'Severidade',CASE i.status WHEN 'open' THEN "
                      "'aberto' WHEN 'cooling' THEN 'resfriando' ELSE 'encerrado' END AS 'Situação',i.started_at AS "
                      "'Início (UTC)',i.resolved_at AS 'Fim (UTC)',TIMESTAMPDIFF(MINUTE,i.started_at,COALESCE("
                      "i.resolved_at,UTC_TIMESTAMP())) AS 'Duração (min)',i.peak_bps AS 'Pico taxa',i.peak_pps AS "
                      "'Pico pacotes/s',i.matches AS 'Minutos casados',CONCAT_WS(', ',JSON_VALUE(i.top,'$[0].key'),"
                      "JSON_VALUE(i.top,'$[1].key'),JSON_VALUE(i.top,'$[2].key')) AS 'Top (IPs/portas)',"
                      "COALESCE(JSON_VALUE(i.top,'$[0].assinantes[0]'),JSON_VALUE(i.top,'$[1].assinantes[0]'),"
                      "JSON_VALUE(i.top,'$[2].assinantes[0]')) AS 'Assinante (CGNAT)' FROM orby_filter_incidents i "
                      "JOIN orby_filter_rules r ON r.id=i.rule_id WHERE " + RULES + " AND i.started_at<$__timeTo() AND "
                      "(i.resolved_at IS NULL OR i.resolved_at>=$__timeFrom()) ORDER BY i.started_at DESC LIMIT 300",
                      14, 10, "Top = quem mais pesou no alarme (destino, origem, porta... conforme o relatório do "
                      "alarme). Detalhe por IP: painel web > Ataques (tipo 'Filtro: ...').")
    unit_override(incidents, "Pico taxa", "bps")
    unit_override(incidents, "Pico pacotes/s", "pps")
    p = [
        at(stat(1, "Alarmes ligados", "SELECT COUNT(*) AS value FROM orby_filter_rules WHERE enabled=1", 0, 6), 0, 0, 6),
        at(stat(2, "Incidentes abertos agora",
                "SELECT COUNT(*) AS value FROM orby_filter_incidents WHERE status IN ('open','cooling')", 6, 6, "none",
                red), 0, 6, 6),
        at(stat(3, "Incidentes no período",
                "SELECT COUNT(*) AS value FROM orby_filter_incidents WHERE $__timeFilter(started_at)", 12, 6, "none",
                [{"value": None, "color": "green"}, {"value": 1, "color": "orange"}]), 0, 12, 6),
        at(stat(4, "Alarmes com erro",
                "SELECT COUNT(*) AS value FROM orby_filter_rules r JOIN orby_filter_rule_state s ON s.rule_id=r.id "
                "WHERE r.enabled=1 AND s.last_error<>''", 18, 6, "none", red,
                "Filtro inválido ou atalho (@rede, @pools...) vazio: veja a coluna Erro abaixo."), 0, 18, 6),
        state,
        incidents,
        series(7, "Taxa medida por alarme (Mbps)",
               "SELECT $__timeGroupAlias(x.bucket_utc,'1m'),r.name AS metric,x.bps/1000000 AS value FROM "
               "orby_filter_rule_samples x JOIN orby_filter_rules r ON r.id=x.rule_id WHERE " + RULES +
               " AND $__timeFilter(x.bucket_utc) ORDER BY 1", 24, "Mbps",
               "O que cada alarme mediu minuto a minuto (soma do tráfego que casa com o filtro)."),
        series(8, "Pacotes/s medidos por alarme",
               "SELECT $__timeGroupAlias(x.bucket_utc,'1m'),r.name AS metric,x.pps AS value FROM "
               "orby_filter_rule_samples x JOIN orby_filter_rules r ON r.id=x.rule_id WHERE " + RULES +
               " AND $__timeFilter(x.bucket_utc) ORDER BY 1", 32, "pps"),
        series(9, "Minutos em que a condição casou",
               "SELECT $__timeGroupAlias(x.bucket_utc,'1m'),r.name AS metric,x.matched AS value FROM "
               "orby_filter_rule_samples x JOIN orby_filter_rules r ON r.id=x.rule_id WHERE " + RULES +
               " AND $__timeFilter(x.bucket_utc) ORDER BY 1", 40, "none",
               "1 = a condição do alarme foi atendida naquele minuto. O incidente abre depois dos 'minutos seguidos' "
               "configurados no alarme."),
    ]
    p[-1]["fieldConfig"]["defaults"]["custom"].update({"drawStyle": "bars", "fillOpacity": 80})
    p[-1]["fieldConfig"]["defaults"].update({"min": 0, "max": 1})
    var = {"type": "query", "name": "alarme", "label": "Alarme", "datasource": dict(DS),
           "query": "SELECT CONCAT(name, IF(enabled,'',' (desligado)')) AS __text, id AS __value FROM orby_filter_rules ORDER BY enabled DESC, name",
           "definition": "SELECT CONCAT(name, IF(enabled,'',' (desligado)')) AS __text, id AS __value FROM orby_filter_rules ORDER BY enabled DESC, name",
           "refresh": 1, "multi": True, "includeAll": True, "allValue": "SELECT id FROM orby_filter_rules",
           "current": {"text": "All", "value": "$__all"}, "hide": 0, "skipUrlSync": False, "sort": 1}
    return {"id": None, "uid": "orbyflow-alarmes", "title": "Alarmes por filtro",
            "description": "Alarmes ligados no painel web (página Alarmes): situação agora, incidentes e a medida "
                           "minuto a minuto de cada um.",
            "tags": ["orbyflow", "alarmes", "filtros"], "editable": True, "schemaVersion": 41, "version": 1,
            "graphTooltip": 1, "links": [], "liveNow": False, "timezone": "browser",
            "time": {"from": "now-24h", "to": "now"}, "refresh": "1m", "fiscalYearStartMonth": 0,
            "timepicker": {"refresh_intervals": ["1m", "5m", "15m"]},
            "annotations": {"list": [{"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"},
                                      "enable": True, "hide": True, "iconColor": "rgba(0, 211, 255, 1)",
                                      "name": "Annotations & Alerts", "type": "dashboard"}]},
            "templating": {"list": [var]}, "panels": p}


if __name__ == "__main__":
    OUT.write_text(json.dumps(build(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(OUT.name)
