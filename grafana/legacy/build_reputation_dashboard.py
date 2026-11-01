# Gera grafana/dashboards/orbymon-reputacao.json. Uso: python3 grafana/build_reputation_dashboard.py
import json
DS = {"type": "mysql", "uid": "orbymon-mysql"}
IP = "${ip:sqlstring}"
panels = []
pid = [0]


def panel(title, ptype, sql, x, y, w, h, fmt="table", unit=None, overrides=None, desc="", options=None, defaults=None):
    pid[0] += 1
    p = {"id": pid[0], "title": title, "type": ptype, "datasource": DS, "description": desc,
         "gridPos": {"x": x, "y": y, "w": w, "h": h},
         "targets": [{"refId": "A", "datasource": DS, "rawSql": sql, "format": fmt, "editorMode": "code"}],
         "fieldConfig": {"defaults": dict({"color": {"mode": "palette-classic"}}, **(defaults or {})),
                         "overrides": overrides or []},
         "options": options or {}}
    if unit:
        p["fieldConfig"]["defaults"]["unit"] = unit
    panels.append(p)


def ov(name, unit, dec=0):
    return {"matcher": {"id": "byName", "options": name},
            "properties": [{"id": "unit", "value": unit}, {"id": "decimals", "value": dec}]}


def width(name, px):
    return {"matcher": {"id": "byName", "options": name}, "properties": [{"id": "custom.width", "value": px}]}


EV = f"$__timeFilter(event_time) AND direction='out' AND ({IP}='' OR local_ip={IP} OR subscriber_ip={IP})"
WHO = "IF(subscriber_ip='',local_ip,subscriber_ip)"
RED = {"color": {"mode": "thresholds"}, "thresholds": {"mode": "absolute", "steps": [
    {"color": "green", "value": None}, {"color": "red", "value": 1}]}}

pid[0] += 1
panels.append({"id": pid[0], "type": "text", "title": "Como usar", "gridPos": {"x": 0, "y": 0, "w": 24, "h": 3},
    "options": {"mode": "markdown", "content":
    "Ataques **originados** na rede e IPs do provedor em **listas de bloqueio**. Para IP de pool CGNAT, a coluna "
    "*Prováveis responsáveis* aponta o assinante (IP privado) pelos fluxos de saída. Para responder uma denúncia com "
    "horário e porta, use a página **Investigar** do painel de administração (porta 8443)."}})

panel("IPs listados agora", "stat",
      "SELECT COUNT(DISTINCT entry) AS value FROM orby_reputation_listings WHERE removed_at IS NULL", 0, 3, 6, 4,
      defaults=RED)
panel("Pools CGNAT listados", "stat",
      "SELECT COUNT(DISTINCT entry) AS value FROM orby_reputation_listings WHERE removed_at IS NULL AND scope='cgnat_pool'",
      6, 3, 6, 4, defaults=RED)
panel("Ataques originados no período", "stat", f"SELECT COUNT(*) AS value FROM orby_attack_events WHERE {EV}",
      12, 3, 6, 4, defaults=RED)
panel("Assinantes/IPs que originaram ataque", "stat",
      f"SELECT COUNT(DISTINCT {WHO}) AS value FROM orby_attack_events WHERE {EV}", 18, 3, 6, 4, defaults=RED)

panel("IPs do provedor em listas de bloqueio (agora)", "table",
      "SELECT entry AS 'IP / bloco',CASE scope WHEN 'cgnat_pool' THEN CONCAT('pool CGNAT ',pool) WHEN 'dedicated' "
      "THEN 'IP dedicado' WHEN 'infra' THEN 'infraestrutura' ELSE scope END AS 'Tipo',"
      "GROUP_CONCAT(DISTINCT source_label ORDER BY source_label SEPARATOR ', ') AS 'Listas',"
      "GROUP_CONCAT(DISTINCT category ORDER BY category SEPARATOR '; ') AS 'Motivo',"
      "MAX(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(detail,'$.suspeitos[0].ip')),JSON_UNQUOTE(JSON_EXTRACT(detail,'$.eventos[0].ip')),''))"
      " AS 'Provável responsável',MIN(first_seen) AS 'Listado desde (UTC)',MAX(last_seen) AS 'Visto (UTC)' "
      "FROM orby_reputation_listings WHERE removed_at IS NULL "
      f"AND ({IP}='' OR entry={IP} OR JSON_SEARCH(detail,'one',{IP}) IS NOT NULL) "
      "GROUP BY entry,scope,pool ORDER BY COUNT(*) DESC,entry LIMIT 200",
      0, 7, 24, 9, overrides=[width("IP / bloco", 150), width("Tipo", 170), width("Provável responsável", 170)],
      desc="Atualizado de hora em hora (DNSBL e AbuseIPDB a cada 6 h). Provável responsável = assinante com mais "
           "fluxos de saída para as portas típicas do abuso nas últimas 48 h.")

panel("Quem mais originou ataques (assinante ou IP dedicado)", "table",
      f"SELECT {WHO} AS 'Assinante / IP',MAX(local_ip) AS 'IP público',MAX(pool) AS 'Pool',COUNT(*) AS 'Eventos',"
      "GROUP_CONCAT(DISTINCT rule_name ORDER BY rule_name SEPARATOR ', ') AS 'Tipos',"
      "MAX(pps) AS 'Pico pps',MAX(mbps)*1000000 AS 'Pico taxa',MIN(event_time) AS 'Primeiro (UTC)',MAX(event_time) AS 'Último (UTC)' "
      f"FROM orby_attack_events WHERE {EV} GROUP BY {WHO} ORDER BY COUNT(*) DESC LIMIT 100",
      0, 16, 24, 10, overrides=[ov("Pico pps", "pps"), ov("Pico taxa", "bps", 1), width("Tipos", 320)],
      desc="IP privado 100.64.x = assinante CGNAT (identificado pelo log NAT do A10). Os eventos ficam guardados.")

panel("Ataques originados por hora", "timeseries",
      f"SELECT $__timeGroupAlias(event_time,'1h'),rule_name AS metric,COUNT(*) AS value FROM orby_attack_events "
      f"WHERE {EV} GROUP BY 1,rule_name ORDER BY 1",
      0, 26, 14, 9, fmt="time_series", unit="short",
      options={"legend": {"displayMode": "table", "placement": "right"}},
      defaults={"custom": {"drawStyle": "bars", "fillOpacity": 70, "stacking": {"mode": "normal"}}})
panel("Ataques originados por tipo", "piechart",
      f"SELECT rule_name AS metric,COUNT(*) AS value FROM orby_attack_events WHERE {EV} GROUP BY rule_name",
      14, 26, 10, 9, fmt="table", options={"reduceOptions": {"values": True, "calcs": ["sum"]},
                                           "legend": {"displayMode": "table", "placement": "right", "values": ["value"]}})

panel("Saída suspeita: muitos destinos na mesma porta (48 h, amostrado)", "table",
      "SELECT IF(subscriber_ip='',local_ip,subscriber_ip) AS 'Assinante / IP',local_ip AS 'IP público',remote_port AS 'Porta',"
      "protocol AS 'Proto',COUNT(DISTINCT remote_ip) AS 'Destinos distintos',SUM(flows) AS 'Fluxos' FROM orby_flow_minute "
      "WHERE source='huawei' AND direction='out' AND bucket_utc>=UTC_TIMESTAMP()-INTERVAL 2 DAY "
      "AND remote_port IN (22,23,25,445,465,587,1433,2323,3306,3389,5060,5900,8291) "
      f"AND ({IP}='' OR local_ip={IP} OR subscriber_ip={IP}) "
      "GROUP BY 1,local_ip,remote_port,protocol HAVING COUNT(DISTINCT remote_ip)>=20 "
      "ORDER BY COUNT(DISTINCT remote_ip) DESC LIMIT 100",
      0, 35, 24, 10,
      desc="Clientes falando com dezenas de destinos em portas de SSH, Telnet, SMTP, SMB, RDP, SQL, SIP ou MikroTik "
           "(8291) costumam estar infectados ou sendo usados para spam/varredura — é o que gera denúncias. "
           "NetFlow 1:2048: o número real de destinos é maior.")

panel("Histórico de listagens (saíram das listas)", "table",
      "SELECT entry AS 'IP / bloco',source_label AS 'Lista',category AS 'Motivo',first_seen AS 'Desde (UTC)',"
      "removed_at AS 'Saiu (UTC)' FROM orby_reputation_listings WHERE removed_at IS NOT NULL "
      f"AND ({IP}='' OR entry={IP}) ORDER BY removed_at DESC LIMIT 200", 0, 45, 14, 8)
panel("Situação das fontes", "table",
      "SELECT source AS 'Fonte',status AS 'Situação',last_ok AS 'Última com sucesso (UTC)',entries AS 'Entradas',"
      "matched AS 'Nos seus blocos',error AS 'Erro' FROM orby_reputation_sources ORDER BY status DESC,source",
      14, 45, 10, 8)

dash = {
    "id": None, "uid": "orbymon-reputacao", "title": "OrbyFlow | Reputação e ataques originados",
    "timezone": "browser", "schemaVersion": 40, "version": 1, "refresh": "5m",
    "time": {"from": "now-7d", "to": "now"}, "tags": ["orbymon", "reputacao", "abuso"],
    "description": "IPs do provedor em listas de bloqueio, assinante provável (CGNAT) e quem origina ataques.",
    "templating": {"list": [
        {"name": "ip", "label": "IP (público ou 100.64.x)", "type": "textbox", "query": "", "current": {"text": "", "value": ""}}]},
    "panels": panels,
}
open("grafana/dashboards/orbymon-reputacao.json", "w").write(json.dumps(dash, ensure_ascii=False, indent=2) + "\n")
print(len(panels), "paineis")
