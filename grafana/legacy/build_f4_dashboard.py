# Gera grafana/dashboards/orbyflow-f4-ataques.json. Uso: python3 grafana/build_f4_dashboard.py
import json
DS = {"type": "mysql", "uid": "orbyflow-mysql"}
IP = "${ip:sqlstring}"; REM = "${remoto:sqlstring}"; PORT = "${porta:sqlstring}"
DIR = "${direcao:sqlstring}"; PROTO = "${proto:sqlstring}"
F = ("source='huawei' AND $__timeFilter(bucket_utc)"
     f" AND ({IP}='' OR local_ip={IP} OR subscriber_ip={IP})"
     f" AND ({REM}='' OR remote_ip={REM})"
     f" AND ({PORT}='' OR local_port={PORT} OR remote_port={PORT})"
     f" AND ({DIR}='all' OR direction={DIR})"
     f" AND ({PROTO}='all' OR protocol={PROTO})")
EV = ("$__timeFilter(event_time)"
      f" AND ({IP}='' OR local_ip={IP} OR subscriber_ip={IP})"
      f" AND ({DIR}='all' OR direction={DIR})"
      f" AND ({PROTO}='all' OR protocol={PROTO})"
      f" AND ({PORT}='' OR local_port={PORT} OR remote_port={PORT})")
# todos os protocolos IP (IANA) pelo nome gravado no rollup; os mais comuns primeiro. Lista fixa: sem custo
# de consulta (um SELECT DISTINCT em 2 dias de fluxos seria lento a cada abertura do painel).
import sys
sys.path.insert(0, "src")
from fmn_filters.protocols import NUMBER_TO_NAME
COMMON = ["tcp", "udp", "icmp", "icmpv6", "gre", "esp", "ah", "ipv6", "ipip", "sctp", "ospf", "pim", "vrrp", "igmp", "l2tp"]
PROTO_OPTS = [("Todos", "all")] + [(n, n) for n in COMMON] + \
    [("%s (%d)" % (n, k), n) for k, n in sorted(NUMBER_TO_NAME.items()) if n not in COMMON]
DIRNAME = "CASE direction WHEN 'in' THEN 'recebido' ELSE 'originado' END"
panels = []
pid = [0]

def panel(title, ptype, sql, x, y, w, h, fmt="table", unit=None, overrides=None, desc="", options=None):
    pid[0] += 1
    p = {"id": pid[0], "title": title, "type": ptype, "datasource": DS, "description": desc,
         "gridPos": {"x": x, "y": y, "w": w, "h": h},
         "targets": [{"refId": "A", "datasource": DS, "rawSql": sql, "format": fmt, "editorMode": "code"}],
         "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}}, "overrides": overrides or []},
         "options": options or {}}
    if unit:
        p["fieldConfig"]["defaults"]["unit"] = unit
    panels.append(p)

def ov(name, unit, dec=2):
    return {"matcher": {"id": "byName", "options": name},
            "properties": [{"id": "unit", "value": unit}, {"id": "decimals", "value": dec}]}

pid[0] += 1
panels.append({"id": pid[0], "type": "text", "title": "Como usar", "gridPos": {"x": 0, "y": 0, "w": 24, "h": 4},
    "options": {"mode": "markdown", "content":
    "**Filtros no topo:** *IP* = IP público (dedicado ou pool CGNAT) **ou** IP privado 100.64.x do assinante; "
    "*IP remoto* = quem está do outro lado; *Porta* = porta de serviço (portas efêmeras são gravadas como 0); "
    "*Sentido* = recebido (internet → rede) ou originado (rede → internet). Período no relógio do canto superior. "
    "Fluxos detalhados ficam **2 dias**; eventos de ataque ficam guardados. Valores são estimativas de NetFlow amostrado 1:2048."}})

panel("Eventos de ataque RECEBIDOS no período", "stat",
      f"SELECT COUNT(*) AS value FROM orby_attack_events WHERE {EV} AND direction='in'", 0, 4, 6, 4)
panel("Eventos de ataque ORIGINADOS no período", "stat",
      f"SELECT COUNT(*) AS value FROM orby_attack_events WHERE {EV} AND direction='out'", 6, 4, 6, 4)
panel("Pico de taxa no filtro (1 min)", "stat",
      f"SELECT COALESCE(MAX(v),0) AS value FROM (SELECT SUM(bytes)*8/60 AS v FROM orby_flow_minute WHERE {F} GROUP BY bucket_utc) t",
      12, 4, 6, 4, unit="bps")
panel("Pico de pacotes/s no filtro (1 min)", "stat",
      f"SELECT COALESCE(MAX(v),0) AS value FROM (SELECT SUM(packets)/60 AS v FROM orby_flow_minute WHERE {F} GROUP BY bucket_utc) t",
      18, 4, 6, 4, unit="pps")

panel("Taxa por sentido e tipo de IP", "timeseries",
      f"SELECT $__timeGroupAlias(bucket_utc,'1m'),CONCAT({DIRNAME},' / ',scope) AS metric,SUM(bytes)*8/60 AS value "
      f"FROM orby_flow_minute WHERE {F} GROUP BY 1,direction,scope ORDER BY 1",
      0, 8, 12, 9, fmt="time_series", unit="bps", options={"legend": {"displayMode": "table", "placement": "bottom"}})
FQ = F.replace("bucket_utc", "f.bucket_utc").replace("source='huawei'", "f.source='huawei'")
EDGE = "CASE direction WHEN 'in' THEN f.input_if ELSE f.output_if END"
panel("Taxa por interface de borda (trânsito, PTT, CDN, peers)", "timeseries",
      f"SELECT $__timeGroupAlias(f.bucket_utc,'1m'),CONCAT({DIRNAME},' · ',"
      f"CASE WHEN {EDGE}=0 THEN 'sem interface (0)' ELSE COALESCE(MAX(im.if_name),CONCAT('ifIndex ',{EDGE},' (sem nome)')) END) AS metric,"
      "SUM(f.bytes)*8/60 AS value FROM orby_flow_minute AS f "
      f"LEFT JOIN orby_interface_names AS im ON im.source='huawei' AND im.if_index={EDGE} "
      f"WHERE {FQ} GROUP BY 1,direction,{EDGE} ORDER BY 1",
      0, 56, 24, 9, fmt="time_series", unit="bps", options={"legend": {"displayMode": "table", "placement": "bottom"}},
      desc="Recebido: interface por onde entrou. Originado: interface por onde saiu para a internet.")

panel("Pacotes/s por sentido, com SYN e porta 0", "timeseries",
      f"SELECT $__timeGroupAlias(bucket_utc,'1m'),{DIRNAME} AS metric,SUM(packets)/60 AS value FROM orby_flow_minute WHERE {F} GROUP BY 1,direction "
      f"UNION ALL SELECT $__timeGroupAlias(bucket_utc,'1m'),CONCAT({DIRNAME},' SYN'),SUM(syn_packets)/60 FROM orby_flow_minute WHERE {F} GROUP BY 1,direction "
      f"UNION ALL SELECT $__timeGroupAlias(bucket_utc,'1m'),CONCAT({DIRNAME},' porta 0/fragmentos'),SUM(zero_port_packets)/60 FROM orby_flow_minute WHERE {F} GROUP BY 1,direction "
      "ORDER BY 1",
      12, 8, 12, 9, fmt="time_series", unit="pps", options={"legend": {"displayMode": "table", "placement": "bottom"}},
      desc="SYN alto em relação ao total sugere SYN flood/varredura; porta 0/fragmentos alto sugere amplificação UDP fragmentada.")

def IFN(col, alias):
    return (f"CASE WHEN {col}=0 THEN 'sem interface (0)' "
            f"ELSE COALESCE({alias}.if_name,CONCAT('ifIndex ',{col},' (sem nome)')) END")

panel("Eventos de ataque detectados", "table",
      "SELECT event_time AS 'Hora',rule_name AS 'Regra',severity AS 'Severidade',"
      f"{DIRNAME} AS 'Sentido',scope AS 'Tipo',pool AS 'Pool',local_ip AS 'IP público/local',"
      "subscriber_ip AS 'IP assinante',protocol AS 'Proto',local_port AS 'Porta local',remote_port AS 'Porta remota',"
      "pps AS 'Pacotes/s',mbps*1000000 AS 'Taxa',remote_ips AS 'IPs remotos',syn_ratio AS 'SYN',"
      f"{IFN('e.input_if','im')} AS 'Entrou por',{IFN('e.output_if','om')} AS 'Saiu por' "
      "FROM orby_attack_events AS e "
      "LEFT JOIN orby_interface_names AS im ON im.source='huawei' AND im.if_index=e.input_if "
      "LEFT JOIN orby_interface_names AS om ON om.source='huawei' AND om.if_index=e.output_if "
      f"WHERE {EV} ORDER BY event_time DESC LIMIT 200",
      0, 17, 24, 9, overrides=[ov("Taxa", "bps"), ov("Pacotes/s", "pps", 0), ov("SYN", "percentunit", 0)])

panel("IPs da rede com maior pico (público, pool ou assinante)", "table",
      f"SELECT {DIRNAME} AS 'Sentido',scope AS 'Tipo',pool AS 'Pool',local_ip AS 'IP público/local',"
      "subscriber_ip AS 'IP assinante',MAX(bps) AS 'Pico',MAX(pps) AS 'Pico pacotes/s',SUM(vol) AS 'Volume',"
      "MAX(remotos) AS 'IPs remotos (pico)' FROM (SELECT direction,scope,pool,local_ip,subscriber_ip,bucket_utc,"
      "SUM(bytes)*8/60 AS bps,SUM(packets)/60 AS pps,SUM(bytes) AS vol,COUNT(DISTINCT remote_ip) AS remotos "
      f"FROM orby_flow_minute WHERE {F} GROUP BY direction,scope,pool,local_ip,subscriber_ip,bucket_utc) t "
      "GROUP BY direction,scope,pool,local_ip,subscriber_ip ORDER BY MAX(bps) DESC LIMIT 50",
      0, 26, 24, 10, overrides=[ov("Pico", "bps"), ov("Pico pacotes/s", "pps", 0), ov("Volume", "decbytes", 1)])

panel("IPs remotos (quem ataca ou é atacado)", "table",
      f"SELECT remote_ip AS 'IP remoto',{DIRNAME} AS 'Sentido',protocol AS 'Proto',"
      "COUNT(DISTINCT local_ip) AS 'IPs nossos envolvidos',SUM(bytes) AS 'Volume',SUM(packets)/GREATEST(1,$__unixEpochTo()-$__unixEpochFrom()) AS 'Pacotes/s médio' "
      f"FROM orby_flow_minute WHERE {F} GROUP BY remote_ip,direction,protocol ORDER BY SUM(bytes) DESC LIMIT 50",
      0, 36, 12, 10, overrides=[ov("Volume", "decbytes", 1), ov("Pacotes/s médio", "pps", 1)])
panel("Protocolos e portas de serviço", "table",
      f"SELECT {DIRNAME} AS 'Sentido',protocol AS 'Proto',local_port AS 'Porta local',remote_port AS 'Porta remota',"
      "SUM(bytes) AS 'Volume',SUM(packets)/GREATEST(1,$__unixEpochTo()-$__unixEpochFrom()) AS 'Pacotes/s médio',"
      "SUM(zero_port_packets)/GREATEST(1,SUM(packets)) AS 'Porta 0/frag.' "
      f"FROM orby_flow_minute WHERE {F} GROUP BY direction,protocol,local_port,remote_port ORDER BY SUM(bytes) DESC LIMIT 50",
      12, 36, 12, 10, overrides=[ov("Volume", "decbytes", 1), ov("Pacotes/s médio", "pps", 1), ov("Porta 0/frag.", "percentunit", 0)],
      desc="Porta 0 = efêmera (não guardada) ou porta 0 real; a coluna 'Porta 0/frag.' mostra só porta 0 real e fragmentos.")

panel("CGNAT: assinantes por trás de cada IP público do pool", "table",
      "SELECT local_ip AS 'IP público (pool)',pool AS 'Pool',subscriber_ip AS 'IP assinante',"
      f"{DIRNAME} AS 'Sentido',SUM(bytes) AS 'Volume',SUM(packets) AS 'Pacotes' FROM orby_flow_minute "
      f"WHERE {F} AND scope='cgnat_pool' AND subscriber_ip<>'' "
      "GROUP BY local_ip,pool,subscriber_ip,direction ORDER BY SUM(bytes) DESC LIMIT 50",
      0, 46, 12, 10, overrides=[ov("Volume", "decbytes", 1), ov("Pacotes", "short", 0)],
      desc="Depende do log NAT do A10. Fluxos sem mapeamento aparecem sem assinante.")
panel("CGNAT: alocações de porta do assinante (log A10, sem amostragem)", "timeseries",
      "SELECT $__timeGroupAlias(bucket_utc,'1m'),inside_ip AS metric,allocs AS value FROM orby_nat_user_minute "
      f"WHERE $__timeFilter(bucket_utc) AND ({IP}='' OR inside_ip={IP}) "
      f"AND ({IP}<>'' OR inside_ip IN (SELECT inside_ip FROM (SELECT inside_ip FROM orby_nat_user_minute WHERE $__timeFilter(bucket_utc) "
      "GROUP BY inside_ip ORDER BY SUM(allocs) DESC LIMIT 10) top)) ORDER BY 1",
      12, 46, 12, 10, fmt="time_series", unit="short",
      options={"legend": {"displayMode": "table", "placement": "bottom"}},
      desc="Sem IP no filtro: os 10 assinantes com mais alocações. Muitas alocações por minuto indicam varredura, flood ou malware.")

dash = {
    "id": None, "uid": "orbyflow-f4-ataques", "title": "OrbyFlow | F4 - Ataques e investigação por IP",
    "timezone": "browser", "schemaVersion": 40, "version": 1, "refresh": "1m",
    "time": {"from": "now-1h", "to": "now"}, "tags": ["orbyflow", "f4", "ataques"],
    "description": "Ataques recebidos e originados, com filtro por IP público, IP privado CGNAT, IP remoto, porta, protocolo e sentido.",
    "templating": {"list": [
        {"name": "ip", "label": "IP (público ou 100.64.x)", "type": "textbox", "query": "", "current": {"text": "", "value": ""}},
        {"name": "remoto", "label": "IP remoto", "type": "textbox", "query": "", "current": {"text": "", "value": ""}},
        {"name": "porta", "label": "Porta", "type": "textbox", "query": "", "current": {"text": "", "value": ""}},
        {"name": "direcao", "label": "Sentido", "type": "custom", "query": "Todos : all,Recebido : in,Originado : out",
         "current": {"text": "Todos", "value": "all"},
         "options": [{"text": "Todos", "value": "all", "selected": True}, {"text": "Recebido", "value": "in", "selected": False},
                     {"text": "Originado", "value": "out", "selected": False}]},
        {"name": "proto", "label": "Protocolo", "type": "custom",
         "query": ",".join("%s : %s" % (t.replace(",", " "), v) for t, v in PROTO_OPTS),
         "current": {"text": "Todos", "value": "all"},
         "options": [{"text": t, "value": v, "selected": v == "all"} for t, v in PROTO_OPTS],
         "description": "Todos os protocolos IP (IANA). Digite para buscar: gre, ah, ospf, sctp..."},
    ]},
    "panels": panels,
}
open("grafana/dashboards/orbyflow-f4-ataques.json", "w").write(json.dumps(dash, ensure_ascii=False, indent=2) + "\n")
print(len(panels), "paineis")
