# Reescreve tabelas com ASN/pais e os mapas (ordem ASN, Nome, IP/Bloco, Pais; unidades; mapa interativo).
# Uso: python3 grafana/fix_names_units_maps.py  (idempotente)
import json

RANGE = "GREATEST(1,$__unixEpochTo()-$__unixEpochFrom())"
BASE = "FROM orby_ip_pairs_minute WHERE source='huawei' AND $__timeFilter(bucket_utc)"
CN = "LEFT JOIN orby_country_names AS cn ON cn.code=t.pais"
PAIS = "COALESCE(cn.name,NULLIF(t.pais,''),'Não informado')"
RATES = ("SUM(total_bytes) AS vol,SUM(total_bytes)*8/" + RANGE + " AS bps,"
         "SUM(total_packets)/" + RANGE + " AS pps")
OUT_RATES = "t.vol AS 'Volume',t.bps AS 'Taxa média',t.pps AS 'Pacotes/s médio'"


def ov(name, unit, dec):
    return {"matcher": {"id": "byName", "options": name},
            "properties": [{"id": "unit", "value": unit}, {"id": "decimals", "value": dec}]}


RATE_OVERRIDES = [ov("Volume", "decbytes", 1), ov("Taxa média", "bps", 2), ov("Pacotes/s médio", "pps", 1)]


def asn_table(limit):
    return ("SELECT t.asn AS 'ASN',t.nome AS 'Nome',t.blocos AS 'Blocos / IPs',t.ips AS 'IPs',"
            "CASE WHEN t.paises>1 THEN 'Vários' ELSE " + PAIS + " END AS 'País'," + OUT_RATES +
            " FROM (SELECT src_asn AS asn,COALESCE(MAX(NULLIF(src_asn_name,'')),'Não identificado') AS nome,"
            "COALESCE(NULLIF(GROUP_CONCAT(DISTINCT NULLIF(src_prefix,'') ORDER BY src_prefix SEPARATOR ', ' LIMIT 3),''),"
            "GROUP_CONCAT(DISTINCT src_ip ORDER BY src_ip SEPARATOR ', ' LIMIT 3)) AS blocos,"
            "COUNT(DISTINCT src_ip) AS ips,COUNT(DISTINCT NULLIF(src_country,'')) AS paises,"
            "MAX(NULLIF(src_country,'')) AS pais," + RATES + " " + BASE +
            " AND src_asn>0 GROUP BY src_asn ORDER BY SUM(total_bytes) DESC LIMIT %d) AS t %s ORDER BY t.vol DESC" % (limit, CN))


def ip_table(side, label, limit):
    return ("SELECT t.asn AS 'ASN',t.nome AS 'Nome',t.ip AS '%s',t.bloco AS 'Bloco'," % label + PAIS + " AS 'País'," +
            OUT_RATES + " FROM (SELECT %(s)s_ip AS ip,MAX(%(s)s_asn) AS asn,"
            "COALESCE(MAX(NULLIF(%(s)s_asn_name,'')),'Não identificado') AS nome,"
            "COALESCE(MAX(NULLIF(%(s)s_prefix,'')),'—') AS bloco,MAX(NULLIF(%(s)s_country,'')) AS pais," % {"s": side} +
            RATES + " " + BASE + " GROUP BY %s_ip ORDER BY SUM(total_bytes) DESC LIMIT %d) AS t %s ORDER BY t.vol DESC"
            % (side, limit, CN))


def country_table(limit, ips_label):
    return ("SELECT " + PAIS + " AS 'País',t.ips AS '%s'," % ips_label + OUT_RATES +
            " FROM (SELECT src_country AS pais,COUNT(DISTINCT src_ip) AS ips," + RATES + " " + BASE +
            " AND src_country<>'' GROUP BY src_country ORDER BY SUM(total_bytes) DESC LIMIT %d) AS t %s ORDER BY t.vol DESC"
            % (limit, CN))


def geo_sql(with_operator=True):
    return ("SELECT t.latitude,t.longitude," + PAIS + " AS 'País',t.asn AS 'ASN',t.nome AS 'Nome',"
            "t.ips AS 'IPs de origem',t.vol AS 'Volume' FROM (SELECT src_latitude AS latitude,src_longitude AS longitude,"
            "src_asn AS asn,COALESCE(MAX(NULLIF(src_asn_name,'')),'Não identificado') AS nome,"
            "MAX(NULLIF(src_country,'')) AS pais,COUNT(DISTINCT src_ip) AS ips,SUM(total_bytes) AS vol " + BASE +
            " AND src_latitude IS NOT NULL AND src_longitude IS NOT NULL GROUP BY src_latitude,src_longitude,src_asn"
            " ORDER BY SUM(total_bytes) DESC LIMIT 300) AS t " + CN + " ORDER BY t.vol DESC")


def interactive_map(p, size_field="Volume", color="#FF891A"):
    layer = p["options"]["layers"][0]
    style = {"size": {"fixed": 7, "min": 5, "max": 26}, "color": {"fixed": color},
             "opacity": 0.7, "symbol": {"mode": "fixed", "fixed": "img/icons/marker/circle.svg"}}
    if size_field:
        style["size"]["field"] = size_field
        style["color"] = {"field": size_field, "fixed": color}
    layer["config"] = {"style": style, "showLegend": True}
    layer["tooltip"] = True
    p["options"]["view"] = {"id": "fit", "allLayers": True, "padding": 10, "maxZoom": 6, "lat": -14, "lon": -51, "zoom": 3}
    p["options"]["controls"] = {"showZoom": True, "mouseWheelZoom": True, "showAttribution": True,
                                "showScale": False, "showMeasure": False, "showDebug": False}
    p["options"]["tooltip"] = {"mode": "details"}
    p["fieldConfig"] = {"defaults": {"color": {"mode": "continuous-YlRd"}},
                        "overrides": [ov("Volume", "decbytes", 1)] if size_field else []}


def setsql(p, sql, overrides):
    p["targets"][0]["rawSql"] = sql
    p["targets"][0]["format"] = "table"
    p.setdefault("fieldConfig", {"defaults": {}})["overrides"] = overrides


def edit(path, fn):
    d = json.load(open(path))
    for p in d["panels"]:
        fn(p)
    open(path, "w").write(json.dumps(d, ensure_ascii=False, indent=2) + "\n")


def live(p):
    t = p["title"]
    if t.startswith("Top 20 ASNs"):
        p["title"] = "Top 20 ASNs observados (ASN, nome, blocos, país)"
        setsql(p, asn_table(20), list(RATE_OVERRIDES))
    elif t.startswith("Países e origens"):
        setsql(p, country_table(20, "IPs de origem"), list(RATE_OVERRIDES))
    elif t.startswith("Minutos recentes"):
        p["targets"][0]["rawSql"] = p["targets"][0]["rawSql"].replace("AS 'PPS estimados'", "AS 'Pacotes/s'")
        ovs = [o for o in p["fieldConfig"].get("overrides", []) if o["matcher"]["options"] != "Pacotes/s"]
        p["fieldConfig"]["overrides"] = ovs + [ov("Pacotes/s", "pps", 1)]
    elif p["type"] == "geomap":
        p["targets"][0]["rawSql"] = geo_sql()
        interactive_map(p)


def ipa(p):
    t = p["title"]
    if t.startswith("Ranking de IPs de origem"):
        setsql(p, ip_table("src", "IP origem", 30), list(RATE_OVERRIDES))
    elif t.startswith("Ranking de IPs de destino"):
        setsql(p, ip_table("dst", "IP destino", 30), list(RATE_OVERRIDES))
    elif t.startswith("Top ASNs de origem"):
        setsql(p, asn_table(30), list(RATE_OVERRIDES))
    elif t.startswith("Paises de origem") or t.startswith("Países de origem"):
        p["title"] = "Países de origem (GeoLite2)"
        setsql(p, country_table(30, "IPs distintos"), list(RATE_OVERRIDES))
    elif p["type"] == "geomap":
        p["targets"][0]["rawSql"] = geo_sql()
        interactive_map(p)


def overview(p):
    t = p["title"]
    if t.startswith("Top ASNs de origem"):
        setsql(p, asn_table(25), list(RATE_OVERRIDES))
    elif t.startswith("Países de origem"):
        p["targets"][0]["rawSql"] = ("SELECT " + PAIS + " AS 'País',t.vol AS 'Volume' FROM (SELECT src_country AS pais,"
                                     "SUM(total_bytes) AS vol " + BASE + " AND src_country<>'' GROUP BY src_country "
                                     "ORDER BY SUM(total_bytes) DESC LIMIT 15) AS t " + CN + " ORDER BY t.vol DESC")
        p["fieldConfig"]["overrides"] = [ov("Volume", "decbytes", 1)]
        p["fieldConfig"]["defaults"]["unit"] = "decbytes"
    elif t.startswith("Últimos incidentes"):
        setsql(p, "SELECT a.event_time AS 'Data UTC',a.rule_name AS 'Regra',a.severity AS 'Severidade',"
                  "a.src_asn AS 'ASN',a.src_asn_name AS 'Nome',a.src_ip AS 'IP origem',a.dst_ip AS 'IP destino',"
                  "COALESCE(cn.name,NULLIF(a.src_country,''),'Não informado') AS 'País',a.pps AS 'Pacotes/s',"
                  "a.mbps*1000000 AS 'Taxa',a.unique_sources AS 'Fontes' FROM orby_alerts AS a "
                  "LEFT JOIN orby_country_names AS cn ON cn.code=a.src_country "
                  "WHERE $__timeFilter(a.event_time) ORDER BY a.event_time DESC LIMIT 500",
               [ov("Pacotes/s", "pps", 0), ov("Taxa", "bps", 2)])
    elif t.startswith("Mapa de origens"):
        p["targets"][0]["rawSql"] = geo_sql()
        interactive_map(p)
    elif t.startswith("Mapa de alertas"):
        p["targets"][0]["rawSql"] = (
            "SELECT a.src_latitude AS latitude,a.src_longitude AS longitude,"
            "COALESCE(cn.name,NULLIF(a.src_country,''),'Não informado') AS 'País',a.src_asn AS 'ASN',"
            "a.src_asn_name AS 'Nome',a.src_ip AS 'IP origem',a.dst_ip AS 'IP destino',a.rule_name AS 'Regra',"
            "a.pps AS 'Pacotes/s',a.event_time AS 'Data UTC' FROM orby_alerts AS a "
            "LEFT JOIN orby_country_names AS cn ON cn.code=a.src_country WHERE $__timeFilter(a.event_time) "
            "AND a.src_ip IS NOT NULL AND a.src_latitude IS NOT NULL AND a.src_longitude IS NOT NULL "
            "ORDER BY a.event_time DESC LIMIT 3000")
        interactive_map(p, size_field=None, color="#E02F44")
        p["fieldConfig"]["overrides"] = [ov("Pacotes/s", "pps", 0)]


edit("grafana/dashboards/orbyflow-huawei-live.json", live)
edit("grafana/dashboards/orbyflow-ip-analytics.json", ipa)
edit("grafana/dashboards/orbyflow-overview.json", overview)
print("ok")
