"""Converte dashboards exportados do Grafana (formato v2, "Export" > JSON) para o formato classico
usado no provisionamento por arquivo (grafana/dashboards/*.json).

Fluxo para atualizar o padrao dos dashboards:
  1. ajuste o dashboard no Grafana e exporte (Compartilhar > Exportar > JSON, formato v2);
  2. salve em grafana/exports/<arquivo>.v2.json (o nome define o arquivo de saida);
  3. python3 grafana/import_v2.py   (gera grafana/dashboards/<arquivo>.json)
  4. sudo bash scripts/deploy-live-dashboards.sh

Ajustes aplicados na conversao (para servir a qualquer provedor):
  - blocos/pools/rede privada fixos no SQL viram consulta a orby_net_prefixes (preenchida da configuracao);
  - filtro Protocolo com todos os protocolos IANA;
  - series escondidas pela legenda no navegador (hideSeriesFrom) nao sao gravadas.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from fmn_filters.protocols import NUMBER_TO_NAME  # noqa: E402

COMMON = ["tcp", "udp", "icmp", "icmpv6", "gre", "esp", "ah", "ipv6", "ipip", "sctp", "ospf", "pim", "vrrp",
          "igmp", "l2tp"]
HIDE = {"dontHide": 0, "hideLabel": 1, "hideVariable": 2}
CURSOR = {"Off": 0, "Crosshair": 1, "Tooltip": 2}


def ds(q):
    return {"type": q.get("group", "mysql"), "uid": (q.get("datasource") or {}).get("name", "orbyflow-mysql")}


def proto_options():
    opts = [("Todos", "all")] + [(n, n) for n in COMMON] + \
        [("%s (%d)" % (n, k), n) for k, n in sorted(NUMBER_TO_NAME.items()) if n not in COMMON]
    return opts


def variable(v):
    kind, spec = v["kind"], v["spec"]
    base = {"name": spec["name"], "label": spec.get("label", ""), "hide": HIDE.get(spec.get("hide"), 0),
            "skipUrlSync": spec.get("skipUrlSync", False), "current": spec.get("current", {})}
    if kind == "TextVariable":
        base.update(type="textbox", query=spec.get("query", ""))
    elif kind == "CustomVariable":
        base.update(type="custom", query=spec.get("query", ""), options=spec.get("options", []),
                    multi=spec.get("multi", False), includeAll=spec.get("includeAll", False),
                    allowCustomValue=spec.get("allowCustomValue", True))
        if spec["name"] == "proto":
            opts = proto_options()
            base.update(query=",".join("%s : %s" % (t, val) for t, val in opts),
                        options=[{"text": t, "value": val, "selected": val == "all"} for t, val in opts],
                        current={"text": "Todos", "value": "all"},
                        description="Todos os protocolos IP (IANA). Digite para buscar: gre, ah, ospf, sctp...")
    elif kind == "QueryVariable":
        q = spec.get("query", {})
        base.update(type="query", datasource=ds(q), query=(q.get("spec") or {}).get("rawSql", ""),
                    definition=(q.get("spec") or {}).get("rawSql", ""), refresh=1,
                    multi=spec.get("multi", False), includeAll=spec.get("includeAll", False))
    else:
        raise ValueError("variavel nao suportada: %s" % kind)
    return base


def panel(name, el, grid):
    spec = el["spec"]
    viz = spec["vizConfig"]
    p = {"id": spec["id"], "type": viz["group"], "title": spec.get("title", ""),
         "description": spec.get("description", ""), "gridPos": grid, "links": spec.get("links", []),
         "options": viz["spec"].get("options", {}), "fieldConfig": viz["spec"].get("fieldConfig", {}),
         "transparent": spec.get("transparent", False)}
    data = spec["data"]["spec"]
    queries = data.get("queries", [])
    if queries:
        targets = []
        for item in queries:
            q = item["spec"]["query"]
            t = {"refId": item["spec"].get("refId", "A"), "datasource": ds(q)}
            t.update(q.get("spec", {}))
            if item["spec"].get("hidden"):
                t["hide"] = True
            targets.append(t)
        p["targets"] = targets
        p["datasource"] = targets[0]["datasource"]
    if data.get("transformations"):
        p["transformations"] = data["transformations"]
    fc = p["fieldConfig"]
    if fc.get("overrides"):   # esconder serie pela legenda e preferencia de navegador, nao padrao
        fc["overrides"] = [o for o in fc["overrides"] if o.get("__systemRef") != "hideSeriesFrom"]
    return p


def convert(doc):
    if doc.get("apiVersion", "").startswith("dashboard.grafana.app/v2") is False:
        raise ValueError("esperado export v2 (apiVersion dashboard.grafana.app/v2...)")
    spec = doc["spec"]
    layout = spec["layout"]
    if layout["kind"] != "GridLayout":
        raise ValueError("layout %s nao suportado (use grade simples)" % layout["kind"])
    grids = {i["spec"]["element"]["name"]: {"x": i["spec"]["x"], "y": i["spec"]["y"], "w": i["spec"]["width"],
                                            "h": i["spec"]["height"]} for i in layout["spec"]["items"]}
    panels = [panel(n, spec["elements"][n], grids[n]) for n in grids]
    panels.sort(key=lambda p: (p["gridPos"]["y"], p["gridPos"]["x"]))
    ts = spec.get("timeSettings", {})
    return {
        "id": None, "uid": doc["metadata"]["name"], "title": spec["title"], "description": spec.get("description", ""),
        "tags": spec.get("tags", []), "editable": spec.get("editable", True), "schemaVersion": 41, "version": 1,
        "graphTooltip": CURSOR.get(spec.get("cursorSync"), 0), "links": spec.get("links", []),
        "liveNow": spec.get("liveNow", False), "timezone": ts.get("timezone", "browser"),
        "time": {"from": ts.get("from", "now-1h"), "to": ts.get("to", "now")},
        "refresh": ts.get("autoRefresh", ""), "fiscalYearStartMonth": ts.get("fiscalYearStartMonth", 0),
        "timepicker": {"refresh_intervals": ts.get("autoRefreshIntervals", [])},
        "annotations": {"list": [{"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"},
                                  "enable": True, "hide": True, "iconColor": "rgba(0, 211, 255, 1)",
                                  "name": "Annotations & Alerts", "type": "dashboard"}]},
        "templating": {"list": [variable(v) for v in spec.get("variables", [])]},
        "panels": panels,
    }


# ------------------------------------------------------------------ SQL independente do provedor
def _in(col, kind):
    return ("EXISTS (SELECT 1 FROM orby_net_prefixes np WHERE np.kind='%s' AND INET_ATON(%s) "
            "BETWEEN np.v_start AND np.v_end)" % (kind, col))


def generic_sql(sql):
    """Troca blocos e pools fixos pelo cadastro do provedor (orby_net_prefixes)."""
    # (src_ip LIKE 'a.b.c.%' OR src_ip LIKE ...) -> blocos publicos do provedor
    sql = re.sub(r"\((\w+(?:\.\w+)?) LIKE '[\d.]+%'(?: OR \1 LIKE '[\d.]+%')*\)",
                 lambda m: _in(m.group(1), "protected"), sql)
    # CASE WHEN INET_ATON(x) BETWEEN ... THEN 'NAT-POOL-..' ... ELSE NULL END -> nome do pool
    sql = re.sub(r"CASE WHEN INET_ATON\((\w+)\) BETWEEN INET_ATON\('[\d.]+'\) AND INET_ATON\('[\d.]+'\) THEN '[^']*'"
                 r"(?: WHEN INET_ATON\(\1\) BETWEEN INET_ATON\('[\d.]+'\) AND INET_ATON\('[\d.]+'\) THEN '[^']*')*"
                 r" ELSE NULL END",
                 lambda m: "(SELECT np.name FROM orby_net_prefixes np WHERE np.kind='pool' AND INET_ATON(%s) "
                           "BETWEEN np.v_start AND np.v_end LIMIT 1)" % m.group(1), sql)
    # INET_ATON(x) BETWEEN INET_ATON('100.64...') AND ... -> rede privada dos assinantes
    sql = re.sub(r"INET_ATON\((\w+)\) BETWEEN INET_ATON\('100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.[\d.]+'\) "
                 r"AND INET_ATON\('[\d.]+'\)", lambda m: _in(m.group(1), "private"), sql)
    return sql


GENERIC_TEXT = [
    (re.compile(r"CGNAT A10: pools publicos [^.]*\. "), "CGNAT: pools públicos e rede privada cadastrados na página Rede do painel. "),
    (re.compile(r"Rede interna 100\.64\.64\.0/19"), "Rede privada dos assinantes"),
]


def make_generic(dash):
    for p in dash["panels"]:
        for t in p.get("targets", []):
            if "rawSql" in t:
                t["rawSql"] = generic_sql(t["rawSql"])
        for rx, rep in GENERIC_TEXT:
            p["title"] = rx.sub(rep, p["title"])
    for rx, rep in GENERIC_TEXT:
        dash["description"] = rx.sub(rep, dash["description"])
    return dash


HARDCODED = re.compile(r"'(?:45\.238|187\.87|100\.64\.64)\.")


# ------------------------------------------------------------------ reputacao separada dos ataques originados
REP_KEEP = {2, 3, 6, 12, 11}            # listas de bloqueio, fontes e historico
ORIG_KEEP = {4, 5, 7, 8, 9, 10}         # ataques originados por clientes
DS_MYSQL = {"type": "mysql", "uid": "orbyflow-mysql"}


def _repack(panels):
    """Mantem a ordem e as larguras; refaz as alturas das linhas sem os paineis removidos."""
    rows = {}
    for p in panels:
        rows.setdefault(p["gridPos"]["y"], []).append(p)
    y = 0
    for _, row in sorted(rows.items()):
        for p in row:
            p["gridPos"]["y"] = y
        y += max(p["gridPos"]["h"] for p in row)
    return y


def _panel(pid, kind, title, sql, grid, desc="", fmt="table", unit=None):
    p = {"id": pid, "type": kind, "title": title, "description": desc, "gridPos": grid, "links": [],
         "datasource": dict(DS_MYSQL), "transparent": False,
         "targets": [{"refId": "A", "datasource": dict(DS_MYSQL), "editorMode": "code", "format": fmt,
                      "rawQuery": True, "rawSql": sql}],
         "options": {}, "fieldConfig": {"defaults": {}, "overrides": []}}
    if kind == "timeseries":
        p["options"] = {"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
                        "tooltip": {"mode": "multi", "sort": "desc"}}
        p["fieldConfig"]["defaults"] = {"custom": {"drawStyle": "bars", "fillOpacity": 60, "lineWidth": 1}}
    if kind == "table":
        p["options"] = {"showHeader": True, "cellHeight": "sm"}
        p["fieldConfig"]["defaults"] = {"custom": {"filterable": True}}
    if unit:
        p["fieldConfig"]["defaults"]["unit"] = unit
    return p


def split_reputation(dash):
    """Dashboard de reputacao/blacklists e outro de ataques originados (antes misturados)."""
    import copy
    rep, orig = copy.deepcopy(dash), copy.deepcopy(dash)
    rep["panels"] = [p for p in rep["panels"] if p["id"] in REP_KEEP]
    orig["panels"] = [p for p in orig["panels"] if p["id"] in ORIG_KEEP]
    bottom = _repack(rep["panels"])
    rep["panels"] += [
        _panel(13, "table", "Listagens ativas por lista",
               "SELECT source_label AS 'Lista',COUNT(DISTINCT entry) AS 'IPs/blocos listados',"
               "SUM(scope='cgnat_pool') AS 'De pool CGNAT',MIN(first_seen) AS 'Listado desde (mais antigo)',"
               "MAX(last_seen) AS 'Última confirmação' FROM orby_reputation_listings WHERE removed_at IS NULL "
               "GROUP BY source_label ORDER BY 2 DESC",
               {"x": 0, "y": bottom, "w": 12, "h": 8},
               "Em quais listas os IPs do provedor estão agora. Listas de spam (Spamhaus, SpamCop, Barracuda) "
               "afetam e-mail; listas de ataque/botnet (FireHOL, IPsum, AbuseIPDB) podem bloquear navegação."),
        _panel(14, "timeseries", "Entradas e saídas das listas por dia",
               "SELECT $__timeGroupAlias(first_seen,'1d'),'entrou' AS metric,COUNT(*) AS value FROM "
               "orby_reputation_listings WHERE $__timeFilter(first_seen) GROUP BY 1 UNION ALL SELECT "
               "$__timeGroupAlias(removed_at,'1d'),'saiu',COUNT(*) FROM orby_reputation_listings WHERE removed_at "
               "IS NOT NULL AND $__timeFilter(removed_at) GROUP BY 1 ORDER BY 1",
               {"x": 12, "y": bottom, "w": 12, "h": 8},
               "Listagens novas e removidas por dia. Muitas entradas seguidas indicam um cliente infectado ativo: "
               "veja o dashboard de ataques originados.", fmt="time_series"),
    ]
    rep.update(uid="orbyflow-reputacao", title="Reputação e blacklists",
               description="IPs e blocos do provedor em listas de bloqueio (blacklists, DNSBL, AbuseIPDB), assinante "
                           "provável no CGNAT, situação de cada fonte e histórico. Quem origina ataques: dashboard "
                           "Ataques originados (clientes).",
               tags=["orbyflow", "reputacao", "blacklist"])
    _repack(orig["panels"])
    orig.update(uid="orbyflow-ataques-originados", title="Ataques originados (clientes)",
                description="Ataques e varreduras saindo de clientes do provedor (causa comum de entrar em blacklist): "
                            "quem origina, por tipo, por hora e saída suspeita para muitos destinos na mesma porta.",
                tags=["orbyflow", "abuso", "originados"])
    return {"orbyflow-reputacao.json": rep, "orbyflow-ataques-originados.json": orig}


def main():
    out = []
    for path in sorted((ROOT / "grafana" / "exports").glob("*.v2.json")):
        dash = make_generic(convert(json.loads(path.read_text(encoding="utf-8"))))
        name = path.name.replace(".v2.json", ".json")
        outputs = split_reputation(dash) if name == "orbyflow-reputacao.json" else {name: dash}
        for fname, d in outputs.items():
            text = json.dumps(d, ensure_ascii=False, indent=2) + "\n"
            if HARDCODED.search(text):
                raise SystemExit("%s: ainda ha blocos do provedor fixos no SQL" % path.name)
            target = ROOT / "grafana" / "dashboards" / fname
            target.write_text(text, encoding="utf-8")
            out.append("%s (%d paineis)" % (target.name, len(d["panels"])))
    print("\n".join(out))


if __name__ == "__main__":
    main()
