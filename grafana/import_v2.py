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
    return {"type": q.get("group", "mysql"), "uid": (q.get("datasource") or {}).get("name", "orbymon-mysql")}


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


def main():
    out = []
    for path in sorted((ROOT / "grafana" / "exports").glob("*.v2.json")):
        dash = make_generic(convert(json.loads(path.read_text(encoding="utf-8"))))
        text = json.dumps(dash, ensure_ascii=False, indent=2) + "\n"
        if HARDCODED.search(text):
            raise SystemExit("%s: ainda ha blocos do provedor fixos no SQL" % path.name)
        target = ROOT / "grafana" / "dashboards" / path.name.replace(".v2.json", ".json")
        target.write_text(text, encoding="utf-8")
        out.append("%s (%d paineis)" % (target.name, len(dash["panels"])))
    print("\n".join(out))


if __name__ == "__main__":
    main()
