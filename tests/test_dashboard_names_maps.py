import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent.parent


def dash(name):
    return json.loads((ROOT / "grafana/dashboards" / name).read_text())


def columns(sql):
    head = sql.split(" FROM (", 1)[0] if " FROM (" in sql else sql.split(" FROM ", 1)[0]
    return re.findall(r"AS '([^']+)'", head)


class NamesAndMapsTests(unittest.TestCase):
    def test_asn_tables_start_with_asn_name_then_ip(self):
        cases = [("orbyflow-huawei-live.json", "Top 20 ASNs"), ("orbyflow-ip-analytics.json", "Top ASNs de origem"),
                 ("orbyflow-overview.json", "Top ASNs de origem"), ("orbyflow-ip-analytics.json", "Ranking de IPs de origem"),
                 ("orbyflow-ip-analytics.json", "Ranking de IPs de destino")]
        for name, title in cases:
            p = [p for p in dash(name)["panels"] if p["title"].startswith(title)][0]
            cols = columns(p["targets"][0]["rawSql"])
            self.assertEqual(cols[:2], ["ASN", "Nome"], (name, title))
            self.assertTrue(cols[2].startswith(("IP", "Blocos")), (name, title, cols))
            self.assertIn("País", cols)

    def test_country_shown_by_name(self):
        for name in ("orbyflow-huawei-live.json", "orbyflow-ip-analytics.json", "orbyflow-overview.json"):
            for p in dash(name)["panels"]:
                sql = " ".join(t.get("rawSql", "") for t in p.get("targets", []))
                if "'País'" in sql:
                    self.assertIn("orby_country_names", sql, (name, p["title"]))

    def test_packet_rates_use_pps_unit(self):
        for name in ("orbyflow-huawei-live.json", "orbyflow-ip-analytics.json", "orbyflow-overview.json"):
            for p in dash(name)["panels"]:
                sql = " ".join(t.get("rawSql", "") for t in p.get("targets", []))
                for col in ("Pacotes/s médio", "Pacotes/s"):
                    if "AS '%s'" % col in sql:
                        units = {o["matcher"]["options"]: [x["value"] for x in o["properties"] if x["id"] == "unit"]
                                 for o in p["fieldConfig"]["overrides"]}
                        self.assertEqual(units.get(col), ["pps"], (name, p["title"]))

    def test_maps_are_interactive(self):
        for name in ("orbyflow-huawei-live.json", "orbyflow-ip-analytics.json", "orbyflow-overview.json"):
            for p in dash(name)["panels"]:
                if p["type"] != "geomap":
                    continue
                o = p["options"]
                self.assertEqual(o["tooltip"], {"mode": "details"}, p["title"])
                self.assertTrue(o["controls"]["showZoom"] and o["controls"]["mouseWheelZoom"])
                self.assertEqual(o["view"]["id"], "fit")
                self.assertIn("País", p["targets"][0]["rawSql"])

    def test_country_sql_sets_utf8_and_is_deployed(self):
        sql = (ROOT / "sql/country_names.sql").read_text()
        self.assertIn("SET NAMES utf8mb4;", sql)
        self.assertIn("('BR','Brasil')", sql)
        self.assertIn("('NL','Países Baixos')", sql)
        self.assertIn("country_names.sql", (ROOT / "scripts/deploy-live-dashboards.sh").read_text())


if __name__ == "__main__":
    unittest.main()
