import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent.parent
DASH = json.loads((ROOT / "grafana/dashboards/orbyflow-f4-ataques.json").read_text())


class F4DashboardTests(unittest.TestCase):
    def sqls(self):
        return [t["rawSql"] for p in DASH["panels"] for t in p.get("targets", [])]

    def test_filters_exist(self):
        names = {v["name"] for v in DASH["templating"]["list"]}
        self.assertEqual(names, {"ip", "remoto", "porta", "direcao", "proto"})

    def test_variables_are_always_escaped(self):
        for sql in self.sqls():
            for raw in re.findall(r"\$\{?(ip|remoto|porta|direcao|proto)\b(?!:sqlstring)", sql):
                self.fail("variavel sem :sqlstring: " + raw)
            self.assertNotRegex(sql, r"\$(ip|remoto|porta|direcao|proto)\b")

    def test_every_query_is_time_bounded_and_uses_mysql_datasource(self):
        for p in DASH["panels"]:
            for t in p.get("targets", []):
                self.assertEqual(t["datasource"]["uid"], "orbyflow-mysql")
                self.assertIn("$__timeFilter(", t["rawSql"], p["title"])

    def test_rates_and_volumes_have_scaling_units(self):
        text = json.dumps(DASH)
        self.assertIn('"bps"', text)
        self.assertIn('"decbytes"', text)
        self.assertNotIn('"Mbps"', text)

    def test_deploy_script_ships_the_dashboard(self):
        self.assertIn("orbyflow-f4-ataques.json", (ROOT / "scripts/deploy-live-dashboards.sh").read_text())


if __name__ == "__main__":
    unittest.main()
