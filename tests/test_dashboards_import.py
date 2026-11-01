"""Dashboards oficiais: gerados do export validado (grafana/exports) e independentes do provedor."""
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
DASH = ROOT / "grafana" / "dashboards"


class DashboardImportTests(unittest.TestCase):
    def test_dashboards_match_exports(self):
        before = {p.name: p.read_text() for p in DASH.glob("*.json")}
        subprocess.run([sys.executable, str(ROOT / "grafana" / "import_v2.py")], check=True, capture_output=True)
        after = {p.name: p.read_text() for p in DASH.glob("*.json")}
        self.assertEqual(before, after, "rode python3 grafana/import_v2.py e faça commit do resultado")
        self.assertEqual(set(after), {"orbymon-f4-ataques.json", "orbymon-cgnat.json", "orbymon-ip-analytics.json",
                                      "orbymon-huawei-live.json", "orbymon-reputacao.json", "orbymon-overview.json"})

    def test_no_provider_specific_blocks(self):
        for path in DASH.glob("*.json"):
            text = path.read_text()
            self.assertIsNone(re.search(r"'(45\.238|187\.87|100\.64\.64)\.", text), path.name)
            self.assertNotIn("hideSeriesFrom", text, path.name)
        cgnat = (DASH / "orbymon-cgnat.json").read_text()
        self.assertIn("orby_net_prefixes", cgnat)

    def test_classic_format_and_uids(self):
        uids = set()
        for path in DASH.glob("*.json"):
            d = json.loads(path.read_text())
            self.assertIn("panels", d)
            self.assertTrue(d["uid"].startswith("orbymon-"))
            uids.add(d["uid"])
            for p in d["panels"]:
                for t in p.get("targets", []):
                    self.assertEqual(t["datasource"], {"type": "mysql", "uid": "orbymon-mysql"})
        self.assertEqual(len(uids), 6)

    def test_protocol_filter_has_all_protocols(self):
        d = json.loads((DASH / "orbymon-f4-ataques.json").read_text())
        proto = [v for v in d["templating"]["list"] if v["name"] == "proto"][0]
        self.assertGreater(len(proto["options"]), 140)
        self.assertIn("gre", {o["value"] for o in proto["options"]})


if __name__ == "__main__":
    unittest.main()
