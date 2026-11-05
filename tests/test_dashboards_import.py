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
        self.assertEqual(set(after), {"orbyflow-f4-ataques.json", "orbyflow-cgnat.json", "orbyflow-ip-analytics.json",
                                      "orbyflow-huawei-live.json", "orbyflow-reputacao.json", "orbyflow-overview.json",
                                      "orbyflow-cgnat-portas.json",       # gerado por grafana/build_cgnat_ports.py
                                      "orbyflow-cgnat-assinantes.json",  # gerado por grafana/build_cgnat_subscribers.py
                                      "orbyflow-ataques-originados.json",  # separado da reputacao pelo import_v2
                                      "orbyflow-alarmes.json",   # gerado por grafana/build_alarms.py
                                      "orbyflow-c2-botnets.json",  # gerado por grafana/build_c2.py
                                      "orbyflow-grupos-asn.json",  # gerado por grafana/build_asn_groups.py
                                      "orbyflow-analise-ataques.json"})  # grafana/build_attack_analysis.py

    def test_no_provider_specific_blocks(self):
        for path in DASH.glob("*.json"):
            text = path.read_text()
            self.assertIsNone(re.search(r"'(45\.238|187\.87|100\.64\.64)\.", text), path.name)
            self.assertNotIn("hideSeriesFrom", text, path.name)
        cgnat = (DASH / "orbyflow-cgnat.json").read_text()
        self.assertIn("orby_net_prefixes", cgnat)

    def test_classic_format_and_uids(self):
        uids = set()
        for path in DASH.glob("*.json"):
            d = json.loads(path.read_text())
            self.assertIn("panels", d)
            self.assertTrue(d["uid"].startswith("orbyflow-"))
            self.assertNotIn("orbymon", json.dumps(d["tags"]) + d["title"].lower())
            uids.add(d["uid"])
            for p in d["panels"]:
                for t in p.get("targets", []):
                    self.assertEqual(t["datasource"], {"type": "mysql", "uid": "orbyflow-mysql"})
        self.assertEqual(len(uids), 13)

    def test_cgnat_ports_dashboard_is_generated(self):
        sys.path.insert(0, str(ROOT / "grafana"))
        import build_cgnat_ports as b
        self.assertEqual(json.loads((DASH / "orbyflow-cgnat-portas.json").read_text()), b.build(),
                         "rode python3 grafana/build_cgnat_ports.py")
        import build_alarms as a
        self.assertEqual(json.loads((DASH / "orbyflow-alarmes.json").read_text()), a.build(),
                         "rode python3 grafana/build_alarms.py")
        import build_c2 as c2
        self.assertEqual(json.loads((DASH / "orbyflow-c2-botnets.json").read_text()), c2.build(),
                         "rode python3 grafana/build_c2.py")
        import build_attack_analysis as aa
        self.assertEqual(json.loads((DASH / "orbyflow-analise-ataques.json").read_text()), aa.build(),
                         "rode python3 grafana/build_attack_analysis.py")
        import build_asn_groups as ag
        self.assertEqual(json.loads((DASH / "orbyflow-grupos-asn.json").read_text()), ag.build(False),
                         "rode python3 grafana/build_asn_groups.py")
        self.assertEqual(json.loads((ROOT / "grafana" / "dashboards-clickhouse" / "orbyflow-grupos-asn.json")
                                    .read_text()), ag.build(True), "rode python3 grafana/build_asn_groups.py")
        deploy = (ROOT / "scripts" / "deploy-live-dashboards.sh").read_text()
        for name in [p.name for p in DASH.glob("*.json")]:
            self.assertIn(name, deploy)
        import build_cgnat_subscribers as s
        self.assertEqual(json.loads((DASH / "orbyflow-cgnat-assinantes.json").read_text()), s.build(),
                         "rode python3 grafana/build_cgnat_subscribers.py")

    def test_protocol_filter_has_all_protocols(self):
        d = json.loads((DASH / "orbyflow-f4-ataques.json").read_text())
        proto = [v for v in d["templating"]["list"] if v["name"] == "proto"][0]
        self.assertGreater(len(proto["options"]), 140)
        self.assertIn("gre", {o["value"] for o in proto["options"]})


if __name__ == "__main__":
    unittest.main()
