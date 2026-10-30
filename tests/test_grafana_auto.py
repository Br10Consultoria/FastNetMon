import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class GrafanaSetupTests(unittest.TestCase):
    def test_dashboard_ids_and_uid(self):
        files = list((ROOT / "grafana/dashboards").glob("*.json"))
        self.assertGreaterEqual(len(files), 2)
        uids = set()
        for path in files:
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertNotIn(data["uid"], uids)
            uids.add(data["uid"])
        live = json.loads((ROOT / "grafana/dashboards/orbymon-huawei-live.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(live["panels"]), 8)
        for panel in live["panels"]:
            self.assertEqual(panel["datasource"]["uid"], "orbymon-mysql")
            for target in panel["targets"]:
                self.assertEqual(target["datasource"]["uid"], "orbymon-mysql")
                self.assertNotIn("*2048", target["rawSql"])

    def test_secure_setup(self):
        setup = (ROOT / "scripts/setup-grafana.sh").read_text(encoding="utf-8")
        self.assertIn("GRANT SELECT ON orbymon.*", setup)
        self.assertNotIn("GRANT ALL", setup)
        self.assertIn("GF_SERVER_PROTOCOL=https", setup)
        self.assertIn("GF_SERVER_HTTP_ADDR=0.0.0.0", setup)
        self.assertIn("secureJsonData:", setup)
        self.assertIn("grafana/dashboards/*.json", setup)
        self.assertNotIn("systemctl restart orbymon-nfcapd", setup)

if __name__ == "__main__":
    unittest.main()
