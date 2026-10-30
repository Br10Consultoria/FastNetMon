"""Regression checks for observed traffic map and near-live Huawei timeseries."""
import json
from pathlib import Path
import subprocess
import unittest
ROOT=Path(__file__).resolve().parent.parent

def dash(name):
    return json.loads((ROOT/"grafana/dashboards"/name).read_text())

class LiveDashboardTests(unittest.TestCase):
    def test_huawei_live_sources_new_enriched_rollup_only(self):
        j=dash("orbymon-huawei-live.json")
        self.assertEqual(j["uid"],"orbymon-huawei-live")
        self.assertEqual(j["refresh"],"30s")
        for p in j["panels"]:
            s=p["targets"][0]["rawSql"]
            self.assertNotIn("orby_traffic_minute",s)
            if "orby_ip_pairs_minute" in s:
                self.assertIn("source='huawei'",s)
        self.assertTrue(any(p["type"]=="geomap" for p in j["panels"]))
        self.assertTrue(any("PPS" in p["title"] and p["type"]=="timeseries" for p in j["panels"]))
        self.assertTrue(any("Mbps" in p["title"] and p["type"]=="timeseries" for p in j["panels"]))
    def test_overview_keeps_alert_map_separate_from_normal_traffic(self):
        j=dash("orbymon-overview.json")
        alerts=[p for p in j["panels"] if p["id"]==7][0]
        traffic=[p for p in j["panels"] if p["id"]==21][0]
        self.assertEqual(alerts["type"],"geomap")
        self.assertEqual(traffic["type"],"geomap")
        self.assertIn("orby_alerts",alerts["targets"][0]["rawSql"])
        self.assertIn("orby_ip_pairs_minute",traffic["targets"][0]["rawSql"])
        self.assertNotIn("orby_alerts",traffic["targets"][0]["rawSql"])
        self.assertNotEqual(alerts["gridPos"],traffic["gridPos"])
    def test_map_has_coordinates_and_bounds(self):
        for name,pid in [("orbymon-huawei-live.json",11),("orbymon-overview.json",21)]:
            p=next(x for x in dash(name)["panels"] if x["id"]==pid)
            q=p["targets"][0]["rawSql"]
            self.assertIn("src_latitude AS latitude",q)
            self.assertIn("src_longitude AS longitude",q)
            self.assertIn("LIMIT 300",q)
            self.assertEqual(p["options"]["layers"][0]["location"]["mode"],"coords")
    def test_panel_uids_stable_and_unique(self):
        for name,uid in (("orbymon-huawei-live.json","orbymon-huawei-live"),
                         ("orbymon-overview.json","orbymon-ddos-overview"),
                         ("orbymon-ip-analytics.json","orbymon-ip-analytics")):
            j=dash(name)
            self.assertEqual(j["uid"],uid)
            ids=[p["id"] for p in j["panels"]]
            self.assertEqual(len(ids),len(set(ids)))
    def test_deployer_no_service_restart(self):
        sh=(ROOT/"scripts/deploy-live-dashboards.sh").read_text()
        self.assertIn('cp -a "$DEST"',sh)
        self.assertNotIn("systemctl restart",sh)
        p=subprocess.run(["bash","-n",str(ROOT/"scripts/deploy-live-dashboards.sh")],capture_output=True,text=True)
        self.assertEqual(p.returncode,0,p.stderr)

if __name__=="__main__":
    unittest.main()
