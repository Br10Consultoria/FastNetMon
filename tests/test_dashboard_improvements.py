"""Regression checks for the human-readable dashboards and safe setup."""
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parent.parent
P=ROOT/"grafana/dashboards"

def dash(name):
    return json.loads((P/name).read_text())

class DashboardImprovementsTests(unittest.TestCase):
    def test_geo_panels_use_enriched_huawei_rollup(self):
        d=dash("orbymon-overview.json")
        sql_by_id={p["id"]:p["targets"][0]["rawSql"] for p in d["panels"]}
        for panel_id in (3,8,9):
            self.assertIn("orby_ip_pairs_minute",sql_by_id[panel_id])
            self.assertIn("source='huawei'",sql_by_id[panel_id])
        self.assertNotIn("1000000000",sql_by_id[8])
        self.assertIn("src_asn_name",sql_by_id[8])
        self.assertIn("src_country",sql_by_id[9])
    def test_tables_show_units_with_numeric_values(self):
        for name in ("orbymon-overview.json","orbymon-ip-analytics.json",
                     "orbymon-cgnat.json"):
            d=dash(name)
            found=False
            for p in d["panels"]:
                for override in p.get("fieldConfig",{}).get("overrides",[]):
                    if override.get("matcher",{}).get("options")=="MB estimados":
                        props=override.get("properties",[])
                        self.assertIn({"id":"unit","value":"suffix: MB"},props)
                        found=True
            self.assertTrue(found,name)
    def test_recency_does_not_depend_on_selected_time_range(self):
        for name in ("orbymon-overview.json","orbymon-ip-analytics.json",
                     "orbymon-cgnat.json"):
            d=dash(name)
            recency=[p for p in d["panels"] if "Atraso da última coleta Huawei" in p["title"]]
            self.assertEqual(len(recency),1,name)
            q=recency[0]["targets"][0]["rawSql"]
            self.assertIn("UTC_TIMESTAMP()",q)
            self.assertNotIn("$__timeFilter",q)
    def test_verified_ifname_is_not_guessed(self):
        for name in ("orbymon-ip-analytics.json","orbymon-cgnat.json"):
            d=dash(name)
            qs=" ".join(p["targets"][0]["rawSql"] for p in d["panels"])
            self.assertIn("orby_interface_names",qs)
            self.assertIn("Não informado",qs)
            self.assertIn("ifIndex ",qs)
    def test_no_duplicate_uids(self):
        self.assertEqual(len({dash(n)["uid"] for n in
           ("orbymon-overview.json","orbymon-ip-analytics.json",
            "orbymon-cgnat.json")}),3)

if __name__=="__main__":
    unittest.main()
