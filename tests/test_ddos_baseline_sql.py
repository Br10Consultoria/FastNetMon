"""Regression guard for the DDoS baseline: read-only and privacy-conserving."""
import re
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DdosBaselineSqlTests(unittest.TestCase):
    def test_queries_are_read_only_and_match_rollup_fields(self):
        sql = (ROOT/"sql/ddos_baseline_readonly.sql").read_text(encoding="utf-8")
        no_comments = "\n".join(
            line.split("--",1)[0] for line in sql.splitlines()
        ).strip()
        statements = [p.strip() for p in no_comments.split(";") if p.strip()]
        self.assertEqual(len(statements), 3)
        self.assertTrue(all(p.upper().startswith("SELECT ") for p in statements))
        self.assertNotRegex(no_comments.upper(),
            r"\b(?:DELETE|UPDATE|INSERT|REPLACE|DROP|ALTER|TRUNCATE|CALL|LOAD|INTO OUTFILE)\b")
        self.assertEqual(sql.count("FROM orby_ip_pairs_minute"), 3)
        self.assertEqual(sql.count("source='huawei'"), 3)
        self.assertEqual(sql.count("INTERVAL 5 MINUTE"), 3)
        self.assertEqual(sql.count("INTERVAL 65 MINUTE"), 3)

    def test_baseline_groups_by_destination_internally_but_does_not_show_ips(self):
        sql = (ROOT/"sql/ddos_baseline_readonly.sql").read_text(encoding="utf-8")
        self.assertEqual(sql.count("GROUP BY bucket_utc,dst_ip"), 2)
        # No raw subscriber/customer IP in outer SELECT: nested IP only for grouping.
        for part in sql.split(";")[1:]:
            if not part.strip():
                continue
            select = part.split("FROM (", 1)[0]
            self.assertNotRegex(select, r"\bdst_ip\b|\bsrc_ip\b")
        self.assertIn("COUNT(DISTINCT src_ip)", sql)
        self.assertIn("dst_port IN (53,123)", sql)
        self.assertIn("netflow_direction", sql)


if __name__ == "__main__":
    unittest.main()
