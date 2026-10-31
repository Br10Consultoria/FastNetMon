"""Protect the read-only /24 topology diagnostic against unexpected writes."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DdosPublicScopeDetailSqlTests(unittest.TestCase):
    def test_only_select_and_no_host_ip_display(self):
        sql = (ROOT / "sql/ddos_public_scope_detail_readonly.sql").read_text()
        clean = "\n".join(line.split("--", 1)[0] for line in sql.splitlines()).strip()
        queries = [part.strip() for part in clean.split(";") if part.strip()]
        self.assertEqual(len(queries), 1)
        self.assertTrue(queries[0].startswith("SELECT\n"))
        self.assertEqual(clean.count("FROM orby_ip_pairs_minute"), 2)
        self.assertEqual(clean.count("source='huawei'"), 2)
        self.assertEqual(clean.count("INTERVAL 65 MINUTE"), 2)
        self.assertEqual(clean.count("INTERVAL 5 MINUTE"), 2)
        self.assertIn("SUBSTRING_INDEX(src_ip,'.',3)", clean)
        self.assertIn("SUBSTRING_INDEX(dst_ip,'.',3)", clean)
        outer = clean.split("FROM (", 1)[0]
        self.assertNotIn("src_ip", outer)
        self.assertNotIn("dst_ip", outer)
        self.assertIn("GROUP BY lado,prefixo_24,input_if,output_if,netflow_direction", clean)
        self.assertIn("LIMIT 35", clean)
        for term in ("INSERT ", "DELETE ", "UPDATE ", "ALTER ",
                     "DROP ", "TRUNCATE ", "REPLACE ", "INTO OUTFILE"):
            self.assertNotIn(term, clean.upper())


if __name__ == "__main__":
    unittest.main()
