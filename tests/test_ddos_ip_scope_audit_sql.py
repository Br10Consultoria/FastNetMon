"""Guarantee Huawei scope audit stays passive and avoids disclosing host IPs."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DdosIpScopeAuditTests(unittest.TestCase):
    def test_scope_audit_contains_only_two_selects(self):
        sql = (ROOT / "sql/ddos_ip_scope_audit_readonly.sql").read_text()
        text = "\n".join(line.split("--",1)[0] for line in sql.splitlines())
        statements = [s.strip() for s in text.split(";") if s.strip()]
        self.assertEqual(len(statements), 2)
        self.assertTrue(all(s.startswith("SELECT\n") for s in statements))
        self.assertEqual(text.count("FROM orby_ip_pairs_minute"), 3)
        self.assertEqual(text.count("source='huawei'"), 3)
        self.assertEqual(text.count("INTERVAL 65 MINUTE"), 3)
        self.assertEqual(text.count("INTERVAL 5 MINUTE"), 3)
        for forbidden in ("UPDATE ", "DELETE ", "INSERT ", "TRUNCATE ",
                          "DROP ", "ALTER ", "REPLACE ", "INTO OUTFILE"):
            self.assertNotIn(forbidden, text.upper())

    def test_scope_audit_only_exposes_ip_16_and_categories(self):
        sql = (ROOT / "sql/ddos_ip_scope_audit_readonly.sql").read_text()
        text = "\n".join(line.split("--",1)[0] for line in sql.splitlines())
        statements = [s.strip() for s in text.split(";") if s.strip()]
        for query in statements:
            outer = query.split("FROM (",1)[0]
            self.assertNotIn("src_ip",outer)
            self.assertNotIn("dst_ip",outer)
        self.assertIn("SUBSTRING_INDEX(src_ip,'.',2)", sql)
        self.assertIn("SUBSTRING_INDEX(dst_ip,'.',2)", sql)
        self.assertIn("CGNAT_100.64/10",sql)
        self.assertIn("PRIVADO_RFC1918",sql)
        self.assertIn("IPv6",sql)
        self.assertIn("netflow_direction AS direcao_raw",sql)
        self.assertNotIn("ORBY_SYSLOG", sql)


if __name__ == "__main__":
    unittest.main()
