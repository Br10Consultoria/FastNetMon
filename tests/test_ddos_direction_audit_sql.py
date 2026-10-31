"""DDoS direction diagnostic only aggregates; no per-customer IP output or DB writes."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]


class DirectionAuditSqlTests(unittest.TestCase):
    def test_only_three_select_statements(self):
        text=(ROOT/"sql/ddos_direction_audit_readonly.sql").read_text(encoding="utf-8")
        uncommented="\n".join(s.split("--",1)[0] for s in text.splitlines())
        queries=[q.strip() for q in uncommented.split(";") if q.strip()]
        self.assertEqual(len(queries),3)
        self.assertTrue(all(q.startswith("SELECT\n") for q in queries))
        self.assertEqual(uncommented.count("FROM orby_ip_pairs_minute"),3)
        self.assertNotIn("UPDATE ",uncommented.upper())
        self.assertNotIn("DELETE ",uncommented.upper())
        self.assertNotIn("INSERT ",uncommented.upper())
        self.assertNotIn("ALTER ",uncommented.upper())
        self.assertNotIn("DROP ",uncommented.upper())
        self.assertEqual(text.count("AND bucket_utc<UTC_TIMESTAMP()-INTERVAL 5 MINUTE"),3)
        self.assertEqual(text.count("AND bucket_utc>=UTC_TIMESTAMP()-INTERVAL 65 MINUTE"),3)

    def test_public_scopes_and_separation_of_direction(self):
        text=(ROOT/"sql/ddos_direction_audit_readonly.sql").read_text(encoding="utf-8")
        self.assertEqual(text.count("src_ip LIKE '45.238.170.%'"),2)
        self.assertEqual(text.count("dst_ip LIKE '45.238.170.%'"),2)
        self.assertEqual(text.count("src_ip LIKE '45.238.171.%'"),2)
        self.assertEqual(text.count("dst_ip LIKE '45.238.171.%'"),2)
        self.assertEqual(text.count("src_ip LIKE '187.87.201.%'"),2)
        self.assertEqual(text.count("dst_ip LIKE '187.87.201.%'"),2)
        self.assertIn("netflow_direction AS direcao_raw",text)
        self.assertIn("GROUP BY protocol,input_if,output_if,netflow_direction",text)
        self.assertIn("WHERE protected_src=1 OR protected_dst=1",text)
        self.assertIn("'nenhuma_ponta_protegida'",text)

    def test_ip_fields_only_used_in_inner_selects(self):
        text=(ROOT/"sql/ddos_direction_audit_readonly.sql").read_text(encoding="utf-8")
        uncommented="\n".join(s.split("--",1)[0] for s in text.splitlines())
        queries=[q.strip() for q in uncommented.split(";") if q.strip()]
        for i,query in enumerate(queries):
            outer_select=query.split("FROM (",1)[0] if i<2 else query.split("FROM orby_ip_pairs_minute",1)[0]
            self.assertNotIn("src_ip",outer_select)
            self.assertNotIn("dst_ip",outer_select)
            self.assertNotIn("src_asn_name",query)


if __name__=="__main__":
    unittest.main()
