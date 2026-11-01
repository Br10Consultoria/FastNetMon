"""Relatorio por cliente/IP: alvos, consultas reais no MariaDB e texto para resposta de abuso."""
from datetime import datetime, timedelta
import json
import os
import unittest

from fmn_filters import customer_report as cr

DB_ENABLED = os.environ.get("ORBYMON_TEST_DB") == "1" and os.environ.get("ORBYMON_DB_USER")
T = datetime(2026, 10, 30, 12, 0)


class TargetTests(unittest.TestCase):
    def test_parse(self):
        nets = cr.parse_targets("187.87.201.40, 45.238.170.64/29 2804:4fa8:1::/48")
        self.assertEqual([str(n) for n in nets], ["187.87.201.40/32", "45.238.170.64/29", "2804:4fa8:1::/48"])
        for bad in ("", "x", "10.0.0.0/8", "2804::/16"):
            with self.assertRaises(cr.ReportError):
                cr.parse_targets(bad)
        sql, params = cr._match_sql(("local_ip",), nets)
        self.assertEqual(sql, "(local_ip IN (%s) OR INET6_ATON(local_ip) BETWEEN INET6_ATON(%s) AND INET6_ATON(%s) OR "
                              "INET6_ATON(local_ip) BETWEEN INET6_ATON(%s) AND INET6_ATON(%s))")
        self.assertEqual(params[:3], ["187.87.201.40", "45.238.170.64", "45.238.170.71"])


@unittest.skipUnless(DB_ENABLED, "defina ORBYMON_TEST_DB=1 e ORBYMON_DB_*")
class DbTests(unittest.TestCase):
    def setUp(self):
        from fmn_filters.mysql_sink import connection_from_env
        self.db = connection_from_env()
        cur = self.db.cursor()
        cur.execute("DELETE FROM orby_attack_events WHERE rule_name LIKE 'teste rel%%'")
        cur.execute("DELETE FROM orby_flow_minute WHERE source='reltest'")
        ev = "INSERT INTO orby_attack_events (event_id,event_time,rule_name,severity,detection,direction,scope,local_ip," \
             "subscriber_ip,protocol,remote_port,pps,mbps,remote_ips,details) VALUES (%s,%s,%s,'high','flow',%s,%s,%s,%s," \
             "'tcp',%s,%s,%s,%s,'{}')"
        cur.executemany(ev, [
            ("r1", T, "teste rel OUT SSH", "out", "cgnat_subscriber", "45.238.170.70", "100.64.70.12", 22, 900, 1.5, 300),
            ("r2", T + timedelta(minutes=5), "teste rel OUT SSH", "out", "cgnat_subscriber", "45.238.170.70",
             "100.64.70.12", 22, 1200, 2.0, 400),
            ("r3", T, "teste rel IN UDP", "in", "dedicated", "187.87.201.42", "187.87.201.42", 0, 90000, 800, 50),
            ("r4", T - timedelta(days=3), "teste rel antigo", "in", "dedicated", "187.87.201.42", "187.87.201.42", 0, 1, 1, 1)])
        fl = "INSERT INTO orby_flow_minute (source,bucket_utc,direction,scope,pool,local_ip,subscriber_ip,remote_ip," \
             "protocol,remote_port,packets,bytes,flows) VALUES ('reltest',%s,%s,%s,%s,%s,%s,%s,'tcp',%s,%s,%s,%s)"
        cur.executemany(fl, [
            (T, "out", "cgnat_pool", "NAT-POOL-08", "45.238.170.70", "100.64.70.12", "203.0.113.%d" % i, 22, 10, 6000, 1)
            for i in range(1, 40)] + [
            (T, "in", "dedicated", "", "187.87.201.42", "187.87.201.42", "198.51.100.9", 0, 1e6, 8e8, 50)])
        self.db.commit()

    def tearDown(self):
        cur = self.db.cursor()
        cur.execute("DELETE FROM orby_attack_events WHERE rule_name LIKE 'teste rel%%'")
        cur.execute("DELETE FROM orby_flow_minute WHERE source='reltest'")
        self.db.commit()
        self.db.close()

    def test_subscriber_and_prefix(self):
        cur = self.db.cursor()
        r = cr.build(cur, cr.parse_targets("100.64.70.12"), T - timedelta(hours=1), T + timedelta(hours=1), "reltest",
                     identify=lambda ip, when: "login joao123" if ip == "100.64.70.12" else "")
        self.assertEqual([(e["regra"], e["quantidade"]) for e in r["eventos"]], [("teste rel OUT SSH", 2)])
        self.assertEqual(r["trafego"]["out"]["remotos"], 39)
        self.assertEqual(r["portas_saida"][0]["porta"], 22)
        self.assertEqual(r["ips_publicos"][0]["ip"], "45.238.170.70")
        self.assertEqual(r["identificacao"][0]["quem"], "login joao123")
        text = cr.render_text(r, lambda t: t.strftime("%d/%m %H:%M") if t else "—", "Teste")
        self.assertIn("originado · teste rel OUT SSH · 2 evento(s)", text)
        self.assertIn("tcp/22 39", text)
        self.assertIn("IPs públicos usados (CGNAT): 45.238.170.70", text)
        from pathlib import Path
        from fmn_filters.bidir_config import build_scopes, validate_config
        root = Path(__file__).resolve().parent.parent
        scopes = build_scopes(validate_config(json.loads((root / "rules/bidir.example.json").read_text())),
                              json.loads((root / "rules/cgnat-profiles.a10.json").read_text()))
        r = cr.build(cur, cr.parse_targets("45.238.170.70 187.87.201.42"), T - timedelta(hours=1), T + timedelta(hours=1),
                     "reltest", scopes)                                 # escopo real (classify devolve 3 valores)
        self.assertEqual([(i["ip"], i["escopo"], i["pool"]) for i in r["identificacao"]],
                         [("45.238.170.70", "cgnat_pool", "NAT-POOL-08"), ("187.87.201.42", "dedicated", "")])
        r = cr.build(cur, cr.parse_targets("187.87.201.40/29"), T - timedelta(hours=1), T + timedelta(hours=1), "reltest")
        self.assertEqual([e["regra"] for e in r["eventos"]], ["teste rel IN UDP"])      # o antigo fica fora do periodo
        self.assertEqual(r["trafego"]["in"]["bytes"], 8e8)
        with self.assertRaises(cr.ReportError):
            cr.build(cur, cr.parse_targets("187.87.201.40"), T, T + timedelta(days=40), "reltest")


if __name__ == "__main__":
    unittest.main()
