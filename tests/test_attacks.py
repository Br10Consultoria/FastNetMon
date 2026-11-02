"""Tela de Ataques: filtros, agrupamento de eventos em ataques, origem/destino por sentido, detalhe e resumo.
A parte com MariaDB roda com ORBYMON_TEST_DB=1 (usa root pelo socket e um banco temporario)."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import unittest

from fmn_filters import attacks as at
from fmn_filters.abuse_lookup import parse_time

T0 = datetime(2026, 11, 1, 10, 0)


def ev(minute, **kw):
    e = {"event_time": T0 + timedelta(minutes=minute), "rule_name": "IN UDP volumetrico", "severity": "high",
         "detection": "flow", "direction": "in", "scope": "dedicated", "pool": "", "local_ip": "187.87.201.40",
         "subscriber_ip": "187.87.201.40", "protocol": "udp", "local_port": 0, "remote_port": 53, "pps": 1000.0,
         "mbps": 10.0, "remote_ips": 300, "syn_ratio": 0.0,
         "details": {"minutes": 3, "top_remote_ips": ["203.0.113.5", "203.0.113.6"]}}
    e.update(kw)
    return e


class FilterTests(unittest.TestCase):
    def parse(self, **a):
        return at.parse_filters(a, T0, parse_time, timezone.utc)

    def test_defaults_last_24h(self):
        f = self.parse()
        self.assertEqual((f["start"], f["end"]), (T0 - timedelta(days=1), T0))

    def test_validation(self):
        for bad in ({"remoto": "x"}, {"porta": "70000"}, {"porta": "a"}, {"proto": "t;cp"},
                    {"inicio": "2026-11-01 11:00", "fim": "2026-11-01 10:00"},
                    {"inicio": "2026-08-01 10:00", "fim": "2026-11-01 10:00"}, {"ip": "10.0.0.0/8"}):
            with self.assertRaises(at.AttackError, msg=bad):
                self.parse(**bad)

    def test_customer_prefixes(self):
        f = at.parse_filters({"cliente": "3"}, T0, parse_time, timezone.utc,
                             [{"id": 3, "prefixes": ["45.238.170.64/29"]}])
        self.assertEqual(str(f["nets"][0]), "45.238.170.64/29")

    def test_where_has_port_json_and_severity(self):
        f = self.parse(porta="23", sev="high", sentido="out")
        w, p = at._event_where(f)
        self.assertIn("JSON_CONTAINS(details,%s,'$.top_portas')", " ".join(w))
        self.assertIn(json.dumps({"porta": 23}), p)
        self.assertIn("critical", p)
        self.assertNotIn("warning", p)


class GroupTests(unittest.TestCase):
    def test_repeated_events_become_one_attack(self):
        events = [ev(0), ev(10, pps=5000.0, severity="critical"), ev(20), ev(120)]
        attacks, total = at.group_events(events)
        self.assertEqual(total, 2)                                  # 120 min depois: outro ataque
        first = attacks[1]
        self.assertEqual(first["events"], 3)
        self.assertEqual(first["pps"], 5000.0)
        self.assertEqual(first["severity"], "critical")
        self.assertEqual(first["start"], T0 - timedelta(minutes=2))  # janela de 3 min
        self.assertEqual(first["end"], T0 + timedelta(minutes=21))

    def test_inbound_origin_is_remote(self):
        a = at.group_events([ev(0)])[0][0]
        self.assertTrue(a["origem"].startswith("203.0.113.5"))
        self.assertEqual(a["destino"], "187.87.201.40")
        self.assertEqual((a["porta_origem"], a["porta_destino"]), (53, ""))
        self.assertEqual(a["service"], "DNS")

    def test_outbound_cgnat_shows_private_and_public(self):
        e = ev(0, direction="out", scope="cgnat_private", local_ip="45.238.170.10", subscriber_ip="100.64.65.10",
               protocol="tcp", remote_port=23, rule_name="OUT varredura",
               details={"minutes": 2, "top_remote_ips": ["198.51.100.9"]})
        a = at.group_events([e])[0][0]
        self.assertEqual((a["entity_col"], a["entity"]), ("subscriber_ip", "100.64.65.10"))
        self.assertEqual(a["origem"], "100.64.65.10 (público 45.238.170.10)")
        self.assertEqual(a["porta_destino"], 23)
        self.assertEqual(a["publics_top"][0], "45.238.170.10")

    def test_nat_event_ports(self):
        e = ev(0, detection="nat", direction="out", scope="cgnat_private", local_ip="100.64.65.10",
               subscriber_ip="100.64.65.10", protocol="", remote_port=0, pps=0.0, mbps=0.0, remote_ips=0,
               rule_name="NAT portas", details={"minutes": 5, "allocs_per_min": 9000, "active_ports": 30000,
                                                "top_portas": [{"protocolo": "tcp", "porta": 23, "destinos": 180}]})
        a = at.group_events([e])[0][0]
        self.assertEqual((a["allocs"], a["ports_top"][0]["destinos"]), (9000, 180))

    def test_key_roundtrip(self):
        a = at.group_events([ev(0)])[0][0]
        p = {k: str(v) for k, v in at.key_params(a).items()}
        k = at.parse_key(p)
        self.assertEqual((k["entity"], k["remote_port"], k["start"]), ("187.87.201.40", 53, a["start"]))
        for bad in ({}, dict(p, alvo="x"), dict(p, col="pool"), dict(p, pr="99999"), dict(p, ate=p["de"])):
            with self.assertRaises(at.AttackError):
                at.parse_key(bad)


class TextTests(unittest.TestCase):
    def test_amplification_summary_and_chart(self):
        a = at.group_events([ev(0)])[0][0]
        k = at.parse_key({x: str(v) for x, v in at.key_params(a).items()})
        flows = {"totais": {"remotos": 300}, "portas": [{"protocol": "udp", "local_port": 0, "remote_port": 53,
                                                         "servico": "DNS"}]}
        text = at.summary_text({"key": k, "attack": a, "flows": flows}, lambda t: t.strftime("%H:%M"), "Cliente X")
        self.assertIn("amplificação DNS", text)
        self.assertIn("Cliente X", text)
        svg = at.svg_series([{"bucket": T0 + timedelta(minutes=i), "pacotes": 60.0 * i} for i in range(5)])
        self.assertTrue(svg.startswith("<svg") and "polyline" in svg and "<script" not in svg)
        self.assertEqual(at.human(1234567), "1,2 mi")


DB = os.environ.get("ORBYMON_TEST_DB") == "1"
ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(DB, "defina ORBYMON_TEST_DB=1 para testar no MariaDB")
class MariaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import pymysql
        cls.db = pymysql.connect(unix_socket="/run/mysqld/mysqld.sock", user="root", autocommit=True,
                                 init_command="SET time_zone='+00:00'")
        cur = cls.db.cursor()
        cur.execute("DROP DATABASE IF EXISTS orby_attacks_test")
        cur.execute("CREATE DATABASE orby_attacks_test")
        cur.execute("USE orby_attacks_test")
        import subprocess
        with open(ROOT / "sql" / "bidir.sql", "rb") as fh:
            subprocess.run(["mariadb", "orby_attacks_test"], stdin=fh, check=True)
        rows = [("e1", T0, "IN UDP volumetrico", "high", "flow", "in", "dedicated", "", "187.87.201.40",
                 "187.87.201.40", "udp", 0, 53, 1000, 10, 300, 0, 0, 0,
                 json.dumps({"minutes": 3, "top_remote_ips": ["203.0.113.5"]})),
                ("e2", T0, "NAT portas", "critical", "nat", "out", "cgnat_private", "", "100.64.65.10",
                 "100.64.65.10", "tcp", 0, 0, 0, 0, 0, 0, 0, 0,
                 json.dumps({"minutes": 5, "allocs_per_min": 9000,
                             "top_portas": [{"protocolo": "tcp", "porta": 23, "destinos": 180}]}))]
        cur.executemany("INSERT INTO orby_attack_events (event_id,event_time,rule_name,severity,detection,direction,"
                        "scope,pool,local_ip,subscriber_ip,protocol,local_port,remote_port,pps,mbps,remote_ips,"
                        "syn_ratio,input_if,output_if,details) VALUES (" + ",".join(["%s"] * 20) + ")", rows)
        flows = [("huawei", T0 - timedelta(minutes=m), "in", "dedicated", "", "187.87.201.40", "187.87.201.40",
                  "203.0.113.%d" % i, "udp", 40000 + i, 53, 10, 20, 2048, 2048 * 500, 0, 0, 1)
                 for m in range(3) for i in range(1, 11)]
        cur.executemany("INSERT INTO orby_flow_minute (source,bucket_utc,direction,scope,pool,local_ip,subscriber_ip,"
                        "remote_ip,protocol,local_port,remote_port,input_if,output_if,packets,bytes,syn_packets,"
                        "zero_port_packets,flows) VALUES (" + ",".join(["%s"] * 18) + ")", flows)

    @classmethod
    def tearDownClass(cls):
        cls.db.cursor().execute("DROP DATABASE IF EXISTS orby_attacks_test")
        cls.db.close()

    def events(self, **a):
        f = at.parse_filters(a, T0 + timedelta(hours=1), parse_time, timezone.utc)
        return at.fetch_events(self.db.cursor(), f)

    def test_filters(self):
        self.assertEqual(len(self.events()), 2)
        self.assertEqual([e["rule_name"] for e in self.events(porta="23")], ["NAT portas"])   # porta no JSON
        self.assertEqual([e["rule_name"] for e in self.events(porta="53")], ["IN UDP volumetrico"])
        self.assertEqual(len(self.events(remoto="203.0.113.5")), 1)
        self.assertEqual(len(self.events(ip="100.64.65.0/24")), 1)
        self.assertEqual(len(self.events(sev="critical")), 1)
        self.assertEqual(len(self.events(tipo="nat", sentido="in")), 0)

    def test_detail_from_mariadb(self):
        a = at.group_events(self.events(sentido="in"))[0][0]
        k = at.parse_key({x: str(v) for x, v in at.key_params(a).items()})
        cur = self.db.cursor()
        d = at.build_detail(cur, k, at.MariaFlows(cur), None, None)
        self.assertIsNone(d["error"])
        self.assertEqual(int(d["flows"]["totais"]["remotos"]), 10)
        self.assertEqual(len(d["flows"]["minutos"]), 3)
        self.assertEqual(d["flows"]["portas"][0]["servico"], "DNS")
        self.assertEqual(len(d["events"]), 1)


if __name__ == "__main__":
    unittest.main()
