import unittest

from fmn_filters.parsers import parse_record
from fmn_filters.protocols import NAMES, NUMBER_TO_NAME, proto_name


class ProtocolTests(unittest.TestCase):
    def test_iana_names(self):
        self.assertEqual(proto_name("47"), "gre")
        self.assertEqual(proto_name(51), "ah")
        self.assertEqual(proto_name("89"), "ospf")
        self.assertEqual(proto_name("58"), "icmpv6")
        self.assertEqual(proto_name("IPv6-ICMP"), "icmpv6")
        self.assertEqual(proto_name("TCP"), "tcp")
        self.assertEqual(proto_name("250"), "250")          # nao atribuido: fica o numero
        self.assertGreaterEqual(len(NUMBER_TO_NAME), 140)
        self.assertTrue({"tcp", "udp", "icmp", "gre", "esp", "ah", "sctp"} <= NAMES)

    def test_dashboard_lists_all_protocols(self):
        import json
        from pathlib import Path
        d = json.loads((Path(__file__).resolve().parent.parent / "grafana/dashboards/orbymon-f4-ataques.json").read_text())
        var = [v for v in d["templating"]["list"] if v["name"] == "proto"][0]
        values = {o["value"] for o in var["options"]}
        self.assertTrue(NAMES <= values)
        self.assertIn("all", values)


class ParserProtocolTests(unittest.TestCase):
    def test_nfdump_number_becomes_name(self):
        ev = parse_record({"src4_addr": "1.2.3.4", "dst4_addr": "45.238.170.70", "proto": 47, "in_packets": 1,
                           "in_bytes": 100, "first": "2026-11-01T10:00:00", "last": "2026-11-01T10:00:01"},
                          assume_utc=True)
        self.assertEqual(ev.protocol, "gre")


if __name__ == "__main__":
    unittest.main()
