import json
from pathlib import Path
import unittest
from fmn_filters.engine import Detector, Rule, matches
from fmn_filters.parsers import parse_record, stream_records


def build_event(src='203.0.113.1', dst='198.51.100.15',
                proto='udp', src_port=55000, dst_port=53,
                start=1000, end=1001, packets=50000, bytes=900000,
                flags='', kind='flow', path=''):
    return parse_record(dict(kind=kind, src_ip=src, dst_ip=dst, src_port=src_port,
                             dst_port=dst_port, protocol=proto, start=start, end=end,
                             packets=packets, bytes=bytes, tcp_flags=flags, path=path))


def rule(overrides=None):
    d = {'name': 'dns-test', 'kind': 'flow', 'match': {'protocols': ['udp'],
         'dst_ports': [53], 'dst_cidrs': ['198.51.100.0/24']},
         'group_by': ['dst_ip', 'dst_port'], 'window_seconds': 10,
         'cooldown_seconds': 60, 'thresholds': {'min_pps': 15000, 'min_unique_sources': 3}}
    d.update(overrides or {})
    return Rule.from_dict(d)


class RuleEngineTests(unittest.TestCase):
    def test_combined_and_does_not_accept_wrong_port(self):
        detector = Detector([rule()])
        for i in range(10):
            self.assertEqual(detector.process(build_event(src=f'203.0.113.{i+1}', dst_port=123)), [])

    def test_alert_only_after_both_thresholds(self):
        detector = Detector([rule()])
        self.assertEqual(detector.process(build_event(src='203.0.113.1')), [])
        self.assertEqual(detector.process(build_event(src='203.0.113.2')), [])
        alert = detector.process(build_event(src='203.0.113.3'))
        self.assertEqual(len(alert), 1)
        self.assertEqual(alert[0]['action'], 'alert_only')
        self.assertEqual(alert[0]['group']['dst_ip'], '198.51.100.15')
        self.assertEqual(alert[0]['metrics_estimated']['pps'], 15000)

    def test_no_mix_between_destinations(self):
        detector = Detector([rule()])
        for i in range(2):
            self.assertEqual(detector.process(build_event(src=f'203.0.113.{i+1}', dst='198.51.100.10')), [])
        self.assertEqual(detector.process(build_event(src='203.0.113.3', dst='198.51.100.11')), [])

    def test_cooldown(self):
        detector = Detector([rule()])
        for i in range(3):
            alerts = detector.process(build_event(src=f'203.0.113.{i+1}'))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(detector.process(build_event(src='203.0.113.4', end=1002)), [])

    def test_flow_over_ten_seconds_is_distributed(self):
        detector = Detector([rule({'thresholds': {'min_pps': 100}})])
        alerts = detector.process(build_event(start=990, end=1000, packets=1000))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['metrics_estimated']['pps'], 100)

    def test_excluded_sources(self):
        item = build_event(src='192.0.2.1')
        self.assertFalse(matches(item, {'exclude_src_cidrs': ['192.0.2.0/24']}))

    def test_any_of_nested(self):
        item = build_event(dst_port=443, proto='tcp')
        self.assertTrue(matches(item, {'any_of': [{'dst_ports': [53]}, {'dst_ports': [443]}]}))
        self.assertFalse(matches(item, {'any_of': [{'dst_ports': [53]}, {'protocols': ['udp']}]}))

    def test_invalid_rule_rejected(self):
        with self.assertRaises(ValueError):
            rule({'match': {'dst_porsts': [53]}})
        with self.assertRaises(ValueError):
            rule({'thresholds': {'min_pps': -5}})

    def test_nfdump_parsing_and_timezone(self):
        raw = {'type': 'FLOW', 'first': '2026-10-26T20:00:00', 'last': '2026-10-26T20:00:01',
               'src4_addr': '203.0.113.1', 'dst4_addr': '198.51.100.1',
               'src_port': 12345, 'dst_port': 443, 'tcp_flags': '....S...',
               'proto': 6, 'in_packets': 1000, 'in_bytes': 50000}
        with self.assertRaises(ValueError):
            parse_record(raw)
        evt = parse_record(raw, assume_utc=True)
        self.assertEqual(evt.tcp_flags, 'S')
        self.assertEqual(evt.protocol, 'tcp')
        self.assertEqual(evt.packets, 1000)

    def test_nat_event_ignored(self):
        self.assertIsNone(parse_record({'type': 'EVENT', 'src4_addr': '203.0.113.1'}))

    def test_php_requires_http_logs(self):
        php_rule = rule({'name': 'php', 'kind': 'http',
           'match': {'path_suffix': '.php', 'dst_ports': [443]},
           'thresholds': {'min_rps': 0.2, 'min_unique_sources': 2},
           'group_by': ['dst_ip']})
        detector = Detector([php_rule])
        self.assertEqual(detector.process(build_event(kind='http', path='/index.php?x=1',
                                     dst_port=443, proto='tcp', src='203.0.113.1')), [])
        alerts = detector.process(build_event(kind='http', path='/index.php',
                                 dst_port=443, proto='tcp', src='203.0.113.2'))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['metrics_estimated']['rps'], 0.2)

    def test_no_http_rule_triggered_by_flow(self):
        php_rule = rule({'name': 'php', 'kind': 'http',
           'match': {'path_suffix': '.php', 'dst_ports': [443]},
           'thresholds': {'min_rps': 0.1}})
        self.assertEqual(Detector([php_rule]).process(build_event(dst_port=443, proto='tcp')), [])

    def test_ipv6(self):
        item = build_event(src='2001:db8::1', dst='2001:db8:100::2')
        self.assertTrue(matches(item, {'dst_cidrs': ['2001:db8:100::/48']}))

    def test_rules_example_valid(self):
        raw = json.loads((Path(__file__).parent.parent/'rules/example-rules.json').read_text())
        self.assertEqual(len([Rule.from_dict(d) for d in raw['rules']]), 5)


if __name__ == '__main__':
    unittest.main()
