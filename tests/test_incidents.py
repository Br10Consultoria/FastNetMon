import json
from pathlib import Path
import tempfile
import unittest
from fmn_filters.incidents import IncidentStore


def alert(at, rule='DNS-query-flood', ip='198.51.100.10', pps=10000, src=None):
    group = {'dst_ip': ip, 'dst_port': 53, 'protocol': 'udp'}
    if src:
        group['src_ip'] = src
    return {'rule': rule, 'kind': 'flow', 'severity': 'critical', 'action': 'alert_only',
            'time_unix': at, 'group': group, 'metrics_estimated': {'pps': pps, 'mbps': 8},
            'sample_sources': ['203.0.113.10']}


class IncidentsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name)/'incident.db'
        self.s = IncidentStore(self.db)

    def tearDown(self):
        self.s.close()
        self.tmp.cleanup()

    def test_create_dedupe_and_persistent_replay(self):
        first = self.s.ingest(alert(1700000000))
        self.assertTrue(first['created'])
        self.assertTrue(self.s.ingest(alert(1700000000))['duplicate'])
        self.s.close()
        self.s = IncidentStore(self.db)
        self.assertEqual(len(self.s.list()), 1)
        self.assertEqual(self.s.list()[0]['alert_count'], 1)

    def test_correlates_same_target_and_accumulates_peaks(self):
        first = self.s.ingest(alert(1700000000))
        second = self.s.ingest(alert(1700000020, pps=30000, src='203.0.113.2'))
        self.assertEqual(first['incident_id'], second['incident_id'])
        item = self.s.detail(first['incident_id'])
        self.assertEqual(item['alert_count'], 2)
        self.assertEqual(item['peak_pps'], 30000)
        self.assertEqual(len(item['observations']), 2)

    def test_independent_target_and_tenant(self):
        a = self.s.ingest(alert(1700000000), 'isp-a')
        b = self.s.ingest(alert(1700000000, ip='198.51.100.11'), 'isp-a')
        c = self.s.ingest(alert(1700000000), 'isp-b')
        self.assertEqual(len({a['incident_id'], b['incident_id'], c['incident_id']}), 3)
        self.assertEqual(len(self.s.list('isp-a')), 2)
        self.assertIsNone(self.s.detail(a['incident_id'], 'isp-b'))

    def test_new_incident_after_quiet_interval(self):
        first = self.s.ingest(alert(1700000000))
        second = self.s.ingest(alert(1700000400), quiet_seconds=300)
        self.assertNotEqual(first['incident_id'], second['incident_id'])

    def test_resolve_then_new_alert_creates_new_incident(self):
        first = self.s.ingest(alert(1700000000))
        self.assertTrue(self.s.resolve(first['incident_id']))
        self.assertFalse(self.s.resolve(first['incident_id']))
        other = self.s.ingest(alert(1700000010, src='203.0.113.5'))
        self.assertNotEqual(first['incident_id'], other['incident_id'])
        self.assertEqual(self.s.metrics(), {'open': 1, 'resolved': 1})

    def test_only_alert_mode_accepted(self):
        obj = alert(1700000000)
        obj['action'] = 'blackhole'
        with self.assertRaises(ValueError):
            self.s.ingest(obj)
        with self.assertRaises(ValueError):
            self.s.ingest({'action': 'alert_only'})

    def test_negative_bad_metrics_not_possible(self):
        obj = alert(1700000000)
        obj['metrics_estimated']['pps'] = float('nan')
        with self.assertRaises(ValueError):
            self.s.ingest(obj)

    def test_bad_status_rejected(self):
        with self.assertRaises(ValueError):
            self.s.list(status='other')


if __name__ == '__main__':
    unittest.main()
