from pathlib import Path
import tempfile
import os
import sqlite3
import json
import unittest
from unittest.mock import patch
from fmn_filters.engine import Detector, Rule
from fmn_filters.watcher import scan


class WatcherTests(unittest.TestCase):
    def test_rotated_file_scanned_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp)/'nfcapd.202610262000'
            f.write_text('dummy')
            os.utime(f, (1000000000, 1000000000))
            r = Rule.from_dict({'name': 'alludp', 'kind': 'flow',
                'match': {'dst_ports': [53], 'protocols': ['udp']},
                'group_by': ['dst_ip'], 'window_seconds': 1,
                'thresholds': {'min_pps': 100}})
            with sqlite3.connect(':memory:') as db:
                payload = [{'type':'FLOW','first':'2026-10-26T20:00:00','last':'2026-10-26T20:00:01',
                            'src4_addr':'203.0.113.2','dst4_addr':'198.51.100.8',
                            'src_port': 50000,'dst_port':53,'proto':17,'in_packets':200,'in_bytes':20000}]
                class Fake:
                    stdout = json.dumps(payload)
                alerts = []
                with patch('fmn_filters.watcher.subprocess.run', return_value=Fake()) as execute, \
                     patch('fmn_filters.watcher.time.time', return_value=1000000010):
                    detector = Detector([r])
                    self.assertEqual(scan(Path(tmp), db, detector, emit=alerts.append), 1)
                    self.assertEqual(scan(Path(tmp), db, detector, emit=alerts.append), 0)
                    self.assertEqual(len(alerts), 1)
                    self.assertEqual(execute.call_count, 1)

if __name__ == '__main__':
    unittest.main()
