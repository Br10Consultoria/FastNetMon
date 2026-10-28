import unittest
from io import StringIO
import json
from fmn_filters.mysql_sink import alert_to_row, flow_to_group, process, ALERT_SQL, FLOW_SQL


class FakeCursor:
    def __init__(self):
        self.sql=[]
    def execute(self,sql,params):
        self.sql.append((sql,params))
    def executemany(self,sql,params):
        for row in params:
            self.sql.append((sql,row))


class MySQLSinkTests(unittest.TestCase):
    def test_aggregated_flow_rollup(self):
        e=dict(src_ip='8.8.8.8',dst_ip='1.1.1.1',src_port=12345,dst_port=53,protocol='udp',
               timestamp='2026-10-28T12:00:20Z',packets=50,bytes=10000,src_asn=15169,
               src_asn_name='Example LLC',src_country='US')
        cur=FakeCursor()
        payload='\n'.join(json.dumps(e) for _ in range(3))
        self.assertEqual(process(StringIO(payload),cur,'flows'),3)
        self.assertEqual(len(cur.sql),1)
        row=cur.sql[0][1]
        self.assertEqual(row[1],15169)
        self.assertEqual(row[8],150)
        self.assertEqual(row[9],30000)

    def test_alert_without_source_group_remains_unattributed(self):
        alert=dict(action='alert_only',time_unix=1000,rule='ddos',kind='flow',group={'dst_ip':'1.1.1.1'},
                   metrics_estimated={'pps':10000}, context={})
        row=alert_to_row(alert)
        self.assertIsNone(row[7])
        self.assertIsNone(row[13])
        self.assertEqual(len(row),22)
        self.assertEqual(alert_to_row(alert)[0],row[0])

    def test_reject_external_actions(self):
        with self.assertRaises(ValueError):
            alert_to_row(dict(action='block',rule='danger',time_unix=1))

    def test_flow_without_public_metadata(self):
        row=flow_to_group(dict(src_ip='10.1.1.1',dst_ip='8.8.8.8',src_port=32,dst_port=443,
                               protocol='tcp',timestamp=123,packets=1,bytes=200))
        self.assertEqual(row[1],0)

if __name__ == '__main__':
    unittest.main()
