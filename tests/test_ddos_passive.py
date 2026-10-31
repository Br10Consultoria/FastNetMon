import json
from datetime import datetime,timedelta,timezone
from unittest.mock import patch
from pathlib import Path
import unittest

from fmn_filters.ddos_passive import validate_config,match_rollup,evaluate,fetch_rows,SQL_ROWS,run

ROOT=Path(__file__).resolve().parent.parent
CFG=json.loads((ROOT/"rules/ddos-passive.example.json").read_text())


def record(minute=0,src="8.8.8.8",dst="45.238.170.10",proto="udp",
           port=53,pps=100000,mbps=700,interface=86,out=16,asn=15169):
    return dict(bucket_utc=datetime(2026,10,30,10,0)+timedelta(minutes=minute),
        src_ip=src,dst_ip=dst,protocol=proto,dst_port=port,input_if=interface,
        output_if=out,netflow_direction=0,src_asn=asn,dst_asn=0,src_country="US",dst_country="",
        total_packets=pps*60,total_bytes=mbps*60e6/8,flow_records=1)


class PassiveTests(unittest.TestCase):
    def setUp(self):
        self.config=validate_config(json.loads(json.dumps(CFG)))
        self.rule=self.config["rules"][0]
        self.start=datetime(2026,10,30,10,0)

    def test_real_scopes(self):
        self.assertEqual(self.config["protected_cidrs"],
            ["45.238.170.0/23","187.87.201.0/24"])
        self.assertTrue(self.config["enabled"])

    def test_composite_and_or_not(self):
        cond={"all_of":[{"protocols":["udp"]},
              {"any_of":[{"dst_ports":[53]},{"dst_ports":[123]}]},
              {"not":{"src_cidrs":["10.0.0.0/8"]}}]}
        self.assertTrue(match_rollup(record(),cond))
        self.assertFalse(match_rollup(record(port=443),cond))
        self.assertFalse(match_rollup(record(src="10.0.0.1"),cond))

    def test_unknown_asn_negative(self):
        self.assertFalse(match_rollup(record(asn=0),{"not":{"src_asns":[15169]}}))

    def test_two_consecutive_minutes_protected_destination(self):
        rows=[record(minute=m,src="8.8.8.%d"%(n+1),pps=10000,mbps=70)
              for m in range(2) for n in range(9)]
        result=evaluate(rows,self.rule,self.config,self.start)
        self.assertEqual(len(result),1)
        self.assertEqual(result[0]["unique_sources"],9)
        self.assertEqual(result[0]["dst_ip"],"45.238.170.10")
        self.assertAlmostEqual(result[0]["pps"],90000)
        self.assertAlmostEqual(result[0]["mbps"],630)
        self.assertEqual(evaluate(rows[:9],self.rule,self.config,self.start),[])
        self.assertEqual(evaluate([dict(r,dst_ip="9.9.9.9") for r in rows],
                                   self.rule,self.config,self.start),[])

    def test_interfaces_not_combined(self):
        rows=[record(minute=m,src="8.8.8.%d"%(n+1),pps=6000,mbps=40,
                     interface=86 if n%2 else 87)
              for m in range(2) for n in range(10)]
        self.assertEqual(evaluate(rows,self.rule,self.config,self.start),[])

    def test_netflow_direction_not_combined(self):
        rows=[record(minute=m,src="8.8.8.%d"%(n+1),pps=6000,mbps=40)
              for m in range(2) for n in range(10)]
        for i,row in enumerate(rows):
            row["netflow_direction"]=i%2
        self.assertEqual(evaluate(rows,self.rule,self.config,self.start),[])

    def test_few_sources_or_excluded_destination(self):
        rows=[record(minute=m,src="8.8.8.%d"%(n+1))
              for m in range(2) for n in range(3)]
        self.assertEqual(evaluate(rows,self.rule,self.config,self.start),[])
        self.config["excluded_destinations"]=["45.238.170.0/23"]
        self.assertEqual(evaluate(rows,self.rule,self.config,self.start),[])

    def test_reject_filters_missing_from_sql_rollup(self):
        c=json.loads(json.dumps(CFG))
        c["rules"][0]["match"]={"tcp_flags_all":"S"}
        with self.assertRaisesRegex(ValueError,"nao presentes"):
            validate_config(c)
        c=json.loads(json.dumps(CFG))
        c["rules"][0]["min_pps"]=-1
        with self.assertRaises(ValueError):
            validate_config(c)

    def test_rule_cannot_have_only_negative_scope(self):
        config=json.loads(json.dumps(CFG))
        config["rules"][0]["match"]={"not":{"protocols":["udp"]}}
        with self.assertRaisesRegex(ValueError,"POSITIVO"):
            validate_config(config)

    def test_rule_cannot_escape_scope_through_unrestricted_or(self):
        config=json.loads(json.dumps(CFG))
        config["rules"][0]["match"]={
            "any_of":[{"protocols":["udp"]},{"src_asns":[15169]}]}
        with self.assertRaisesRegex(ValueError,"POSITIVO"):
            validate_config(config)
        config["rules"][0]["match"]={
            "all_of":[{"protocols":["udp"]},{"any_of":[
                {"dst_ports":[53]},{"src_asns":[15169]}]}]}
        self.assertTrue(validate_config(config))

    def test_empty_ingestion_window_does_not_claim_passive_health(self):
        class FakeCursor:
            def __init__(self):
                self.executed=[]
            def __enter__(self): return self
            def __exit__(self,exc_type,exc,tb): return False
            def execute(self,sql,params): self.executed.append((sql,params))
        class FakeDB:
            def __init__(self): self.cur=FakeCursor();self.commits=0
            def cursor(self): return self.cur
            def commit(self): self.commits+=1
            def rollback(self): raise AssertionError("unexpected rollback")
            def close(self): pass
        db=FakeDB()
        with (patch("fmn_filters.ddos_passive.connection_from_env",return_value=db),
              patch("fmn_filters.ddos_passive.fetch_rows",return_value=[])):
            written=run(self.config,now=datetime(2026,10,31,18,0,tzinfo=timezone.utc))
        self.assertEqual(written,0)
        self.assertEqual(db.commits,1)
        self.assertEqual(len(db.cur.executed),1)
        self.assertEqual(db.cur.executed[0][1][3],"sem_dados")
        self.assertEqual(db.cur.executed[0][1][4:6],(0,0))

    def test_no_partial_analysis_when_rows_exceed_cap(self):
        class Cur:
            def execute(self,sql,params):
                self.params=params
            def fetchall(self):
                return [tuple(range(14))]*4
        with self.assertRaises(RuntimeError):
            fetch_rows(Cur(),"huawei",self.start,self.start+timedelta(minutes=2),3)
        self.assertIn("LIMIT %s",SQL_ROWS)


if __name__=="__main__":
    unittest.main()
