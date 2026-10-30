import json
from datetime import datetime,timedelta,timezone
from pathlib import Path
import unittest
from unittest.mock import patch

from fmn_filters.cgnat_baseline import (
    validate_config,classify,selection_query,percentile,summarize_rows,run
)

ROOT=Path(__file__).resolve().parent.parent
CFG=json.loads((ROOT/"rules/cgnat-profiles.example.json").read_text())


def cfg_copy():
    return json.loads(json.dumps(CFG))


class CGNATBaselineTests(unittest.TestCase):
    def test_initial_public_prefixes_are_unclassified(self):
        c=validate_config(cfg_copy())
        self.assertEqual(classify("45.238.170.1",c),"uso_nao_classificado")
        self.assertEqual(classify("187.87.201.198",c),"uso_nao_classificado")
        self.assertIsNone(classify("177.85.70.98",c))
        self.assertEqual(c["cgnat_pools"],[])

    def test_exact_cgnat_subset_and_no_fictitious_client(self):
        c=cfg_copy()
        c["cgnat_pools"]=["187.87.201.160/27"]
        c["dedicated_public_cidrs"]=["187.87.201.32/28"]
        validate_config(c)
        self.assertEqual(classify("187.87.201.174",c),"cgnat_compartilhado")
        self.assertEqual(classify("187.87.201.38",c),"ip_dedicado")
        self.assertEqual(classify("187.87.201.90",c),"uso_nao_classificado")
        self.assertNotIn("subscriber",json.dumps(c))

    def test_reject_overlap_or_outside_protected(self):
        c=cfg_copy()
        c["cgnat_pools"]=["187.87.201.160/27"]
        c["dedicated_public_cidrs"]=["187.87.201.176/28"]
        with self.assertRaisesRegex(ValueError,"sobrepoem"):
            validate_config(c)
        c=cfg_copy()
        c["cgnat_pools"]=["170.83.185.160/27"]
        with self.assertRaisesRegex(ValueError,"nao pertence"):
            validate_config(c)
        c=cfg_copy()
        c["cgnat_pools"]=["100.64.0.0/10"]
        with self.assertRaises(ValueError):
            validate_config(c)

    def test_observation_sides_are_separate_and_no_double_count(self):
        c=validate_config(cfg_copy())
        bucket=datetime(2026,10,30,10,0)
        rows=[
            (bucket,"45.238.170.10","177.85.70.98","tcp",86,16,0,6000,750000),
            (bucket+timedelta(minutes=1),"45.238.170.10","177.85.70.98","tcp",86,16,0,12000,1500000),
            (bucket+timedelta(minutes=2),"177.85.70.98","45.238.170.10","tcp",86,16,1,6000,750000),
            (bucket+timedelta(minutes=3),"45.238.170.10","177.85.70.98","tcp",87,16,0,5000,500000),
        ]
        out=summarize_rows(rows,c)
        self.assertEqual(len(out),3)
        self.assertEqual({r["observacao"] for r in out},
                         {"IP_NA_ORIGEM","IP_NO_DESTINO"})
        self.assertEqual({r["ifIndex_entrada"] for r in out},{86,87})
        src=next(r for r in out if r["observacao"]=="IP_NA_ORIGEM"
                 and r["ifIndex_entrada"]==86)
        self.assertEqual(src["minutos_com_dados"],2)
        self.assertFalse(src["baseline_confiavel"])
        self.assertEqual(src["maior_numero_ips_remotos_observados"],1)
        self.assertGreater(src["mbps_pico_observado"],src["mbps_p95_observado"]-0.01)

    def test_nearest_rank_p95(self):
        self.assertEqual(percentile([1,2,3,4,5,6,7,8,9,10],.95),10)
        self.assertEqual(percentile([],.95),0)

    def test_parameterized_query_and_window(self):
        c=validate_config(cfg_copy())
        sql,params=selection_query(c,datetime(2026,10,30,9),
                                     datetime(2026,10,30,10))
        self.assertEqual(sql.count("BETWEEN %s AND %s"),4)
        self.assertEqual(params[0],"huawei")
        self.assertEqual(params[-1],80001)
        self.assertIn("LIMIT %s",sql)

    def test_refuse_partial_report(self):
        c=cfg_copy()
        c["max_rows"]=1000
        class Cursor:
            def __enter__(self): return self
            def __exit__(self,*a): return False
            def execute(self,sql,params): pass
            def fetchall(self): return [()]*1001
        class DB:
            def cursor(self): return Cursor()
            def close(self): pass
        with patch("fmn_filters.cgnat_baseline.connection_from_env",
                   return_value=DB()):
            with self.assertRaisesRegex(RuntimeError,"parcial recusado"):
                run(c,now=datetime(2026,10,30,10,tzinfo=timezone.utc))


if __name__=="__main__":
    unittest.main()
