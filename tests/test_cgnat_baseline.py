import json
from datetime import datetime,timedelta,timezone
from pathlib import Path
import unittest
from unittest.mock import patch

from fmn_filters.cgnat_baseline import (
    validate_config, classify, pool_for_ip, pool_baseline,
    selection_query, percentile, summarize_rows, run
)
from fmn_filters.configure_a10 import merge_profiles

ROOT=Path(__file__).resolve().parent.parent
BASE=json.loads((ROOT/"rules/cgnat-profiles.example.json").read_text())
A10=json.loads((ROOT/"rules/cgnat-profiles.a10.json").read_text())


def base_cfg():
    return json.loads(json.dumps(BASE))


def a10_cfg():
    return json.loads(json.dumps(A10))


class CGNATBaselineTests(unittest.TestCase):
    def test_a10_four_real_pools_and_lsn_100_64(self):
        c=validate_config(a10_cfg())
        self.assertEqual(c["inside_private_cidrs"],["100.64.64.0/19"])
        self.assertEqual(len(c["cgnat_pools"]),4)
        self.assertEqual(sum(__import__("ipaddress").ip_network(s).num_addresses for s in c["cgnat_pools"]),256)
        self.assertEqual(classify("45.238.170.70",c),"cgnat_compartilhado")
        self.assertEqual(classify("45.238.171.180",c),"cgnat_compartilhado")
        self.assertEqual(classify("187.87.201.198",c),"uso_nao_classificado")
        self.assertIsNone(classify("177.85.70.98",c))
        self.assertEqual(pool_for_ip("45.238.170.70",c)["name"],"NAT-POOL-08")
        self.assertEqual(pool_for_ip("45.238.171.70",c)["max_users_per_ip"],32)
        self.assertIsNone(pool_for_ip("100.64.64.1",c))

    def test_merge_preserves_local_profiles_and_existing_thresholds(self):
        old=base_cfg()
        old["dedicated_public_cidrs"]=["187.87.201.64/27"]
        old["lookback_hours"]=6
        combined=merge_profiles(old,a10_cfg())
        self.assertEqual(combined["dedicated_public_cidrs"],["187.87.201.64/27"])
        self.assertEqual(combined["lookback_hours"],6)
        self.assertEqual(len(combined["cgnat_pools"]),4)
        self.assertEqual(merge_profiles(combined,a10_cfg()),combined)

    def test_never_override_previously_set_different_pools(self):
        old=base_cfg()
        old["cgnat_pools"]=["45.238.170.0/26"]
        with self.assertRaisesRegex(ValueError,"divergentes"):
            merge_profiles(old,a10_cfg())

    def test_reject_overlap_and_invalid_cgnat_private(self):
        old=base_cfg()
        old["dedicated_public_cidrs"]=["45.238.170.64/26"]
        with self.assertRaisesRegex(ValueError,"sobrepoem"):
            merge_profiles(old,a10_cfg())
        bad=a10_cfg()
        bad["inside_private_cidrs"]=["192.168.1.0/24"]
        with self.assertRaises(ValueError):
            validate_config(bad)
        bad=a10_cfg()
        bad["cgnat_pool_metadata"]["45.238.170.64/26"]["max_users_per_ip"]=0
        with self.assertRaises(ValueError):
            validate_config(bad)

    def test_per_pool_directions_isolated_and_no_double_count(self):
        c=validate_config(a10_cfg())
        minute=datetime(2026,10,30,10,0)
        rows=[
            (minute,"45.238.170.70","8.8.8.8","tcp",86,16,0,6000,750000),
            (minute,"45.238.170.71","8.8.8.8","tcp",86,16,0,6000,750000),
            (minute,"8.8.8.8","45.238.170.70","tcp",86,16,1,3000,375000),
            (minute,"45.238.171.70","8.8.8.8","tcp",86,16,0,1000,125000),
        ]
        result=pool_baseline(rows,c)
        self.assertEqual(len(result),3)
        pool8src=next(r for r in result if r["pool"]=="NAT-POOL-08" and r["observacao"]=="IP_NA_ORIGEM")
        self.assertEqual(pool8src["max_ips_publicos_observados_no_minuto"],2)
        self.assertEqual(pool8src["minutos_com_dados"],1)
        self.assertEqual(pool8src["limite_configurado_usuarios_por_ip"],32)
        self.assertFalse(pool8src["baseline_confiavel"])
        self.assertNotEqual(pool8src["mbps_pico_observado"],0)

    def test_unknown_traffic_is_not_misclassified_as_subscriber(self):
        c=validate_config(a10_cfg())
        rows=[(datetime(2026,10,30,10),"100.64.64.10","8.8.8.8","tcp",86,16,0,100,1000)]
        self.assertEqual(pool_baseline(rows,c),[])
        self.assertEqual(summarize_rows(rows,c),[])

    def test_query_stays_parameterized_and_limited(self):
        c=validate_config(a10_cfg())
        sql,args=selection_query(c,datetime(2026,10,30,9),datetime(2026,10,30,10))
        self.assertEqual(sql.count("BETWEEN %s AND %s"),4)
        self.assertEqual(args[0],"huawei")
        self.assertEqual(args[-1],80001)
        self.assertIn("LIMIT %s",sql)

    def test_nearest_rank(self):
        self.assertEqual(percentile([1,2,3,4,5,6,7,8,9,10],.95),10)
        self.assertEqual(percentile([],.95),0)

    def test_refuse_partial_report(self):
        c=a10_cfg()
        c["max_rows"]=1000
        class Cursor:
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def execute(self,sql,args):pass
            def fetchall(self):return [()]*1001
        class DB:
            def cursor(self):return Cursor()
            def close(self):pass
        with patch("fmn_filters.cgnat_baseline.connection_from_env",return_value=DB()):
            with self.assertRaisesRegex(RuntimeError,"parcial recusado"):
                run(c,now=datetime(2026,10,30,10,tzinfo=timezone.utc))


if __name__=="__main__":
    unittest.main()
