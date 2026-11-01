"""Etapa 2: excecoes (CIDR/ASN), linha de base por hora, limite dinamico e 'acima do habitual'."""
from datetime import date, datetime, timedelta
import io
import json
import os
import unittest

from fmn_filters import baseline as bl
from fmn_filters import exceptions as ex
from fmn_filters import filter_rules as fr
from fmn_filters.bidir_config import validate_config
from fmn_filters.calibrate import Calibrator

from test_bidir_detector import CFG, RULES, START, rows
from test_calibrate import T0, row

DB_ENABLED = os.environ.get("ORBYMON_TEST_DB") == "1" and os.environ.get("ORBYMON_DB_USER")


def matcher(*entries):
    base = {"side": "remote", "direction": "any", "rule_name": "", "action": "ignore", "factor": 1}
    return ex.Matcher([dict(base, **e) for e in entries])


class ValidateTests(unittest.TestCase):
    def test_normalizes_and_rejects(self):
        e = ex.validate("cidr", " 187.87.201.53 ", "local", "out")
        self.assertEqual((e["value"], e["factor"], e["days"]), ("187.87.201.53/32", 1.0, None))
        self.assertEqual(ex.validate("asn", "AS15169", "remote")["value"], "15169")
        self.assertEqual(ex.validate("cidr", "45.238.170.70", "local", action="multiply", factor="5")["factor"], 5)
        for args in (("cidr", "0.0.0.0/0", "remote"), ("cidr", "2804::/16", "remote"), ("cidr", "x", "remote"),
                     ("asn", "15169", "local"), ("asn", "abc", "remote"),
                     ("cidr", "8.8.8.8", "remote", "any", "", "multiply", 3),
                     ("cidr", "8.8.8.8", "local", "any", "", "multiply", 1.1),
                     ("cidr", "8.8.8.8", "remote", "sideways")):
            with self.assertRaises(ex.ExceptionError, msg=args):
                ex.validate(*args)
        with self.assertRaises(ex.ExceptionError):
            ex.validate("cidr", "8.8.8.8", "remote", days=400)


class MatcherTests(unittest.TestCase):
    def test_scope_by_side_direction_and_rule(self):
        m = matcher({"cidrs": ["142.250.0.0/15"], "direction": "in", "rule_name": "IN UDP volumetrico"},
                    {"cidrs": ["187.87.201.53/32"], "side": "local", "direction": "out"},
                    {"cidrs": ["2001:db8::/32"]},
                    {"cidrs": ["45.238.170.10/32"], "side": "local", "action": "multiply", "factor": 4})
        self.assertTrue(m.ignore_row("IN UDP volumetrico", "in", ("45.238.170.10", ""), "142.251.1.1"))
        self.assertFalse(m.ignore_row("IN TCP volumetrico", "in", ("45.238.170.10", ""), "142.251.1.1"))
        self.assertFalse(m.ignore_row("IN UDP volumetrico", "out", ("45.238.170.10", ""), "142.251.1.1"))
        self.assertTrue(m.ignore_row("OUT UDP flood", "out", ("187.87.201.53", ""), "1.1.1.1"))
        self.assertFalse(m.ignore_row("IN UDP volumetrico", "in", ("187.87.201.53", ""), "1.1.1.1"))
        self.assertTrue(m.ignore_row("x", "in", ("1.2.3.4", ""), "2001:db8::5"))
        self.assertFalse(m.ignore_row("x", "in", ("1.2.3.4", ""), "2001:db9::5"))
        self.assertFalse(m.ignore_row("x", "in", ("1.2.3.4", ""), "not-an-ip"))
        self.assertEqual(m.multiplier("IN UDP volumetrico", "in", "45.238.170.10"), 4)
        self.assertEqual(m.multiplier("IN UDP volumetrico", "in", "45.238.170.11"), 1)
        self.assertFalse(ex.Matcher())

    def test_overlapping_ranges_merge(self):
        m = matcher({"cidrs": ["10.0.0.0/24", "10.0.0.128/25", "10.0.1.0/24", "10.0.5.0/24"]})
        for ip, hit in (("10.0.0.200", True), ("10.0.1.255", True), ("10.0.2.1", False), ("10.0.5.9", True)):
            self.assertEqual(m.ignore_row("r", "in", (), ip), hit, ip)


class FetchTests(unittest.TestCase):
    def test_ripestat_parse(self):
        payload = {"data": {"prefixes": [{"prefix": "8.8.8.0/24"}, {"prefix": "2001:4860::/32"},
                                         {"prefix": "0.0.0.0/0"}, {"prefix": "lixo"}, {"prefix": "8.8.8.0/24"}]}}

        class Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        seen = []

        def opener(req, timeout):
            seen.append(req.full_url)
            return Resp(json.dumps(payload).encode())
        self.assertEqual(ex.fetch_asn(15169, opener), ["2001:4860::/32", "8.8.8.0/24"])
        self.assertIn("resource=AS15169", seen[0])
        with self.assertRaises(ex.ExceptionError):
            ex.fetch_asn(1, lambda req, timeout: Resp(b'{"data": {"prefixes": []}}'))


class DetectorTests(unittest.TestCase):
    def test_remote_exception_removes_cdn_traffic(self):
        from fmn_filters.bidir_detector import evaluate
        rule = RULES["IN UDP volumetrico"]
        data = rows(pps=80000, mbps=800, remote_prefix="142.250.1.")
        self.assertEqual(len(evaluate(data, rule, START)), 1)
        m = matcher({"cidrs": ["142.250.0.0/15"], "direction": "in"})
        self.assertEqual(evaluate(data, rule, START, m), [])
        mixed = data + rows(pps=80000, mbps=800, remote_prefix="203.0.113.")
        self.assertEqual(len(evaluate(mixed, rule, START, m)), 1)        # o resto continua contando

    def test_multiplier_and_dynamic_limit(self):
        from fmn_filters.bidir_detector import evaluate
        rule = RULES["IN UDP volumetrico"]                               # dedicado: 50k pps / 400 Mbps
        small = rows(pps=20000, mbps=150)
        self.assertEqual(evaluate(small, rule, START), [])
        cfg = dict(CFG, dynamic_thresholds={"enabled": True, "factor": 2.0, "min_days": 3, "floor_ratio": 0.25,
                                            "timezone": "UTC"})
        hour = START.hour
        table = {(rule["name"], "dedicated", "wke" if START.weekday() >= 5 else "wkd", hour, m): (v, 5)
                 for m, v in (("min_pps", 5000.0), ("min_mbps", 50.0))}
        dyn = bl.Limits(validate_config(json.loads(json.dumps(cfg))), table)
        found = evaluate(small, rule, START, None, dyn)
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0]["details"]["dynamic_limit"])
        self.assertEqual(found[0]["details"]["limits"], {"min_pps": 12500.0, "min_mbps": 100.0})   # piso 25%
        m = matcher({"cidrs": ["45.238.170.10/32"], "side": "local", "action": "multiply", "factor": 3})
        self.assertEqual(evaluate(small, rule, START, m, dyn), [])        # 3 x 12500 > 20000
        big = rows(pps=160000, mbps=1300)
        self.assertEqual(evaluate(big, rule, START, m)[0]["details"]["limit_multiplier"], 3)
        few = {k: (v[0], 2) for k, v in table.items()}                    # menos dias que min_days: vale o fixo
        self.assertEqual(evaluate(small, rule, START, None, bl.Limits({"dynamic_thresholds": dyn.st}, few)), [])


class BaselineTests(unittest.TestCase):
    def test_settings_and_effective(self):
        st = bl.validate_settings({"enabled": True})
        self.assertEqual(st["factor"], 2.0)
        for bad in ({"factor": 50}, {"min_days": 0}, {"floor_ratio": 2}, {"timezone": "Marte/Base"}, {"x": 1},
                    {"enabled": "sim"}):
            with self.assertRaises(ValueError):
                bl.validate_settings(bad)
        static = {"min_pps": 50000, "min_mbps": 400, "min_remote_ips": 8}
        table = {("R", "dedicated", "wkd", 3, "min_pps"): (8000.0, 4), ("R", "dedicated", "wkd", 20, "min_pps"): (40000.0, 4)}
        lim, dyn = bl.effective("R", "dedicated", static, ("wkd", 3), table, st)
        self.assertEqual((lim["min_pps"], lim["min_mbps"], lim["min_remote_ips"], dyn), (16000.0, 400, 8, True))
        lim, dyn = bl.effective("R", "dedicated", static, ("wkd", 20), table, st)
        self.assertEqual((lim["min_pps"], dyn), (50000, False))           # nunca acima do fixo
        self.assertEqual(bl.slot(datetime(2026, 11, 1, 2, 30), "America/Bahia"), ("wke", 23))   # sab 23h local

    def test_calibrator_baseline_rows_and_offenders(self):
        cfg = validate_config(dict(json.loads(json.dumps(CFG)), dynamic_thresholds={"timezone": "UTC"}))
        cal = Calibrator(cfg, exc=matcher({"cidrs": ["45.238.170.99/32"], "side": "local", "action": "multiply",
                                           "factor": 5}))
        for m in range(120):                                              # 00h e 01h UTC de um domingo
            for n in range(3):
                cal.add(row(m, ip="45.238.170.%d" % (10 + n), pps=1000.0 if m < 60 else 3000.0))
            cal.add(row(m, ip="45.238.170.99", pps=900000.0, mbps=5000))  # perfil proprio: fora da base
            cal.add(row(m, ip="45.238.170.50", pps=60000.0, mbps=500))   # estoura sempre
        summary, _ = cal.finish()
        base = {(r[0], r[1], r[2], r[3], r[4]): r for r in summary["linha_de_base"]}
        h0 = base[("IN UDP volumetrico", "dedicated", "wke", 0, "min_pps")]
        h1 = base[("IN UDP volumetrico", "dedicated", "wke", 1, "min_pps")]
        self.assertEqual(h0[7], 240)                                      # 4 IPs x 60 min (sem o .99)
        self.assertEqual(h0[6], 1000.0)
        self.assertEqual(h1[6], 3000.0)
        self.assertEqual(h0[5], 60000.0)
        top = [e for e in summary["regras"] if e["regra"] == "IN UDP volumetrico" and e["escopo"] == "dedicated"][0]
        self.assertEqual(top["reincidentes"][0]["entidade"], "45.238.170.50")


class UsualTests(unittest.TestCase):
    def test_above_usual(self):
        t = datetime(2026, 11, 1, 3, 0)
        _, _, d = fr.validate("Habitual", "any", {"conditions": [{"metric": "mbps", "op": "above_usual", "value": 200,
                                                                  "window": 7}]})
        self.assertEqual(d["retention_days"], 8)
        self.assertIn("acima do habitual (mesmo horário, 7 dia(s))", fr.describe(d))
        usual = [{"t": t - timedelta(days=k, minutes=j), "bps": 10e6, "pps": 1, "flows": 1, "bpp": 1}
                 for k in range(1, 5) for j in range(-10, 11)]
        s = lambda mbps: {"bps": mbps * 1e6, "pps": 1, "flows": 1, "bpp": 1}
        self.assertTrue(fr.check(d, s(31), [], usual, t))
        self.assertFalse(fr.check(d, s(29), [], usual, t))
        self.assertFalse(fr.check(d, s(31), [], usual[:30], t))           # menos da metade dos dias
        self.assertFalse(fr.check(d, s(31), [], None, t))
        with self.assertRaises(fr.RuleError):
            fr.validate("x y z", "any", {"conditions": [{"metric": "mbps", "op": "above_usual", "value": 50,
                                                         "window": 40}]})


@unittest.skipUnless(DB_ENABLED, "defina ORBYMON_TEST_DB=1 e ORBYMON_DB_*")
class DbTests(unittest.TestCase):
    def setUp(self):
        from fmn_filters.mysql_sink import connection_from_env
        self.db = connection_from_env()
        cur = self.db.cursor()
        cur.execute("DELETE FROM orby_baseline WHERE rule_name LIKE 'teste %%'")
        cur.execute("DELETE FROM orby_exception_prefixes")
        cur.execute("DELETE FROM orby_exceptions")
        self.db.commit()

    def tearDown(self):
        cur = self.db.cursor()
        cur.execute("DELETE FROM orby_baseline WHERE rule_name LIKE 'teste %%'")
        cur.execute("DELETE FROM orby_exception_prefixes")
        cur.execute("DELETE FROM orby_exceptions")
        self.db.commit()
        self.db.close()

    def test_merge_moving_average_once_per_day(self):
        cur = self.db.cursor()
        r = lambda v: [("teste R", "dedicated", "wkd", 3, "min_pps", v, v / 2, 100)]
        self.assertEqual(bl.merge(cur, r(1000.0), date(2026, 11, 2)), 1)
        self.assertEqual(bl.merge(cur, r(9999.0), date(2026, 11, 2)), 0)    # mesmo dia: ignorado
        bl.merge(cur, r(2000.0), date(2026, 11, 3))
        self.db.commit()
        t = bl.load(cur)
        self.assertEqual(t[("teste R", "dedicated", "wkd", 3, "min_pps")], (1500.0, 2))

    def test_sync_and_load(self):
        cur = self.db.cursor()
        cur.execute("INSERT INTO orby_exceptions (kind,value,side,direction,action) VALUES ('asn','15169','remote','in','ignore')")
        cur.execute("INSERT INTO orby_exceptions (kind,value,side,direction,action,expires_at) VALUES "
                    "('cidr','9.9.9.0/24','remote','any','ignore', UTC_TIMESTAMP() - INTERVAL 1 DAY)")
        self.db.commit()
        calls = []

        def fake(asn, opener=None):
            calls.append(asn)
            return ["142.250.0.0/15", "2001:4860::/32"]
        orig = ex.fetch_asn
        ex.fetch_asn = fake
        try:
            self.assertEqual(ex.sync(self.db, log=lambda *a: None), 1)
            self.assertEqual(ex.sync(self.db, log=lambda *a: None), 0)       # recente: nao repete
        finally:
            ex.fetch_asn = orig
        m = ex.load(self.db.cursor())
        self.assertTrue(m.ignore_row("r", "in", (), "142.251.3.4"))
        self.assertFalse(m.ignore_row("r", "out", (), "142.251.3.4"))
        self.assertFalse(m.ignore_row("r", "in", (), "9.9.9.9"))            # vencida


if __name__ == "__main__":
    unittest.main()
