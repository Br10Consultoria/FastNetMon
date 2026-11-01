"""Analise avancada: filtro nfdump com atalhos do provedor sobre arquivos nfcapd reais (fixture)."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
import unittest

from fmn_filters import flow_query as fq
from fmn_filters.bidir_config import build_scopes

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "nfcapd.20261101120000"
CFG = json.loads((ROOT / "rules" / "bidir.example.json").read_text())
PROFILE = json.loads((ROOT / "rules" / "cgnat-profiles.a10.json").read_text())
HAVE_NFDUMP = os.path.exists(fq.NFDUMP)


def flow_dir(tmp):
    d = Path(tmp) / "huawei"
    d.mkdir(parents=True)
    shutil.copy(FIXTURE, d / FIXTURE.name)
    now = time.time() - 60
    os.utime(d / FIXTURE.name, (now, now))
    (d / "nfcapd.current.1234").write_text("x")        # arquivo em gravacao: ignorado
    return d


class ExpandTests(unittest.TestCase):
    def setUp(self):
        self.t = fq.macros(CFG, PROFILE)

    def test_macros(self):
        self.assertEqual(fq.expand("@dst_rede and proto udp", self.t),
                         "(dst net 45.238.170.0/23 or dst net 187.87.201.0/24 or dst net 2804:4fa8::/32) and proto udp")
        self.assertIn("src net 45.238.170.64/26", fq.expand("@src_pools", self.t))
        self.assertEqual(fq.expand("proto icmpv6", self.t), "proto 58")

    def test_rejects(self):
        for bad in ("", "any; reboot", "any `id`", "any $(id)", "a\nb", "x" * 5000, "@nada"):
            with self.assertRaises(fq.QueryError):
                fq.expand(bad, self.t)


@unittest.skipUnless(HAVE_NFDUMP, "nfdump ausente")
class RunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.dir = flow_dir(self.tmp)
        self.t = fq.macros(CFG, PROFILE)
        self.end = datetime.now(timezone.utc).replace(tzinfo=None)
        self.start = self.end - timedelta(minutes=30)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def q(self, expr, mode="dstip", order="bytes", limit=10, **kw):
        return fq.run(expr, kw.get("start", self.start), kw.get("end", self.end), mode, order, limit,
                      self.dir, self.t, lock_path=os.path.join(self.tmp, "lock"))

    def test_top_destinations_with_macro_and_tags(self):
        r = self.q("@dst_rede")
        fq.annotate(r, build_scopes(CFG, PROFILE), {334: "Vlanif2511"})
        self.assertEqual(r.files, 1)
        self.assertEqual(r.rows[0]["IP de destino"], "45.238.170.70")
        self.assertEqual(r.rows[0]["_tags"]["IP de destino"], "pool NAT-POOL-08")
        self.assertGreater(float(r.summary["bytes"]), 0)
        self.assertEqual(len(r.series), 1)
        self.assertTrue(fq.svg_series(r.series * 3).startswith("<svg"))

    def test_outbound_ssh_syn_from_pools(self):
        r = self.q("@src_pools and proto tcp and dst port 22 and flags S and not flags AFRPU", mode="srcip")
        self.assertEqual([x["IP de origem"] for x in r.rows], ["45.238.170.71"])

    def test_flows_and_interfaces(self):
        r = self.q("proto udp and dst port 0", mode="flows", limit=3)
        fq.annotate(r, None, {334: "Vlanif2511"})
        self.assertEqual(len(r.rows), 3)
        self.assertEqual(r.rows[0]["Proto"], "udp")
        self.assertEqual(r.rows[0]["_tags"]["Entrada"], "Vlanif2511")
        r = self.q("any", mode="inif")
        self.assertIn("334", [x["Interface de entrada"] for x in r.rows])

    def test_errors(self):
        with self.assertRaises(fq.QueryError) as ctx:
            self.q("dst ip 1.2.3")
        self.assertIn("nfdump", str(ctx.exception))
        with self.assertRaises(fq.QueryError):
            self.q("any", start=self.end - timedelta(hours=30))
        with self.assertRaises(fq.QueryError):
            self.q("any", mode="flows", start=self.end - timedelta(hours=7))
        r = self.q("any", start=self.end - timedelta(days=3), end=self.end - timedelta(days=2, hours=12))
        self.assertTrue(r.notes)                       # sem arquivos no periodo

    def test_lock_blocks_concurrent_query(self):
        import fcntl
        with open(os.path.join(self.tmp, "lock"), "a") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            with self.assertRaises(fq.QueryError):
                self.q("any")

    def test_builtin_filters_are_valid(self):
        import re
        sql = (ROOT / "sql" / "saved_filters.sql").read_text()
        exprs = re.findall(r"^\('[^']+','([^']+)'", sql, re.M)
        self.assertGreaterEqual(len(exprs), 15)
        for expr in exprs:
            self.q(expr, mode="proto", limit=1)     # nfdump aceita a sintaxe (levanta QueryError se nao)


if __name__ == "__main__":
    unittest.main()
