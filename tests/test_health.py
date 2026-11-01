"""Saude: verificacoes, tempo de execucao, transicoes de aviso."""
from collections import namedtuple
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

from fmn_filters import health as h

ROOT = Path(__file__).resolve().parent.parent
CFG = json.loads((ROOT / "rules" / "bidir.example.json").read_text())
DB_ENABLED = os.environ.get("ORBYMON_TEST_DB") == "1" and os.environ.get("ORBYMON_DB_USER")


class FileChecks(unittest.TestCase):
    def test_nfcapd_age(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(h.check_nfcapd(d)["status"], h.CRIT)              # nenhum arquivo
            f = Path(d) / "nfcapd.20261101120000"
            f.write_bytes(b"x")
            now = time.time()
            os.utime(f, (now - 60, now - 60))
            self.assertEqual(h.check_nfcapd(d, now)["status"], h.OK)
            self.assertEqual(h.check_nfcapd(d, now + 200)["status"], h.WARN)
            self.assertEqual(h.check_nfcapd(d, now + 400)["status"], h.CRIT)
        self.assertEqual(h.check_nfcapd("/nao/existe")["status"], h.CRIT)

    def test_disks_dedupe_and_thresholds(self):
        U = namedtuple("U", "total used free")
        S = namedtuple("S", "st_dev")
        usage = {"/": U(100, 50, 50), "/var/lib/orbymon": U(100, 90, 10), "/var/log/orbymon": U(100, 95, 5)}
        devs = {"/": 1, "/var/lib/orbymon": 2, "/var/log/orbymon": 3, "/var/lib/mysql": 1}
        out = h.check_disks(usage=lambda p: usage[p], stat=lambda p: S(devs[p]))
        self.assertEqual([(i["key"], i["status"]) for i in out],
                         [("disk:/", h.OK), ("disk:/var/lib/orbymon", h.WARN), ("disk:/var/log/orbymon", h.CRIT)])


class BackupChecks(unittest.TestCase):
    def test_backup_age(self):
        self.assertEqual(h.check_backup("/nao/existe")["status"], h.WARN)
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(h.check_backup(d)["value"], "nenhum backup ainda")
            f = Path(d) / "orbymon-backup-20261101-033700.tar.gz.enc"
            f.write_bytes(b"x")
            (Path(d) / "outro.txt").write_bytes(b"x")
            now = time.time()
            os.utime(f, (now - 3600, now - 3600))
            ok = h.check_backup(d, now)
            self.assertEqual((ok["status"], ok["value"]), (h.OK, "último há 60 min (1 arquivo(s), cifrado)"))
            self.assertEqual(h.check_backup(d, now + 2 * 86400)["status"], h.WARN)
            self.assertEqual(h.check_backup(d, now + 5 * 86400)["status"], h.CRIT)


class SystemdChecks(unittest.TestCase):
    def test_failed_units_and_runtime(self):
        self.assertEqual(h.check_failed_units(lambda a: "")["status"], h.OK)
        bad = h.check_failed_units(lambda a: "orbymon-bidir-huawei.service loaded failed failed X\n")
        self.assertEqual((bad["status"], bad["value"]), (h.CRIT, "1 com falha"))
        self.assertEqual(h.check_failed_units(lambda a: None)["status"], h.UNKNOWN)

        def show(args):
            unit = args[1]
            if unit == "orbymon-bidir-huawei.service":
                return "LoadState=loaded\nExecMainStartTimestampMonotonic=1000000\nExecMainExitTimestampMonotonic=" \
                       "51000000\nActiveState=inactive\n"
            if unit == "orbymon-flow-rollup-huawei.service":
                return "LoadState=loaded\nExecMainStartTimestampMonotonic=1000000\nExecMainExitTimestampMonotonic=" \
                       "6000000\nActiveState=inactive\n"
            return "LoadState=not-found\n"
        out = {i["key"]: i for i in h.check_runtimes(run=show)}
        self.assertEqual(out["runtime:bidir-huawei"]["status"], h.WARN)          # 50 s num timer de 60 s
        self.assertIn("50.0 s", out["runtime:bidir-huawei"]["value"])
        self.assertEqual(out["runtime:flow-rollup-huawei"]["status"], h.OK)
        self.assertEqual(len(out), 2)


class DecimalTests(unittest.TestCase):
    def test_mariadb_decimal_sums_and_broken_check(self):
        from decimal import Decimal

        class Cur:
            def __init__(self):
                self.sql = ""

            def execute(self, sql, params=()):
                self.sql = sql

            def fetchone(self):
                if "SUM(nat_resolved)" in self.sql:
                    return (Decimal("900"), Decimal("100"))
                if "COUNT(*)" in self.sql:
                    return (Decimal("0"),)
                if "SUM(DATA_LENGTH" in self.sql:
                    return (Decimal("2500000000"),)
                return (None,)

            def fetchall(self):
                if "information_schema" in self.sql:
                    return [("orby_flow_minute", Decimal("2000000000"), Decimal("12345678"))]
                return []
        out = {i["key"]: i for i in h.check_db(Cur(), CFG, datetime(2026, 11, 1, 12), telegram_on=True)}
        self.assertEqual(out["nat_resolve"]["value"], "90%")
        self.assertEqual(out["telegram"]["status"], h.OK)
        self.assertEqual(out["db_size"]["value"], "2.5 GB")

        class BrokenDb:
            def cursor(self):
                raise RuntimeError("conexao caiu")
        with tempfile.TemporaryDirectory() as d:
            items = h.collect(BrokenDb(), CFG, d, datetime(2026, 11, 1, 12), run=lambda a: "", disks=("/",))
        keys = {i["key"]: i["status"] for i in items}
        self.assertEqual(keys["db"], h.UNKNOWN)
        self.assertIn("disk:/", keys)


class MessageTests(unittest.TestCase):
    def test_message(self):
        a = h.item("nfcapd", "Coleta <NetStream>", h.CRIT, "último arquivo há 10 min", "parou")
        r = h.item("disk:/", "Disco /", h.OK, "50% usado")
        text = h.message([a], [r], [], site="POP1")
        self.assertIn("🔴 [POP1] <b>Saúde do OrbyFlow: problema</b>", text)
        self.assertIn("Coleta &lt;NetStream&gt;", text)
        self.assertIn("🟢", text)
        self.assertEqual(h.message([], [], []), "")


@unittest.skipUnless(DB_ENABLED, "defina ORBYMON_TEST_DB=1 e ORBYMON_DB_*")
class SaveTests(unittest.TestCase):
    def setUp(self):
        from fmn_filters.mysql_sink import connection_from_env
        self.db = connection_from_env()
        self.db.cursor().execute("DELETE FROM orby_health")
        self.db.commit()

    def tearDown(self):
        self.db.cursor().execute("DELETE FROM orby_health")
        self.db.commit()
        self.db.close()

    def test_confirm_notify_remind_recover(self):
        t = datetime(2026, 11, 1, 12, 0)
        bad = [h.item("rollup", "Rollup", h.CRIT, "10 min")]
        good = [h.item("rollup", "Rollup", h.OK, "1 min")]
        self.assertEqual(h.save(self.db, bad, t), ([], [], []))                 # 1a vez: ainda nao confirma
        alerts, rec, rem = h.save(self.db, bad, t + timedelta(minutes=2))
        self.assertEqual([a["key"] for a in alerts], ["rollup"])
        self.assertEqual(alerts[0]["since"], t)
        self.assertEqual(h.save(self.db, bad, t + timedelta(minutes=4)), ([], [], []))
        _, _, rem = h.save(self.db, bad, t + timedelta(hours=2, minutes=3))
        self.assertEqual(len(rem), 1)                                          # lembrete de critico
        _, rec, _ = h.save(self.db, good, t + timedelta(hours=3))
        self.assertEqual([r["key"] for r in rec], ["rollup"])
        self.assertEqual(h.save(self.db, good, t + timedelta(hours=3, minutes=2)), ([], [], []))
        h.save(self.db, [h.item("rollup", "Rollup", h.WARN, "x")], t + timedelta(hours=4))   # oscilacao unica
        self.assertEqual(h.save(self.db, good, t + timedelta(hours=4, minutes=2)), ([], [], []))

    def test_collect_with_db(self):
        cfg = dict(CFG, a10_sources=["10.100.10.10"])
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "huawei").mkdir()
            items = h.collect(self.db, cfg, d, datetime.now(timezone.utc).replace(tzinfo=None), telegram_on=True, run=lambda a: "", disks=("/",))
        keys = {i["key"] for i in items}
        for k in ("nfcapd", "rollup", "detector", "nat", "filter_rules", "telegram", "disk:/", "services"):
            self.assertIn(k, keys)


if __name__ == "__main__":
    unittest.main()
