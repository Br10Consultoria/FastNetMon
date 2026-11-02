"""Agregados dos dashboards: mesmas somas do detalhado, IPs/remotos distintos e gravacao no MariaDB."""
from datetime import datetime
import os
from pathlib import Path
import unittest

from fmn_filters import flow_rollup as fr

from test_flow_rollup import flow, run

DB_ENABLED = os.environ.get("ORBYMON_TEST_DB") == "1" and os.environ.get("ORBYMON_DB_USER")


def sample():
    recs = [flow("203.0.113.%d" % i, "187.87.201.40", 53, 40000 + i, packets=10, nbytes=10000) for i in range(1, 6)]
    recs.append(flow("187.87.201.40", "198.51.100.9", 40000, 22, proto="tcp", packets=4, nbytes=400, flags="S"))
    recs.append(flow("100.64.65.10", "198.51.100.9", 40001, 22, proto="tcp", packets=6, nbytes=600, flags="S"))
    rows, _ = run(recs)
    return rows


class AggregateTests(unittest.TestCase):
    def test_sums_match_detail(self):
        rows = sample()
        a = fr.aggregates(rows)
        total = sum(r[13] for r in rows)
        self.assertAlmostEqual(sum(x[6] for x in a["agg"]), total)
        self.assertAlmostEqual(sum(x[7] for x in a["ip"]), total)
        self.assertAlmostEqual(sum(x[6] for x in a["port"]), total)
        self.assertAlmostEqual(sum(x[5] for x in a["remote"]), total)
        dedicated_in = [x for x in a["ip"] if x[2] == "in" and x[4] == "187.87.201.40"][0]
        self.assertEqual(dedicated_in[-1], 5)                                 # 5 remotos distintos
        ssh = [x for x in a["remote"] if x[4] == "198.51.100.9"][0]
        self.assertEqual(ssh[-1], 2)                                          # 2 IPs nossos envolvidos
        self.assertTrue(all(x[1].minute % 5 == 0 for x in a["port"] + a["remote"]))
        edges = {(x[2], x[5]) for x in a["agg"]}
        self.assertIn(("in", 101), edges)                                     # entrada do recebido
        self.assertIn(("out", 202), edges)                                    # saida do originado


@unittest.skipUnless(DB_ENABLED, "defina ORBYMON_TEST_DB=1 e ORBYMON_DB_*")
class DbTests(unittest.TestCase):
    def test_two_files_same_minute_add_up(self):
        from fmn_filters.mysql_sink import connection_from_env
        db = connection_from_env()
        try:
            c = db.cursor()
            for t in ("orby_flow_agg_minute", "orby_flow_ip_minute", "orby_flow_port_5m", "orby_flow_remote_5m",
                      "orby_flow_minute"):
                c.execute("DELETE FROM " + t + " WHERE source='huawei' AND bucket_utc BETWEEN '2026-10-30 11:55' "
                          "AND '2026-10-30 12:05'")
            c.execute("DELETE FROM orby_flow_ingested_files WHERE file_name LIKE 'nfcapd.aggtest%%'")
            db.commit()
            rows = sample()

            class St:
                st_size, st_mtime_ns = 1, 1
            for name in ("nfcapd.aggtest1", "nfcapd.aggtest2"):            # dois arquivos de 30 s no mesmo minuto
                self.assertTrue(fr.save_file(db, "huawei", Path(name), St, rows, {"fluxos": 7}))
            c.execute("SELECT SUM(packets) FROM orby_flow_agg_minute WHERE source='huawei' AND bucket_utc='2026-10-30 12:00'")
            self.assertAlmostEqual(c.fetchone()[0], 2 * sum(r[13] for r in rows))
            c.execute("SELECT remotes FROM orby_flow_ip_minute WHERE local_ip='187.87.201.40' AND direction='in' "
                      "AND bucket_utc='2026-10-30 12:00'")
            self.assertEqual(c.fetchone()[0], 5)                             # maior entre arquivos, nao soma
            c.execute("SELECT SUM(bytes) FROM orby_flow_minute WHERE source='huawei' AND bucket_utc='2026-10-30 12:00'")
            detail = c.fetchone()[0]
            c.execute("SELECT SUM(bytes) FROM orby_flow_port_5m WHERE source='huawei' AND bucket_utc='2026-10-30 12:00'")
            self.assertAlmostEqual(c.fetchone()[0], detail)
        finally:
            c = db.cursor()
            for t in ("orby_flow_agg_minute", "orby_flow_ip_minute", "orby_flow_port_5m", "orby_flow_remote_5m",
                      "orby_flow_minute"):
                c.execute("DELETE FROM " + t + " WHERE source='huawei' AND bucket_utc BETWEEN '2026-10-30 11:55' "
                          "AND '2026-10-30 12:05'")
            c.execute("DELETE FROM orby_flow_ingested_files WHERE file_name LIKE 'nfcapd.aggtest%%'")
            db.commit()
            db.close()




class FakeCur:
    def __init__(self, db):
        self.db = db
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False
    def execute(self, sql, params=None):
        if sql.startswith("SELECT MIN"):
            return
        self.db.calls.append(params[1])
        if params[1] in self.db.fail_at:
            self.db.fail_at[params[1]] -= 1
            if self.db.fail_at[params[1]] >= 0:
                raise RuntimeError("timeout")
    def fetchone(self):
        return (datetime(2026, 11, 1, 0, 3),)


class FakeDb:
    def __init__(self, fail_at=None):
        self.calls, self.fail_at, self.closed = [], dict(fail_at or {}), 0
    def cursor(self):
        return FakeCur(self)
    def commit(self):
        pass
    def rollback(self):
        pass
    def close(self):
        self.closed += 1


class BackfillTests(unittest.TestCase):
    def test_blocks_of_15_min_aligned_to_5(self):
        db = FakeDb()
        done, skipped = fr.backfill(db, "huawei", datetime(2026, 11, 1, 1, 2), log=lambda m: None)
        # 00:00 .. 01:00 em blocos de 15 min
        self.assertEqual((done, skipped), (4, 0))
        self.assertEqual(sorted(set(db.calls)), [datetime(2026, 11, 1, 0, m) for m in (0, 15, 30, 45)])

    def test_retries_then_skips_and_continues(self):
        bad = datetime(2026, 11, 1, 0, 15)
        db = FakeDb({bad: 5})                               # falha sempre nesse bloco
        logs = []
        done, skipped = fr.backfill(db, "huawei", datetime(2026, 11, 1, 1, 0), log=logs.append,
                                    reconnect=lambda: db)
        self.assertEqual((done, skipped), (3, 1))
        self.assertTrue(any(m.startswith("PULADO") for m in logs))

    def test_retry_succeeds(self):
        bad = datetime(2026, 11, 1, 0, 30)
        db = FakeDb({bad: 1})                               # falha so na primeira tentativa
        done, skipped = fr.backfill(db, "huawei", datetime(2026, 11, 1, 1, 0), log=lambda m: None,
                                    reconnect=lambda: db)
        self.assertEqual((done, skipped), (4, 0))


if __name__ == "__main__":
    unittest.main()
