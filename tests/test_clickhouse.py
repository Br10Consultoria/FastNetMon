"""ClickHouse: schema, gravacao com deduplicacao, spool em falha e consultas do detalhe de ataque.
Usa o chdb (motor do ClickHouse embutido) quando instalado: pip install chdb."""
from datetime import datetime, timedelta
import gzip
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from fmn_filters import clickhouse as ch
from fmn_filters import attacks as at

try:
    from chdb import session as chs
    HAVE_CHDB = True
except ImportError:
    HAVE_CHDB = False


def chdb_transport(sess):
    def send(sql, params, settings, data):
        st = ""
        if settings:
            st = " SETTINGS " + ", ".join("%s=%s" % (k, repr(str(v)) if not str(v).isdigit() else v)
                                          for k, v in settings.items())
        if data is not None:
            head, fmt = sql.split(" FORMAT ")
            q = head + st + " FORMAT " + fmt + "\n" + data.decode()
            sess.query(q)
            return b""
        if " FORMAT " in sql:
            head, fmt = sql.rsplit(" FORMAT ", 1)
            sql = head + st + " FORMAT " + fmt
        else:
            sql += st
        res = sess.query(sql, params=params) if params else sess.query(sql)
        return str(res).encode() if res is not None else b""
    return send


def row(bucket, remote, lport=40000, rport=53, packets=2048.0, local="187.87.201.40", sub="187.87.201.40",
        scope="dedicated", direction="in", proto="udp"):
    return ("huawei", bucket, direction, scope, "", local, sub, remote, proto, lport, rport, 10, 20, packets,
            packets * 500, 0.0, 0.0, 1)


class EncodeTests(unittest.TestCase):
    def test_tsv_escaping_and_dates(self):
        out = ch.encode_rows([("a\tb", datetime(2026, 11, 1, 10, 5), 1.5, 3, "x\\y\n")]).decode()
        self.assertEqual(out, "a\\tb\t2026-11-01 10:05:00\t1.5\t3\tx\\\\y\\n\n")

    def test_schema_limits(self):
        self.assertIn("INTERVAL 45 DAY", ch.schema(45)[1])
        with self.assertRaises(ValueError):
            ch.schema(0)
        with self.assertRaises(ValueError):
            ch.schema(30, "x; DROP")

    def test_client_requires_local_url(self):
        self.assertIsNone(ch.Client.from_env({}))
        with self.assertRaises(ch.ClickHouseError):
            ch.Client.from_env({"ORBYMON_CH_URL": "http://10.0.0.5:8123"})
        c = ch.Client.from_env({"ORBYMON_CH_URL": "http://127.0.0.1:8123/", "ORBYMON_CH_USER": "u",
                                "ORBYMON_CH_PASSWORD": "p"})
        self.assertEqual((c.url, c.user), ("http://127.0.0.1:8123", "u"))


class SpoolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_failure_goes_to_spool_and_is_resent_with_same_token(self):
        calls = []
        state = {"down": True}

        def transport(sql, params, settings, data):
            if state["down"]:
                raise ch.ClickHouseError("ClickHouse inacessivel")
            calls.append((sql, settings, data))
            return b""
        sink = ch.Sink(ch.Client("http://127.0.0.1:8123", "u", "p", transport=transport), spool_dir=self.tmp,
                       log=lambda m: None)
        rows = [row(datetime(2026, 11, 1, 10, 0), "203.0.113.5")]
        self.assertFalse(sink.write("huawei:nfcapd.1:10:20", rows))
        self.assertEqual(sink.pending(), 1)
        self.assertEqual(sink.flush_spool(), 0)                      # ainda fora: fica guardado
        self.assertEqual(sink.pending(), 1)
        state["down"] = False
        self.assertEqual(sink.flush_spool(), 1)
        self.assertEqual(sink.pending(), 0)
        self.assertEqual(calls[0][1], {"insert_deduplication_token": "huawei:nfcapd.1:10:20"})
        self.assertIn(b"203.0.113.5", calls[0][2])

    def test_spool_is_trimmed(self):
        sink = ch.Sink(ch.Client("http://127.0.0.1:8123", "u", "p", transport=lambda *a: (_ for _ in ()).throw(
            ch.ClickHouseError("x"))), spool_dir=self.tmp, log=lambda m: None, max_bytes=1)
        sink.write("t1", [row(datetime(2026, 11, 1, 10, 0), "203.0.113.5")])
        self.assertEqual(sink.pending(), 0)                          # acima do limite: descartado


@unittest.skipUnless(HAVE_CHDB, "chdb nao instalado")
class ChdbTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.sess = chs.Session(str(cls.tmp / "db"))
        for sql in ch.schema(30):
            cls.sess.query(sql)
        cls.client = ch.Client("http://127.0.0.1:8123", "u", "p", transport=chdb_transport(cls.sess))
        cls.sink = ch.Sink(cls.client, spool_dir=cls.tmp / "spool", log=lambda m: None)
        t0 = datetime(2026, 11, 1, 10, 0)
        rows = []
        for m in range(5):
            for i in range(1, 30):
                rows.append(row(t0 + timedelta(minutes=m), "203.0.113.%d" % i))
        rows.append(row(t0, "198.51.100.9", lport=40001, rport=23, direction="out", proto="tcp",
                        local="45.238.170.10", sub="100.64.65.10", scope="cgnat_private"))
        cls.sink.write("huawei:f1:1:1", rows)
        cls.sink.write("huawei:f1:1:1", rows)                          # repetido: o ClickHouse descarta
        cls.t0 = t0

    @classmethod
    def tearDownClass(cls):
        cls.sess.close()
        shutil.rmtree(cls.tmp)

    def test_dedup_and_status(self):
        st = ch.status(self.client)
        self.assertEqual(int(st["linhas"]), 5 * 29 + 1)

    def test_detail_queries(self):
        fl = at.ClickFlows(self.client)
        self.assertEqual(fl.since(), self.t0)
        k = {"direction": "in", "entity_col": "local_ip", "entity": "187.87.201.40", "protocol": "udp",
             "local_port": 0, "remote_port": 53}
        d = fl.detail(k, self.t0, self.t0 + timedelta(minutes=5))
        self.assertEqual(int(d["totais"]["remotos"]), 29)
        self.assertEqual(len(d["minutos"]), 5)
        self.assertIsInstance(d["minutos"][0]["bucket"], datetime)
        self.assertEqual(d["portas"][0]["remote_port"], 53)
        self.assertEqual(d["conversas"][0]["protocol"], "udp")
        one = fl.detail(k, self.t0, self.t0 + timedelta(minutes=5), remote="203.0.113.7")
        self.assertEqual(int(one["totais"]["remotos"]), 1)

    def test_cgnat_subscriber_and_remote_search(self):
        fl = at.ClickFlows(self.client)
        k = {"direction": "out", "entity_col": "subscriber_ip", "entity": "100.64.65.10", "protocol": "tcp",
             "local_port": 0, "remote_port": 23}
        d = fl.detail(k, self.t0, self.t0 + timedelta(minutes=1))
        self.assertEqual(d["outros"][0]["ip"], "45.238.170.10")          # IP publico usado
        self.assertEqual(fl.locals_for_remote("198.51.100.9", self.t0, self.t0 + timedelta(minutes=1)),
                         {"45.238.170.10", "100.64.65.10"})

    def test_pick_backend_prefers_covering_clickhouse(self):
        class Maria:
            name = "m"

            def since(self):
                return datetime(2026, 11, 1, 9, 0)
        fl = at.ClickFlows(self.client)
        b, s = at.pick_backend(Maria(), fl, self.t0)
        self.assertIs(b, fl)
        b, s = at.pick_backend(Maria(), fl, datetime(2026, 11, 1, 9, 30))   # so o MariaDB cobre
        self.assertEqual(b.name, "m")


class HealthTests(unittest.TestCase):
    def test_spool_age(self):
        from fmn_filters import health
        tmp = Path(tempfile.mkdtemp())
        try:
            self.assertEqual(health.check_clickhouse(tmp / "nao-existe"), [])
            self.assertEqual(health.check_clickhouse(tmp)[0]["status"], health.OK)
            f = tmp / "a.tsv.gz"
            f.write_bytes(b"x")
            mt = f.stat().st_mtime
            self.assertEqual(health.check_clickhouse(tmp, mt + 600)[0]["status"], health.WARN)
            self.assertEqual(health.check_clickhouse(tmp, mt + 7200)[0]["status"], health.CRIT)
        finally:
            shutil.rmtree(tmp)


@unittest.skipUnless(HAVE_CHDB, "chdb nao instalado")
class PairsAndDimsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.sess = chs.Session(str(self.tmp / "db"))
        for sql in ch.schema(30):
            self.sess.query(sql)
        self.client = ch.Client("http://127.0.0.1:8123", "u", "p", transport=chdb_transport(self.sess))

    def tearDown(self):
        self.sess.close()
        shutil.rmtree(self.tmp)

    def test_pairs_with_null_coordinates_and_spool_header(self):
        r = ("huawei", datetime(2026, 11, 1, 10, 0), "2001:db8::1", "187.87.201.40", "udp", 53, 10, 20, 0, "", "",
             0, 262687, "", "BR10", "", "BR", None, None, -12.9, -38.5, 2048.0, 1e6, 1)
        state = {"down": True}
        real = self.client.transport

        def flaky(*a):
            if state["down"]:
                raise ch.ClickHouseError("fora")
            return real(*a)
        self.client.transport = flaky
        sink = ch.Sink(self.client, spool_dir=self.tmp / "spool", log=lambda m: None)
        self.assertFalse(sink.write_pairs("huawei:f:1:1", [r]))
        state["down"] = False
        self.assertEqual(sink.flush_spool(), 1)
        got = json.loads(str(self.sess.query("SELECT src_ip, src_latitude, dst_latitude FROM "
                                             "orbyflow.orby_ip_pairs_minute FORMAT JSON")))["data"]
        self.assertEqual(got, [{"src_ip": "2001:db8::1", "src_latitude": None, "dst_latitude": -12.9}])

    def test_dimension_sync_only_when_changed(self):
        class Cur:
            data = {"orby_interface_names": [("huawei", 10, "100GE0/1/0")],
                    "orby_country_names": [("BR", "Brasil")],
                    "orby_net_prefixes": [("pool", "45.238.170.64/26", "NAT-POOL-08", 1, 2)]}

            def execute(self, sql):
                self.rows = self.data[sql.split(" FROM ")[1].strip()]

            def fetchall(self):
                return self.rows
        self.client.database = "orbyflow"
        self.assertEqual(len(ch.sync_dimensions(self.client, Cur())), 3)
        self.assertEqual(ch.sync_dimensions(self.client, Cur()), [])            # sem mudanca: nada
        Cur.data["orby_interface_names"] = [("huawei", 10, "100GE0/1/0"), ("huawei", 20, "Eth-Trunk1")]
        self.assertEqual(ch.sync_dimensions(self.client, Cur()), ["orby_interface_names"])
        n = json.loads(str(self.sess.query("SELECT count() AS n FROM orbyflow.orby_interface_names FORMAT JSON")))
        self.assertEqual(int(n["data"][0]["n"]), 2)


if __name__ == "__main__":
    unittest.main()
