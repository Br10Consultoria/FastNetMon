from datetime import datetime, timedelta
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from fmn_filters import threat_intel as ti

T0 = datetime(2026, 11, 4, 10, 0)


class ParseTests(unittest.TestCase):
    def test_plain_and_comments(self):
        text = "# Feodo\n162.243.103.246\n10.0.0.0/8 ; DROP\nlixo\n2001:db8::/32\n"
        nets = [str(n) for n, _, _ in ti.parse_plain(text)]
        self.assertEqual(nets, ["162.243.103.246/32", "10.0.0.0/8", "2001:db8::/32"])

    def test_c2intel_csv(self):
        out = ti.parse_c2intel("#ip,ioc\n1.117.74.144,Possible Cobaltstrike C2 IP\nlixo,x\n")
        self.assertEqual([(str(n), m) for n, _, m in out], [("1.117.74.144/32", "Cobaltstrike")])

    def test_threatfox_only_ip_port_c2(self):
        text = json.dumps({"query_status": "ok", "data": [
            {"ioc": "45.9.9.9:3524", "ioc_type": "ip:port", "threat_type": "botnet_cc", "malware_printable": "Mirai"},
            {"ioc": "evil.example", "ioc_type": "domain", "threat_type": "botnet_cc"},
            {"ioc": "45.9.9.8:80", "ioc_type": "ip:port", "threat_type": "payload_delivery", "malware": "x"},
            {"ioc": "45.9.9.7:80", "ioc_type": "ip:port", "threat_type": "cc_skimming"}]})
        out = ti.parse_threatfox(text)
        self.assertEqual([(str(n), p, m) for n, p, m in out], [("45.9.9.9/32", 3524, "Mirai"), ("45.9.9.8/32", 80, "x")])
        self.assertEqual(ti.parse_threatfox("nao json"), [])


class IndexTests(unittest.TestCase):
    def setUp(self):
        self.idx = ti.Index(exclude=["187.87.201.0/24", "100.64.64.0/19"])
        self.idx.add(ti.FEED_BY_NAME["feodo"], ti.parse_plain("162.243.103.246\n187.87.201.10\n"))
        self.idx.add(ti.FEED_BY_NAME["spamhaus_drop"], ti.parse_plain(
            "5.10.0.0/16\n10.0.0.0/8\n100.64.0.0/10\n1.0.0.0/4\n2a0b::/32\n"))
        self.idx.add(ti.FEED_BY_NAME["et_compromised"], ti.parse_plain("5.10.4.0/24\n"))
        self.idx.build()

    def test_exact_and_networks(self):
        self.assertEqual({i[0] for i in self.idx.lookup("162.243.103.246")}, {"feodo"})
        self.assertEqual(len(self.idx.lookup("5.10.4.9")), 2)          # /16 e /24 sobrepostos, listas diferentes
        self.assertEqual(len(self.idx.lookup("5.10.200.1")), 1)
        self.assertTrue(self.idx.lookup("2a0b::1"))
        self.assertFalse(self.idx.lookup("8.8.8.8"))
        self.assertFalse(self.idx.lookup("nao-ip"))

    def test_private_own_and_huge_skipped(self):
        self.assertFalse(self.idx.lookup("187.87.201.10"))             # bloco nosso
        self.assertFalse(self.idx.lookup("10.1.1.1"))                  # privado
        self.assertFalse(self.idx.lookup("100.64.70.1"))               # CGNAT
        self.assertFalse(self.idx.lookup("2.2.2.2"))                   # /4: grande demais
        self.assertEqual(self.idx.size(), 4)


class FakeFlows:
    def __init__(self, rows):
        self.rows = rows
        self.asked = []

    def remotes(self, start, end):
        return sorted({r[4] for r in self.rows})

    def detail(self, start, end, ips):
        self.asked.append(list(ips))
        return [r for r in self.rows if r[4] in ips]


class FakeCursor:
    def __init__(self, log):
        self.log, self.rowcount = log, 1

    def execute(self, sql, params=None):
        self.log.append((" ".join(sql.split())[:40], params))


class FakeDb:
    def __init__(self):
        self.log = []

    def cursor(self):
        return FakeCursor(self.log)

    def commit(self):
        pass


class RunTests(unittest.TestCase):
    def test_hits_events_and_subscriber(self):
        idx = ti.Index()
        idx.add(ti.FEED_BY_NAME["threatfox"], [(ti.ip_network("45.9.9.9"), 3524, "Mirai")])
        idx.add(ti.FEED_BY_NAME["ipsum"], ti.parse_plain("45.9.9.9\n101.36.98.148\n"))
        idx.build()
        t1 = T0 + timedelta(minutes=4)
        flows = FakeFlows([
            ("45.238.170.70", "100.64.70.39", "cgnat_pool", "NAT-POOL-08", "45.9.9.9", "udp", 0, 4096.0, 600.0, 3, T0, t1),
            ("187.87.201.40", "", "dedicated", "", "101.36.98.148", "udp", 0, 2048.0, 1e6, 9, T0, t1),
            ("187.87.201.41", "", "dedicated", "", "8.8.8.8", "udp", 53, 1.0, 1.0, 1, T0, t1)])
        db = FakeDb()
        hits, events = ti.run(flows, idx, T0, T0 + timedelta(minutes=10), db)
        self.assertEqual(flows.asked, [["101.36.98.148", "45.9.9.9"]])         # so os IPs listados
        by = {h["remote_ip"]: h for h in hits}
        self.assertEqual(set(by), {"45.9.9.9", "101.36.98.148"})
        bot = by["45.9.9.9"]
        self.assertEqual((bot["cpe_ip"], bot["category"], bot["listed_port"], bot["malware"]),
                         ("100.64.70.39", "bot", 3524, "Mirai"))
        self.assertIn("ThreatFox", bot["sources"])
        self.assertIn("IPsum", bot["sources"])
        self.assertEqual(by["101.36.98.148"]["category"], "reputacao")
        self.assertEqual(events, 1)                                             # evento so para C2
        ev = [p for s, p in db.log if s.startswith("INSERT IGNORE INTO orby_attack_events")]
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0][2], "C2/botnet: Mirai")
        self.assertEqual(ev[0][6:8], ("45.238.170.70", "100.64.70.39"))

    def test_same_pair_same_day_same_event_id(self):
        h = {"cpe_ip": "100.64.70.39", "remote_ip": "45.9.9.9", "protocol": "udp", "remote_port": 0,
             "public_ip": "45.238.170.70", "scope": "cgnat_pool", "pool": "", "subscriber_ip": "100.64.70.39",
             "category": "bot", "sources": "x", "listed_port": 0, "malware": "", "first_seen": T0, "last_seen": T0,
             "flows": 1, "packets": 1.0, "bytes": 1.0}
        db = FakeDb()
        ti.store(db, [h])
        ti.store(db, [dict(h, last_seen=T0 + timedelta(hours=3))])
        ids = [p[0] for s, p in db.log if s.startswith("INSERT IGNORE")]
        self.assertEqual(len(set(ids)), 1)

    def test_window_resumes_and_caps(self):
        with tempfile.TemporaryDirectory() as d:
            now = datetime(2026, 11, 4, 12, 0, 30)
            start, end = ti.window(d, now)
            self.assertEqual(end, datetime(2026, 11, 4, 11, 57))
            self.assertEqual(start, end - timedelta(minutes=15))
            ti.save_window(d, end)
            self.assertEqual(ti.window(d, now + timedelta(minutes=10))[0], end)
            Path(d, "last_end").write_text("2026-10-01 00:00:00")
            s2, e2 = ti.window(d, now)
            self.assertEqual(e2 - s2, ti.MAX_WINDOW)


class RefreshTests(unittest.TestCase):
    def test_download_keeps_old_copy_on_failure_and_skips_without_key(self):
        class Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        calls = []

        def opener(req, timeout=60):
            calls.append(req.full_url)
            if "ipsum" in req.full_url:
                raise OSError("rede fora")
            return Resp(b"1.2.3.4\n5.6.7.0/24\n")

        with tempfile.TemporaryDirectory() as d:
            Path(d, "ipsum.txt").write_text("9.9.9.9\n")
            os.utime(Path(d, "ipsum.txt"), (0, 0))                                # vencida
            st = ti.refresh(d, {"refresh_h": 6}, opener=opener, log=lambda *a: None)
            self.assertEqual(st["feodo"], (True, "", 2))
            self.assertFalse(st["ipsum"][0])
            self.assertEqual(Path(d, "ipsum.txt").read_text(), "9.9.9.9\n")       # copia anterior mantida
            self.assertFalse(st["threatfox"][0])
            self.assertIn("Auth-Key", st["threatfox"][1])
            self.assertNotIn(ti.THREATFOX_API, calls)                             # sem chave nem tenta
            st2 = ti.refresh(d, {"refresh_h": 6}, opener=opener, log=lambda *a: None)
            self.assertNotIn("feodo", st2)                                         # ainda fresca


if __name__ == "__main__":
    unittest.main()
