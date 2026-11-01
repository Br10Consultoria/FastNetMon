"""Etapa 2: reputacao (listas de bloqueio) e investigacao de denuncias de abuso."""
from datetime import datetime, timedelta, timezone
import gzip
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from zoneinfo import ZoneInfo

from fmn_filters import abuse_lookup as al
from fmn_filters import reputation as rep
from fmn_filters.bidir_config import build_scopes

ROOT = Path(__file__).resolve().parent.parent
CFG = json.loads((ROOT / "rules" / "bidir.example.json").read_text())
PROFILE = json.loads((ROOT / "rules" / "cgnat-profiles.a10.json").read_text())
SCOPES = build_scopes(CFG, PROFILE)
DB_ENABLED = os.environ.get("ORBYMON_TEST_DB") == "1" and os.environ.get("ORBYMON_DB_USER")


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def opener_for(files):
    def opener(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else req
        for key, body in files.items():
            if key in url:
                if isinstance(body, Exception):
                    raise body
                return FakeResponse(body.encode() if isinstance(body, str) else body)
        return FakeResponse(b"# vazio\n1.1.1.1\n")
    return opener


class ParseTests(unittest.TestCase):
    def test_parse_and_match_blocks(self):
        text = "# comentario\n45.238.170.70\n45.238.171.0/25\n8.8.8.8\n187.0.0.0/8\nlixo\n2804:4fa8::1\n"
        found = rep.match(rep.parse_entries(text), [__import__("ipaddress").ip_network(c) for c in
                                                     ("45.238.170.0/23", "187.87.201.0/24", "2804:4fa8::/32")])
        self.assertEqual(set(found), {"45.238.170.70", "45.238.171.0/25", "187.0.0.0/8", "2804:4fa8::1"})

    def test_ipsum_counts(self):
        entries = rep.parse_entries("# x\n45.238.170.70\t7\n", "ipsum")
        self.assertEqual(entries[0][1], {"listas": 7})

    def test_run_collects_and_survives_failing_source(self):
        files = {"blocklist_de_ssh": "45.238.170.70\n1.2.3.4\n", "ipsum": "45.238.170.70\t5\n",
                 "ciarmy": RuntimeError("fora do ar")}
        settings = {"disabled": set(), "dnsbl": False, "abuseipdb_key": "", "heavy_every_h": 6}
        listings, status = rep.run(CFG, PROFILE, settings, None, opener_for(files), log=lambda *a: None)
        by = {(l.entry, l.source) for l in listings}
        self.assertIn(("45.238.170.70", "blocklist_de_ssh"), by)
        self.assertIn(("45.238.170.70", "ipsum"), by)
        self.assertFalse(status["ciarmy"][0])
        self.assertTrue(status["blocklist_de_ssh"][0])
        ipsum = [l for l in listings if l.source == "ipsum"][0]
        self.assertEqual(ipsum.category, "presente em 5 listas de ameaças")
        ssh = [l for l in listings if l.source == "blocklist_de_ssh"][0]
        self.assertEqual(ssh.ports, (22,))


class DnsblTests(unittest.TestCase):
    def resolver(self, answers):
        return lambda name: answers.get(name, [])

    def test_listing_test_point_and_pbl_ignored(self):
        answers = {"2.0.0.127.zen.spamhaus.org": ["127.0.0.2"], "70.170.238.45.zen.spamhaus.org": ["127.0.0.4"],
                   "71.170.238.45.zen.spamhaus.org": ["127.0.0.11"],                 # PBL: residencial, nao e abuso
                   "2.0.0.127.bl.spamcop.net": ["127.0.0.2"]}
        lists = [rep.DNSBLS[0], rep.DNSBLS[1], rep.DNSBLS[2]]
        found, status = rep.check_dnsbl(["45.238.170.70", "45.238.170.71"], lists, self.resolver(answers))
        self.assertEqual(list(found["dnsbl_spamhaus_zen"]), ["45.238.170.70"])
        self.assertIn("XBL", found["dnsbl_spamhaus_zen"]["45.238.170.70"]["codigo"])
        self.assertEqual(found["dnsbl_spamcop"], {})
        self.assertFalse(status["dnsbl_barracuda"][0])                          # sem resposta ao teste

    def test_public_resolver_refused(self):
        answers = {"2.0.0.127.zen.spamhaus.org": ["127.255.255.254"]}
        found, status = rep.check_dnsbl(["45.238.170.70"], [rep.DNSBLS[0]], self.resolver(answers))
        self.assertFalse(status["dnsbl_spamhaus_zen"][0])
        self.assertIn("resolvedor", status["dnsbl_spamhaus_zen"][1])


class AbuseIpdbTests(unittest.TestCase):
    def test_check_block_per_24(self):
        calls = []

        def opener(req, timeout=None):
            calls.append(req.full_url)
            self.assertEqual(req.headers["Key"], "k" * 80)
            body = {"data": {"reportedAddress": [{"ipAddress": "45.238.170.70", "numReports": 3,
                                                  "abuseConfidenceScore": 40}]}} if "170.0" in req.full_url else {"data": {}}
            return FakeResponse(json.dumps(body).encode())
        import ipaddress
        found = rep.check_abuseipdb("k" * 80, [ipaddress.ip_network("45.238.170.0/23")], opener)
        self.assertEqual(len(calls), 2)
        self.assertEqual(found["45.238.170.70"]["denuncias"], 3)


def t(h, m, s=0):
    return datetime(2026, 10, 30, h, m, s, tzinfo=timezone.utc).timestamp()


def write_nat(directory, name, rows, gz=False):
    data = "".join("%.3f\t%s\t%s\t%s\t%d\t%s\t%d\t%.3f\n" % (r + (r[0],)) for r in rows)
    path = Path(directory) / name
    if gz:
        with gzip.open(str(path) + ".gz", "wt") as fh:
            fh.write(data)
    else:
        path.write_text(data)


class NatLookupTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        write_nat(self.dir, "nat-events-2026103012.tsv", [(t(12, 10), "a", "tcp", "100.64.70.60", 7000, "45.238.170.70", 51240)], gz=True)
        write_nat(self.dir, "nat-events-2026103013.tsv", [
            (t(13, 50), "a", "tcp", "100.64.65.10", 40001, "45.238.170.70", 51234),
            (t(13, 56), "f", "tcp", "100.64.65.10", 40001, "45.238.170.70", 51234),
            (t(13, 58), "a", "tcp", "100.64.66.20", 40002, "45.238.170.70", 51234),
            (t(13, 40), "a", "udp", "100.64.67.30", 5000, "45.238.170.70", 51234),
            (t(13, 55), "a", "tcp", "100.64.69.50", 6001, "45.238.170.71", 51234),
            (t(13, 30), "f", "tcp", "100.64.71.70", 8000, "45.238.170.70", 51299)])  # alocada antes do arquivo
        write_nat(self.dir, "nat-events-2026103014.tsv", [(t(14, 2), "f", "tcp", "100.64.70.60", 7000, "45.238.170.70", 51240)])

    def tearDown(self):
        shutil.rmtree(self.dir)

    def q(self, **kw):
        base = dict(ip="45.238.170.70", when=datetime(2026, 10, 30, 13, 55, 1), window_min=10)
        base.update(kw)
        return al.investigate(al.Query(**base), SCOPES, nat_dir=self.dir)

    def test_exact_port_identifies_subscriber_across_gz_files(self):
        r = self.q(port=51240)
        self.assertEqual(r.confidence, "alta")
        self.assertIn("100.64.70.60", r.verdict)

    def test_port_reused_later_does_not_confuse(self):
        r = self.q(port=51234, remote_port=22)          # SSH -> so TCP; 100.64.66.20 pegou a porta depois
        self.assertEqual(r.confidence, "alta")
        self.assertIn("100.64.65.10", r.verdict)
        self.assertNotIn("100.64.66.20", r.verdict)

    def test_protocol_ambiguity_reported(self):
        r = self.q(port=51234)
        self.assertEqual(r.confidence, "media")
        self.assertIn("100.64.67.30", r.verdict)

    def test_without_port_lists_users_of_ip(self):
        r = self.q()
        ips = {s["ip"] for s in r.subscribers}
        self.assertIn("100.64.65.10", ips)
        self.assertIn("100.64.70.60", ips)
        self.assertNotIn("100.64.69.50", ips)            # outro IP publico
        self.assertNotIn("100.64.71.70", ips)            # liberada antes da janela
        self.assertEqual(r.confidence, "baixa")

    def test_wrong_timezone_hint(self):
        r = self.q(port=51234, when=datetime(2026, 10, 30, 13, 57, 0), remote_port=22, window_min=5)
        self.assertIn("fuso", r.verdict)

    def test_missing_logs_reported(self):
        r = self.q(port=1, when=datetime(2026, 10, 29, 3, 0))
        self.assertTrue(any("ausente" in n or "Nenhum arquivo" in n for n in r.notes))

    def test_dedicated_and_external(self):
        self.assertEqual(self.q(ip="187.87.201.138").scope, "dedicated")
        self.assertEqual(self.q(ip="8.8.8.8").scope, "external")


class ExtractTests(unittest.TestCase):
    EMAIL = """From: abuse@example.net
Date: Fri, 30 Oct 2026 15:12:01 +0100
Subject: abuse report for 45.238.170.70

Oct 30 14:55:01 srv sshd[1234]: Failed password for root from 45.238.170.70 port 51234 ssh2
[30/Oct/2026:14:56:10 +0100] 45.238.170.71 "POST /wp-login.php" 200
2026-10-30T13:57:00Z IN=eth0 SRC=187.87.201.138 DST=203.0.113.5 PROTO=TCP SPT=40000 DPT=23
Reported-From: 8.8.8.8 at 2026-10-30 10:00:00
Source: 45.238.171.80
Source-Port: 33333
Date: 2026-10-30 12:00:00 UTC
"""

    def test_extract(self):
        qs = al.extract_reports(self.EMAIL, SCOPES, ZoneInfo("Europe/Berlin"))
        got = [(q.ip, q.when, q.port, q.remote, q.remote_port) for q in qs]
        self.assertIn(("45.238.170.70", datetime(2026, 10, 30, 13, 55, 1), 51234, None, 22), got)
        self.assertIn(("45.238.170.71", datetime(2026, 10, 30, 13, 56, 10), None, None, None), got)
        self.assertIn(("187.87.201.138", datetime(2026, 10, 30, 13, 57), 40000, "203.0.113.5", 23), got)
        self.assertNotIn("8.8.8.8", [g[0] for g in got])
        self.assertEqual(sum(1 for g in got if g[0] == "45.238.170.70"), 1)    # linha Subject ignorada
        xarf = [q for q in qs if q.ip == "45.238.171.80"]
        self.assertEqual(len(xarf), 1)

    def test_time_formats(self):
        utc = timezone.utc
        sp = ZoneInfo("America/Sao_Paulo")
        self.assertEqual(al.parse_time("2026-10-30 14:05:00", sp), datetime(2026, 10, 30, 17, 5))
        self.assertEqual(al.parse_time("30/10/2026 14:05", sp), datetime(2026, 10, 30, 17, 5))
        self.assertEqual(al.parse_time("Fri, 30 Oct 2026 14:05:00 -0300", utc), datetime(2026, 10, 30, 17, 5))
        self.assertEqual(al.parse_time("2026-10-30T17:05:00+00:00", sp), datetime(2026, 10, 30, 17, 5))
        self.assertIsNone(al.parse_time("sem data", utc))


@unittest.skipUnless(DB_ENABLED, "defina ORBYMON_TEST_DB=1 e ORBYMON_DB_* para testar no MariaDB")
class ReputationDbTests(unittest.TestCase):
    def setUp(self):
        from fmn_filters.mysql_sink import connection_from_env
        self.db = connection_from_env()
        with self.db.cursor() as c:
            c.execute("DELETE FROM orby_reputation_listings")
            c.execute("DELETE FROM orby_reputation_sources")
            c.execute("DELETE FROM orby_flow_minute WHERE source='reptest'")
            now = datetime.now(timezone.utc).replace(tzinfo=None, second=0, microsecond=0)
            for i, sub in enumerate(("100.64.65.10", "100.64.65.10", "100.64.66.20")):
                c.execute("""INSERT INTO orby_flow_minute (source,bucket_utc,direction,scope,pool,local_ip,subscriber_ip,
 remote_ip,protocol,local_port,remote_port,packets,bytes,flows) VALUES ('reptest',%s,'out','cgnat_pool','NAT-POOL-08',
 '45.238.170.70',%s,%s,'tcp',0,%s,10,1000,%s)""", (now - timedelta(minutes=i), sub, "203.0.113.%d" % i,
                                                  22 if sub == "100.64.65.10" else 443, 5))
        self.db.commit()
        self.cfg = dict(CFG, source="reptest")
        self.settings = {"disabled": {s.name for s in rep.SOURCES} - {"blocklist_de_ssh", "ciarmy"},
                         "dnsbl": False, "abuseipdb_key": "", "heavy_every_h": 6}

    def tearDown(self):
        with self.db.cursor() as c:
            c.execute("DELETE FROM orby_flow_minute WHERE source='reptest'")
        self.db.commit()
        self.db.close()

    def run_with(self, ssh, ciarmy, when):
        files = {"blocklist_de_ssh": ssh, "ciarmy": ciarmy}
        return rep.run(self.cfg, PROFILE, self.settings, self.db, opener_for(files), now=when, log=lambda *a: None)

    def test_lifecycle_suspects_and_notifications(self):
        sent = []

        class T:
            def send(self, text):
                sent.append(text)

        class F:
            @staticmethod
            def header(icon, title):
                return "%s %s" % (icon, title)

        t0 = datetime(2026, 11, 1, 10, 0)
        self.run_with("45.238.170.70\n", "45.238.170.70\n1.1.1.1\n", t0)
        stats = rep.notify(self.db, T(), F())
        self.assertEqual(stats["enviados"], 1)                          # um aviso por IP, com as duas listas
        self.assertIn("100.64.65.10", sent[0])                          # quem falou na porta 22
        self.assertNotIn("100.64.66.20", sent[0])
        self.assertIn("blocklist.de SSH", sent[0])
        self.assertIn("CINS Army", sent[0])
        self.run_with("45.238.170.70\n", "1.1.1.1\n", t0 + timedelta(hours=1))   # saiu so de uma lista
        self.assertEqual(rep.notify(self.db, T(), F()), {"novos": 0, "enviados": 0, "removidos": 0})
        self.run_with("1.1.1.1\n", "1.1.1.1\n", t0 + timedelta(hours=2))          # saiu de todas
        self.assertEqual(rep.notify(self.db, T(), F())["removidos"], 1)
        self.assertIn("Saiu de todas", sent[-1])
        self.run_with("45.238.170.70\n", "1.1.1.1\n", t0 + timedelta(hours=3))   # voltou: avisa de novo
        self.assertEqual(rep.notify(self.db, T(), F())["enviados"], 1)
        with self.db.cursor() as c:
            c.execute("SELECT first_seen FROM orby_reputation_listings WHERE source='blocklist_de_ssh'")
            self.assertEqual(c.fetchone()[0], t0 + timedelta(hours=3))

    def test_failed_source_does_not_remove(self):
        t0 = datetime(2026, 11, 1, 10, 0)
        self.run_with("45.238.170.70\n", "1.1.1.1\n", t0)
        self.run_with(RuntimeError("fora"), "1.1.1.1\n", t0 + timedelta(hours=1))
        with self.db.cursor() as c:
            c.execute("SELECT removed_at FROM orby_reputation_listings WHERE source='blocklist_de_ssh'")
            self.assertIsNone(c.fetchone()[0])
            c.execute("SELECT status FROM orby_reputation_sources WHERE source='blocklist_de_ssh'")
            self.assertEqual(c.fetchone()[0], "falha")

    def test_mark_notified_first_run(self):
        self.settings["mark_notified"] = True
        self.run_with("45.238.170.70\n", "1.1.1.1\n", datetime(2026, 11, 1, 10, 0))
        self.assertEqual(rep.notify(self.db, type("T", (), {"send": lambda s, x: None})(),
                                    type("F", (), {"header": staticmethod(lambda i, t: t)}))["novos"], 0)

    def test_flow_evidence_and_history(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        r = al.investigate(al.Query("45.238.170.70", now, 10, None, None, None, 22), SCOPES, "reptest", self.db,
                           nat_dir="/nonexistent")
        self.assertEqual({f["assinante"] for f in r.flows}, {"100.64.65.10"})
        self.assertIn("100.64.65.10", r.verdict)
        h = al.ip_history(self.db.cursor(), "45.238.170.70", "cgnat_pool", "reptest")
        self.assertEqual(h["assinantes"][0]["ip"], "100.64.65.10")
        h = al.ip_history(self.db.cursor(), "100.64.65.10", "cgnat_private", "reptest")
        self.assertEqual(h["ips_publicos"][0]["ip"], "45.238.170.70")
        self.assertEqual(h["saida_por_porta"][0]["porta"], 22)


if __name__ == "__main__":
    unittest.main()
