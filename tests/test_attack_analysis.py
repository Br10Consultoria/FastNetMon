from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import tempfile
import unittest

from fmn_filters import attack_analysis as aa

HEAD = "ts,te,td,sa,da,sp,dp,pr,flg,stos,ipkt,ibyt,opkt,obyt,in,out,sas,das"
T = "2026-11-04 12:00:00,2026-11-04 12:00:01,1.0"


def row(sa, da, sp, dp, pr="UDP", flg="........", pk=10, by=12000, sas=0, das=0):
    return "%s,%s,%s,%d,%d,%s,%s,0,%d,%d,0,0,0,0,%d,%d" % (T, sa, da, sp, dp, pr, flg, pk, by, sas, das)


def csv_text(rows):
    return HEAD + "\n" + "\n".join(rows) + "\nSummary\nflows,bytes\n1,1\n"


def stats(rows, direction="in"):
    return aa.stats_of(aa.csv_rows(csv_text(rows)), direction)


class ClassifyTests(unittest.TestCase):
    def test_dns_amplification_with_fragments(self):
        rows = [row("8.8.%d.%d" % (i // 250, i % 250), "187.87.201.40", 53, 40000 + i, by=14000) for i in range(300)]
        rows += [row("8.8.0.%d" % i, "187.87.201.40", 0, 0, by=8000) for i in range(100)]
        main, vectors, facts = aa.classify(stats(rows), "in")
        self.assertTrue(main.startswith("Amplificação DNS (UDP/53)"), main)
        self.assertEqual(vectors[0][0], "Amplificação DNS (UDP/53)")
        self.assertIn("Fragmentos UDP (porta 0)", [v[0] for v in vectors])
        self.assertEqual(facts["ips_remotos"], 300)
        self.assertEqual(facts["bytes_por_pacote"], round((300 * 14000 + 100 * 8000) / 4000))

    def test_syn_ack_rst_and_tcp(self):
        syn = [row("9.9.%d.%d" % (i // 200, i % 200), "187.87.201.40", 30000 + i, 443, "TCP", "......S.", 5, 300)
               for i in range(400)]
        self.assertEqual(aa.classify(stats(syn), "in")[0], "SYN flood")
        ack = [row("9.9.9.%d" % i, "187.87.201.40", 30000, 80, "TCP", "....A...", 5, 300) for i in range(50)]
        self.assertEqual(aa.classify(stats(ack), "in")[0], "ACK flood")
        sa = [row("1.1.1.%d" % i, "187.87.201.40", 443, 5000 + i, "TCP", "....A.S.", 5, 300) for i in range(50)]
        self.assertEqual(aa.classify(stats(sa), "in")[0], "Reflexão TCP (SYN-ACK)")

    def test_udp_random_ports_and_icmp_and_multivector(self):
        rnd = [row("5.5.5.%d" % (i % 200), "187.87.201.40", 4444, 1000 + i * 7, by=5000) for i in range(300)]
        self.assertEqual(aa.classify(stats(rnd), "in")[0], "UDP flood em portas aleatórias")
        mix = rnd[:100] + [row("6.6.6.%d" % i, "187.87.201.40", 0, 0, "ICMP", by=5000) for i in range(100)]
        main, vectors, _ = aa.classify(stats(mix), "in")
        self.assertTrue(main.endswith("+ multivetor"), main)
        self.assertEqual({v[0] for v in vectors}, {"UDP flood em portas aleatórias", "ICMP flood"})

    def test_outbound_reflector_scan_and_flood(self):
        refl = [row("187.87.201.50", "203.0.113.%d" % i, 123, 80, by=48000) for i in range(30)]
        self.assertEqual(aa.classify(stats(refl, "out"), "out")[0], "Cliente usado como refletor NTP (UDP/123)")
        scan = [row("45.238.170.70", "198.51.%d.%d" % (i // 250, i % 250), 40000 + i, 23, "TCP", "......S.", 1, 60)
                for i in range(500)]
        self.assertEqual(aa.classify(stats(scan, "out"), "out")[0], "Varredura TCP/23 (Telnet)")
        flood = [row("187.87.201.50", "203.0.113.9", 5000 + i, 27015, by=50000) for i in range(20)]
        self.assertEqual(aa.classify(stats(flood, "out"), "out")[0], "UDP flood na porta 27015")

    def test_empty(self):
        self.assertEqual(aa.classify(stats([]), "in")[0], "Sem fluxos amostrados na janela")


class AnalyzeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.ev_time = datetime(2026, 11, 4, 12, 0)
        for m in range(-3, 2):
            f = self.dir / ("nfcapd.20261104%02d%02d" % (12 + (m // 60), m % 60))
            f.write_text("")
            ts = (self.ev_time + timedelta(minutes=m)).replace(tzinfo=timezone.utc).timestamp()
            os.utime(f, (ts, ts))

    def tearDown(self):
        self.tmp.cleanup()

    def test_carpet_bombing_and_filters(self):
        calls = []
        attack = [row("8.8.8.%d" % i, "187.87.201.40", 53, 40000 + i, by=14000, sas=15169) for i in range(50)]

        def run(files, flow_dir, expr, extra=(), timeout=60):
            calls.append((len(files), expr, list(extra)))
            if "-A" in extra:
                return csv_text([row("8.8.8.8", "187.87.201.%d" % i, 53, 1) for i in range(1, 41)])
            return csv_text(attack)

        ev = {"event_id": "x", "event_time": self.ev_time, "direction": "in", "local_ip": "187.87.201.40",
              "details": {"minutes": 2}}
        a = aa.analyze(ev, self.dir, None, run)
        self.assertEqual(calls[0][1], "dst ip 187.87.201.40")
        self.assertIn("-c", calls[0][2])
        self.assertEqual(calls[1][1], "proto udp and src port 53 and dst net 187.87.201.0/24")
        self.assertEqual(a["facts"]["ips_do_bloco_atingidos"], 40)
        self.assertIn("carpet bombing (40 IPs do 187.87.201.0/24)", a["vector"])
        self.assertEqual(a["top_asns"][0]["asn"], 15169)
        self.assertIn("Amplificação DNS", aa.summary(a))
        text = aa.telegram_text(dict(ev, subscriber_ip="", rule_name="Reflexão/amplificação UDP"), a, "BR10")
        self.assertIn("Mesmo vetor em <b>40 IPs</b>", text)

    def test_never_builds_filter_from_non_ip(self):
        ev = {"event_id": "x", "event_time": self.ev_time, "direction": "in", "local_ip": "1.2.3.4 or any",
              "details": {}}
        with self.assertRaises(ValueError):
            aa.analyze(ev, self.dir, None, lambda *a, **k: "")

    def test_no_files(self):
        ev = {"event_id": "x", "event_time": datetime(2020, 1, 1), "direction": "in", "local_ip": "187.87.201.40",
              "details": {}}
        self.assertEqual(aa.analyze(ev, self.dir, None, lambda *a, **k: "")["files"], 0)


if __name__ == "__main__":
    unittest.main()


class WeeklyReportTests(unittest.TestCase):
    def test_render_skips_missing_sections_and_escapes(self):
        from fmn_filters import weekly_report as w
        start, end = datetime(2026, 10, 28, 11), datetime(2026, 11, 4, 11)
        d = {"in": [(12, 3)], "biggest": [("187.87.201.40", 2500.0, 3e5, datetime(2026, 11, 2, 23), "UDP <volumétrico>")],
             "vectors": [("Amplificação DNS (UDP/53)", 9, 2)], "carpet": [(2, 40)], "asns": [(4134, "CHINANET", "CN", 5)],
             "targets": [("187.87.201.40", 9, 2500.0)], "out": None, "c2": [(1, 1)],
             "c2_top": [("100.64.70.39", "Mirai", 2)], "suspects": [("100.64.70.39", 1, 2, 0, 0, 13)],
             "blacklists": None, "nat_peak": [], "alarms": None}
        text = w.render(d, start, end, "BR10")
        self.assertIn("2,5 Gb/s", text)
        self.assertIn("&lt;volumétrico&gt;", text)
        self.assertIn("até 40 IPs", text)
        self.assertIn("Mirai", text)
        self.assertNotIn("originados por clientes", text)          # tabela ausente: secao some
        self.assertNotIn("Blacklists", text)
        self.assertIn("28/10 08:00", text)                          # horario local
