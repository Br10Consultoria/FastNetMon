from datetime import datetime, timedelta
import json
from pathlib import Path
import random
import unittest

from fmn_filters.bidir_config import validate_config
from fmn_filters.calibrate import (Calibrator, attack_minutes, calibrate_nat, percentile, render,
                                   round_up)

ROOT = Path(__file__).resolve().parent.parent
T0 = datetime(2026, 11, 1, 0, 0)


def cfg():
    return validate_config(json.loads((ROOT / "rules/bidir.example.json").read_text()))


def row(minute, ip="45.238.170.10", direction="in", scope="dedicated", proto="udp", pps=1000.0,
        mbps=10.0, sub=None, lport=0, rport=0):
    return {"bucket_utc": T0 + timedelta(minutes=minute), "direction": direction, "scope": scope,
            "local_ip": ip, "subscriber_ip": sub if sub is not None else (ip if scope != "cgnat_pool" else ""),
            "protocol": proto, "local_port": lport, "remote_port": rport,
            "packets": pps * 60, "bytes": mbps * 60e6 / 8}


def entry(summary, rule, scope):
    return [e for e in summary["regras"] if e["regra"] == rule and e["escopo"] == scope][0]


class HelperTests(unittest.TestCase):
    def test_round_up_two_significant_digits(self):
        self.assertEqual([round_up(v) for v in (23456, 1001, 99.1, 7.2, 0)], [24000, 1100, 100, 8, 0])

    def test_percentile(self):
        self.assertEqual(percentile(list(range(1, 1001)), .999), 999)
        self.assertEqual(percentile([], .99), 0.0)


class CalibrationTests(unittest.TestCase):
    def test_proposal_follows_real_distribution_and_floor(self):
        random.seed(3)
        cal = Calibrator(cfg())
        for m in range(600):                         # 10 h de trafego normal, 5 IPs dedicados
            for n in range(5):
                cal.add(row(m, ip="45.238.170.%d" % (10 + n), pps=random.uniform(5000, 20000),
                            mbps=random.uniform(50, 150)))
        summary, proposal = cal.finish(factor=2.0)
        e = entry(summary, "IN UDP volumetrico", "dedicated")
        self.assertEqual(e["amostras"], 3000)
        self.assertGreater(e["min_pps"]["proposto"], e["min_pps"]["p99_9"] * 1.9)
        self.assertLessEqual(e["min_pps"]["proposto"], 41000)          # ~2 x 20000, arredondado
        self.assertEqual(e["minutos_acima_do_proposto"], 0)
        self.assertEqual(summary["minutos_com_dados"], 600)
        validate_config(proposal)                                     # proposta continua valida
        rule = [r for r in proposal["rules"] if r["name"] == "IN UDP volumetrico"][0]
        self.assertEqual(rule["limits"]["dedicated"]["min_pps"], e["min_pps"]["proposto"])
        self.assertEqual(rule["limits"]["dedicated"]["min_remote_ips"], 8)   # criterio estrutural mantido

    def test_low_traffic_uses_floor_and_sparse_scope_keeps_current(self):
        cal = Calibrator(cfg())
        for m in range(500):
            cal.add(row(m, pps=10, mbps=0.1))
        summary, _ = cal.finish()
        e = entry(summary, "IN UDP volumetrico", "dedicated")
        # trava da rodada: no maximo metade do atual (50000/400), mesmo com trafego quase nulo
        self.assertEqual((e["min_pps"]["proposto"], e["min_mbps"]["proposto"]), (25000, 200))
        self.assertTrue(e["min_pps"]["limitado"])
        summary, _ = cal.finish(max_down=0.0001)
        e = entry(summary, "IN UDP volumetrico", "dedicated")
        self.assertEqual((e["min_pps"]["proposto"], e["min_mbps"]["proposto"]), (1000, 10))   # piso
        pool = entry(summary, "IN UDP volumetrico", "cgnat_pool")
        self.assertEqual(pool["amostras"], 0)
        self.assertEqual(pool["min_pps"]["proposto"], pool["min_pps"]["atual"])

    def test_current_alarm_simulation_needs_consecutive_minutes(self):
        cal = Calibrator(cfg())
        big = dict(pps=60000, mbps=500)                # acima dos limites atuais do dedicado
        for m in range(200):
            spike = m in (10, 11, 12, 50, 90, 91)      # 10-12: 1 alarme; 50: isolado; 90-91: 1 alarme
            cal.add(row(m, **(big if spike else dict(pps=100, mbps=1))))
        summary, _ = cal.finish()
        e = entry(summary, "IN UDP volumetrico", "dedicated")
        self.assertAlmostEqual(e["alarmes_atuais_por_dia"], 2 / (200 / 1440), places=0)

    def test_attack_minutes_are_ignored(self):
        events = [(T0 + timedelta(minutes=100), "45.238.170.10", "45.238.170.10")]
        cal = Calibrator(cfg(), attack_minutes(events, margin=2))
        for m in range(300):
            cal.add(row(m, pps=900000 if 98 <= m <= 102 else 5000, mbps=5000 if 98 <= m <= 102 else 50))
        summary, _ = cal.finish()
        e = entry(summary, "IN UDP volumetrico", "dedicated")
        self.assertEqual(summary["entidade_minutos_ignorados_por_ataque"], 5)
        self.assertLess(e["min_pps"]["maximo"], 10000)

    def test_pool_and_subscriber_measured_separately_like_detector(self):
        cal = Calibrator(cfg())
        for m in range(400):
            for s in range(10):                        # 10 assinantes atras do mesmo IP de pool
                cal.add(row(m, ip="45.238.170.70", scope="cgnat_pool", sub="100.64.64.%d" % (s + 1),
                            pps=2000, mbps=20))
        summary, _ = cal.finish()
        self.assertEqual(entry(summary, "IN UDP volumetrico", "cgnat_pool")["min_pps"]["maximo"], 20000)
        self.assertEqual(entry(summary, "IN UDP volumetrico", "cgnat_subscriber")["min_pps"]["maximo"], 2000)

    def test_port_filtered_rule_only_counts_its_ports(self):
        cal = Calibrator(cfg())
        for m in range(300):
            cal.add(row(m, pps=50000, mbps=400, rport=443))
            cal.add(row(m, pps=300, mbps=3, rport=53))
        summary, _ = cal.finish()
        refl = entry(summary, "IN reflexao/amplificacao UDP", "dedicated")
        self.assertEqual(refl["min_pps"]["maximo"], 300)

    def test_syn_rule_measures_syn_signal_and_ratio(self):
        cal = Calibrator(cfg())
        for m in range(300):
            r = row(m, proto="tcp", pps=30000, mbps=300)
            r["syn_packets"] = r["packets"] * 0.05          # trafego normal: pouco SYN
            cal.add(r)
        summary, _ = cal.finish()
        e = entry(summary, "IN SYN flood", "dedicated")
        self.assertEqual(e["sinal"], "SYN/s")
        self.assertAlmostEqual(e["min_pps"]["maximo"], 1500, places=0)   # 5% de 30000
        self.assertEqual(e["alarmes_atuais_por_dia"], 0)                 # pps alto, mas sem SYN dominante

    def test_port_zero_rule_respects_ratio_in_simulation(self):
        cal = Calibrator(cfg())
        for m in range(300):
            r = row(m, pps=40000, mbps=400)
            r["zero_port_packets"] = r["packets"] * (0.9 if m in (100, 101) else 0.01)
            cal.add(r)
        summary, _ = cal.finish()
        e = entry(summary, "IN porta 0 / fragmentos", "dedicated")
        self.assertAlmostEqual(e["alarmes_atuais_por_dia"], 1 / (300 / 1440), places=0)

    def test_out_of_order_rows_are_rejected(self):
        cal = Calibrator(cfg())
        cal.add(row(5))
        with self.assertRaises(ValueError):
            cal.add(row(4))

    def test_nat_rules(self):
        c = cfg()
        rows = [{"allocs": 100 + n % 50, "active_ports": 300} for n in range(1000)]
        report = calibrate_nat(c, rows, c)
        rule = [r for r in c["nat_rules"] if r["name"] == "NAT taxa de alocacao de portas"][0]
        self.assertEqual(rule["min_allocs_per_min"], 3000)             # trava: metade de 6000
        self.assertEqual(report[0]["amostras"], 1000)

    def test_render_has_one_line_per_rule_scope(self):
        cal = Calibrator(cfg())
        for m in range(150):
            cal.add(row(m))
        summary, proposal = cal.finish()
        summary.update(nat=calibrate_nat(cfg(), [], proposal), periodo_utc=["a", "b"], fator=2.0)
        text = render(summary)
        self.assertIn("IN UDP volumetrico", text)
        self.assertEqual(len(text.splitlines()), 2 + len(summary["regras"]) + 2 + 2)


if __name__ == "__main__":
    unittest.main()
