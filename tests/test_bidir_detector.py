from datetime import datetime, timedelta
import json
from pathlib import Path
import unittest

from fmn_filters.bidir_config import validate_config
from fmn_filters.bidir_detector import dedupe, evaluate, evaluate_nat, insert_event

ROOT = Path(__file__).resolve().parent.parent
CFG = validate_config(json.loads((ROOT / "rules/bidir.example.json").read_text()))
RULES = {r["name"]: r for r in CFG["rules"]}
NAT_RULES = {r["name"]: r for r in CFG["nat_rules"]}
START = datetime(2026, 10, 30, 12, 0)


def rows(direction="in", scope="dedicated", local="45.238.170.10", sub=None, proto="udp",
         pps=80000, mbps=800, sources=20, lport=0, rport=0, in_if=101, minutes=2, syn=0.0,
         pool="", remote_prefix="203.0.113.", zero=0.0):
    sub = local if sub is None and scope in ("dedicated", "cgnat_private") else (sub or "")
    out = []
    for m in range(minutes):
        for s in range(sources):
            out.append(dict(bucket_utc=START + timedelta(minutes=m), direction=direction, scope=scope,
                            pool=pool, local_ip=local, subscriber_ip=sub, remote_ip=remote_prefix + str(s + 1),
                            protocol=proto, local_port=lport, remote_port=rport, input_if=in_if, output_if=202,
                            packets=pps * 60 / sources, bytes=mbps * 60e6 / 8 / sources,
                            syn_packets=pps * 60 / sources * syn,
                            zero_port_packets=pps * 60 / sources * zero))
    return out


def ev(rule, data):
    return evaluate(data, RULES[rule], START)


class DetectionTests(unittest.TestCase):
    def test_attack_split_across_interfaces_is_summed(self):
        one = ev("IN UDP volumetrico", rows(pps=80000))
        two = ev("IN UDP volumetrico", rows(pps=40000, mbps=400, in_if=101) + rows(pps=40000, mbps=400, in_if=102))
        self.assertEqual(len(one), 1)
        self.assertEqual(len(two), 1)
        self.assertAlmostEqual(two[0]["pps"], 80000)
        self.assertEqual({i["in"] for i in two[0]["details"]["interfaces"]}, {101, 102})

    def test_outbound_flood_from_protected_ip(self):
        found = ev("OUT UDP flood", rows(direction="out", pps=200000, mbps=900, sources=3, rport=0))
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0]["direction"], found[0]["scope"], found[0]["subscriber_ip"]),
                         ("out", "dedicated", "45.238.170.10"))
        self.assertEqual(ev("IN UDP volumetrico", rows(direction="out", pps=200000)), [])

    def test_reflection_uses_source_service_port(self):
        data = rows(pps=90000, mbps=900, rport=53)
        found = ev("IN reflexao/amplificacao UDP", data)
        self.assertEqual((len(found), found[0]["remote_port"]), (1, 53))
        self.assertEqual(ev("IN reflexao/amplificacao UDP", rows(pps=90000, rport=443)), [])

    def test_cgnat_pool_has_higher_threshold_than_dedicated(self):
        pool = rows(scope="cgnat_pool", local="45.238.170.70", pps=70000, mbps=600, pool="NAT-POOL-08")
        self.assertEqual(ev("IN UDP volumetrico", pool), [])                      # < 100k do pool
        self.assertEqual(len(ev("IN UDP volumetrico", rows(pps=70000, mbps=600))), 1)  # dedicado dispara

    def test_pool_attack_attributes_resolved_private_subscribers(self):
        data = (rows(scope="cgnat_pool", local="45.238.170.70", sub="100.64.64.7", pps=180000, mbps=1500,
                     pool="NAT-POOL-08") +
                rows(scope="cgnat_pool", local="45.238.170.70", sub="100.64.64.8", pps=20000, mbps=100,
                     pool="NAT-POOL-08", remote_prefix="198.51.100."))
        found = {e["scope"]: e for e in ev("IN UDP volumetrico", data)}
        self.assertIn("cgnat_pool", found)
        top = found["cgnat_pool"]["details"]["top_subscribers"]
        self.assertEqual(top[0]["ip"], "100.64.64.7")
        self.assertGreater(top[0]["share"], 0.85)
        self.assertEqual(found["cgnat_subscriber"]["subscriber_ip"], "100.64.64.7")
        self.assertEqual(found["cgnat_subscriber"]["local_ip"], "45.238.170.70")
        self.assertEqual(found["cgnat_subscriber"]["pool"], "NAT-POOL-08")

    def test_unresolved_pool_traffic_never_creates_subscriber_event(self):
        data = rows(scope="cgnat_pool", local="45.238.170.70", sub="", pps=180000, mbps=1500)
        self.assertEqual({e["scope"] for e in ev("IN UDP volumetrico", data)}, {"cgnat_pool"})

    def test_pre_nat_subscriber_outbound_preferred_over_resolved_duplicate(self):
        data = (rows(direction="out", scope="cgnat_private", local="100.64.64.9", pps=60000, mbps=300, sources=4) +
                rows(direction="out", scope="cgnat_pool", local="45.238.170.70", sub="100.64.64.9",
                     pps=60000, mbps=300, sources=4))
        events = ev("OUT UDP flood", data)
        self.assertEqual({e["scope"] for e in events}, {"cgnat_private", "cgnat_subscriber"})
        self.assertEqual([e["scope"] for e in dedupe(events)], ["cgnat_private"])

    def test_requires_all_consecutive_minutes(self):
        data = rows(pps=80000)
        self.assertEqual(ev("IN UDP volumetrico", [r for r in data if r["bucket_utc"] == START]), [])
        weak = [dict(r, packets=r["packets"] / 10) if r["bucket_utc"] > START else r for r in data]
        self.assertEqual(ev("IN UDP volumetrico", weak), [])

    def test_few_remote_sources_do_not_trigger_distributed_rule(self):
        self.assertEqual(ev("IN UDP volumetrico", rows(pps=80000, sources=2)), [])

    def test_syn_flood_needs_syn_dominance(self):
        self.assertEqual(len(ev("IN SYN flood", rows(proto="tcp", pps=40000, mbps=20, syn=0.9))), 1)
        self.assertEqual(ev("IN SYN flood", rows(proto="tcp", pps=40000, mbps=20, syn=0.1)), [])

    def test_outbound_scan_many_destinations(self):
        found = ev("OUT SYN flood ou varredura",
                   rows(direction="out", scope="cgnat_private", local="100.64.64.9", proto="tcp",
                        pps=4000, mbps=3, sources=300, syn=0.95, rport=22))
        self.assertEqual(len(found), 1)
        self.assertGreaterEqual(found[0]["remote_ips"], 300)

    def test_reflector_detected_from_outbound_source_port(self):
        found = ev("OUT IP usado como refletor",
                   rows(direction="out", pps=9000, mbps=90, sources=10, lport=123))
        self.assertEqual((len(found), found[0]["local_port"]), (1, 123))

    def test_port_zero_flood_inbound_and_outbound(self):
        found = ev("IN porta 0 / fragmentos", rows(pps=15000, mbps=150, sources=10, zero=0.9))
        self.assertEqual(len(found), 1)
        self.assertGreaterEqual(found[0]["details"]["zero_port_ratio"], 0.9)
        self.assertEqual(ev("IN porta 0 / fragmentos", rows(pps=15000, mbps=150, sources=10, zero=0.1)), [])
        out = ev("OUT porta 0 / fragmentos", rows(direction="out", scope="cgnat_private",
                                                   local="100.64.64.9", pps=4000, mbps=40, sources=2, zero=0.8))
        self.assertEqual((len(out), out[0]["subscriber_ip"]), (1, "100.64.64.9"))

    def test_old_rows_without_zero_column_still_work(self):
        data = [{k: v for k, v in r.items() if k != "zero_port_packets"} for r in rows(pps=80000)]
        self.assertEqual(len(ev("IN UDP volumetrico", data)), 1)

    def test_infra_scope_is_not_evaluated(self):
        self.assertEqual(ev("IN UDP volumetrico", rows(scope="infra", local="187.87.201.198", pps=900000)), [])


class NatRuleTests(unittest.TestCase):
    def nat(self, ip="100.64.64.9", allocs=7000, ports=100, minutes=2):
        return [dict(bucket_utc=START + timedelta(minutes=m), inside_ip=ip, allocs=allocs, frees=0,
                     active_ports=ports) for m in range(minutes)]

    def test_port_allocation_rate_is_unsampled_signal(self):
        found = evaluate_nat(self.nat(), NAT_RULES["NAT taxa de alocacao de portas"], START)
        self.assertEqual((len(found), found[0]["subscriber_ip"], found[0]["detection"]),
                         (1, "100.64.64.9", "nat"))
        self.assertEqual(evaluate_nat(self.nat(allocs=100), NAT_RULES["NAT taxa de alocacao de portas"], START), [])
        self.assertEqual(evaluate_nat(self.nat(minutes=1), NAT_RULES["NAT taxa de alocacao de portas"], START), [])

    def test_active_ports_rule(self):
        found = evaluate_nat(self.nat(allocs=1, ports=25000), NAT_RULES["NAT portas ativas por assinante"], START)
        self.assertEqual(found[0]["details"]["active_ports"], 25000)


class FakeCursor:
    def __init__(self):
        self.calls, self.last = [], None

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        if sql.startswith("UPDATE orby_bidir_rule_state"):
            self.last = params[0]

    def fetchone(self):
        return (self.last,)


class PersistenceTests(unittest.TestCase):
    def event(self, minute=0):
        e = ev("IN UDP volumetrico", rows(pps=80000))[0]
        e["bucket"] = START + timedelta(minutes=minute)
        return e

    def test_cooldown_and_dual_write(self):
        cur = FakeCursor()
        rule = RULES["IN UDP volumetrico"]
        self.assertTrue(insert_event(cur, "huawei", rule, self.event(0), 15))
        sqls = [c[0] for c in cur.calls]
        self.assertTrue(any("orby_attack_events" in s for s in sqls))
        self.assertTrue(any("orby_alerts" in s for s in sqls))
        before = len(cur.calls)
        self.assertFalse(insert_event(cur, "huawei", rule, self.event(5), 15))
        self.assertEqual(len(cur.calls) - before, 2)                 # so state insert + select
        self.assertTrue(insert_event(cur, "huawei", rule, self.event(16), 15))


class ConfigTests(unittest.TestCase):
    def cfg(self):
        return json.loads((ROOT / "rules/bidir.example.json").read_text())

    def test_ipv6_key_is_optional_for_existing_installations(self):
        cfg = self.cfg()
        cfg.pop("ipv6_protected_cidrs")
        self.assertEqual(validate_config(cfg)["ipv6_protected_cidrs"], [])

    def test_example_is_valid_and_covers_both_directions(self):
        self.assertEqual({r["direction"] for r in CFG["rules"]}, {"in", "out"})
        self.assertEqual(CFG["extra_infrastructure_cidrs"], ["187.87.201.193/32", "187.87.201.198/32"])

    def test_rejects_bad_configs(self):
        for mutate in (lambda c: c.pop("rules"), lambda c: c.update(extra=1),
                       lambda c: c["rules"][0].update(direction="both"),
                       lambda c: c["rules"][0].update(protocols=[]),
                       lambda c: c["rules"][0]["limits"].update(foo={"min_pps": 1}),
                       lambda c: c["rules"][0]["limits"]["dedicated"].update(min_pps=-1),
                       lambda c: c["rules"][0]["limits"].update(dedicated={"min_remote_ips": 8}),
                       lambda c: c["rules"][1].update(name=c["rules"][0]["name"]),
                       lambda c: c["rules"][0].update(consecutive_minutes=9),
                       lambda c: c["rules"][2]["limits"]["dedicated"].update(min_syn_ratio=1.5),
                       lambda c: c["rules"][0]["limits"]["dedicated"].update(min_zero_port_ratio=2),
                       lambda c: c.update(nat_socket="relativo.sock"),
                       lambda c: c["nat_rules"][0].pop("min_allocs_per_min"),
                       lambda c: c.update(ipv6_protected_cidrs=["10.0.0.0/8"]),
                       lambda c: c.update(ipv6_protected_cidrs=["2001:db8::/32"])):
            cfg = self.cfg()
            mutate(cfg)
            with self.assertRaises(ValueError):
                validate_config(cfg)


if __name__ == "__main__":
    unittest.main()
