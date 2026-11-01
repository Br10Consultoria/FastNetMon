import json
from pathlib import Path
import unittest

from fmn_filters.bidir_config import build_scopes, validate_config
from fmn_filters.flow_rollup import INSERT_SQL, aggregate

ROOT = Path(__file__).resolve().parent.parent
PROFILE = json.loads((ROOT / "rules/cgnat-profiles.a10.json").read_text())


def config(**over):
    cfg = json.loads((ROOT / "rules/bidir.example.json").read_text())
    cfg.update(over)
    return validate_config(cfg)


def flow(src, dst, sport, dport, proto="udp", packets=1000, nbytes=1_000_000, flags="",
         in_if=101, out_if=202, end="2026-10-30T12:00:30Z"):
    return {"start": "2026-10-30T12:00:00Z", "end": end, "src_ip": src, "dst_ip": dst,
            "src_port": sport, "dst_port": dport, "protocol": proto, "packets": packets,
            "bytes": nbytes, "tcp_flags": flags, "input_if": in_if, "output_if": out_if}


def run(records, cfg=None, resolve=None):
    cfg = cfg or config()
    scopes = build_scopes(cfg, json.loads(json.dumps(PROFILE)))
    return aggregate(records, "huawei", scopes, cfg, resolve)


COLS = ("source", "bucket", "direction", "scope", "pool", "local_ip", "subscriber_ip", "remote_ip",
        "protocol", "local_port", "remote_port", "input_if", "output_if", "packets", "bytes",
        "syn_packets", "flows")


def as_dicts(rows):
    return [dict(zip(COLS, r)) for r in rows]


class RollupTests(unittest.TestCase):
    def test_insert_columns_match_row_shape(self):
        rows, _ = run([flow("8.8.8.8", "45.238.170.10", 53, 40000)])
        self.assertEqual(len(rows[0]), INSERT_SQL.count("%s"))

    def test_inbound_to_pool_resolves_private_subscriber(self):
        calls = []

        def resolve(keys):
            calls.append(keys)
            return [["100.64.64.7", 51000] if k[1] == 20005 else None for k in keys]
        rows, stats = run([flow("9.9.9.9", "45.238.170.70", 53, 20005, packets=500)], resolve=resolve)
        row = as_dicts(rows)[0]
        self.assertEqual((row["direction"], row["scope"], row["pool"]), ("in", "cgnat_pool", "NAT-POOL-08"))
        self.assertEqual(row["subscriber_ip"], "100.64.64.7")
        self.assertEqual((row["local_port"], row["remote_port"]), (0, 53))   # efemera zerada, servico mantido
        self.assertEqual(stats["nat_resolvido"], 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0][:3], ["45.238.170.70", 20005, "udp"])

    def test_unresolved_pool_flow_is_never_guessed(self):
        rows, stats = run([flow("45.238.170.71", "8.8.8.8", 33333, 53)], resolve=lambda k: [None] * len(k))
        self.assertEqual(as_dicts(rows)[0]["subscriber_ip"], "")
        self.assertEqual(stats["nat_nao_resolvido"], 1)
        rows, stats = run([flow("45.238.170.71", "8.8.8.8", 33333, 53)])     # sem resolvedor
        self.assertEqual(as_dicts(rows)[0]["subscriber_ip"], "")

    def test_outbound_pre_nat_and_dedicated(self):
        rows = as_dicts(run([flow("100.64.64.9", "8.8.8.8", 41000, 443, "tcp"),
                             flow("45.238.170.10", "1.1.1.1", 50000, 53)])[0])
        by_scope = {r["scope"]: r for r in rows}
        self.assertEqual(by_scope["cgnat_private"]["subscriber_ip"], "100.64.64.9")
        self.assertEqual(by_scope["cgnat_private"]["direction"], "out")
        self.assertEqual((by_scope["cgnat_private"]["local_port"], by_scope["cgnat_private"]["remote_port"]), (0, 443))
        self.assertEqual(by_scope["dedicated"]["subscriber_ip"], "45.238.170.10")

    def test_internal_and_transit_discarded_but_spoofed_bogon_sources_kept(self):
        rows, stats = run([flow("45.238.170.10", "45.238.170.70", 1, 2),
                           flow("8.8.8.8", "1.1.1.1", 1, 2),
                           flow("100.64.64.9", "100.64.65.9", 1, 2),
                           flow("10.1.2.3", "45.238.170.10", 1, 2),      # origem forjada (RFC1918)
                           flow("240.0.0.7", "45.238.170.10", 1, 2)])    # origem forjada (reservada)
        self.assertEqual((stats["internos_descartados"], stats["transito_descartado"]), (2, 1))
        self.assertEqual(stats["remoto_nao_publico_mantido"], 2)
        self.assertEqual({r["remote_ip"] for r in as_dicts(rows)}, {"10.1.2.3", "240.0.0.7"})

    def test_syn_only_counted_and_ack_not(self):
        rows = as_dicts(run([flow("1.2.3.4", "45.238.170.10", 1000, 80, "tcp", packets=100, flags="S"),
                             flow("1.2.3.5", "45.238.170.10", 1000, 80, "tcp", packets=100, flags="SA"),
                             flow("1.2.3.6", "45.238.170.10", 1000, 80, "udp", packets=100, flags="S")])[0])
        syn = {r["remote_ip"]: r["syn_packets"] for r in rows}
        self.assertEqual(syn, {"1.2.3.4": 100.0, "1.2.3.5": 0.0, "1.2.3.6": 0.0})

    def test_observation_ifindex_filter_avoids_double_counting(self):
        cfg = config(observation_ifindexes={"in": [86], "out": [86]})
        rows, stats = run([
            flow("8.8.8.8", "45.238.170.10", 53, 40000, in_if=86, out_if=0),     # entrou pelo uplink
            flow("8.8.8.8", "45.238.170.10", 53, 40000, in_if=16, out_if=0),     # mesmo pacote visto no A10
            flow("45.238.170.10", "8.8.8.8", 40000, 53, in_if=0, out_if=86),     # saiu pelo uplink (Huawei exporta in=0)
            flow("45.238.170.10", "8.8.8.8", 40000, 53, in_if=16, out_if=99)], cfg)
        self.assertEqual(sorted(r["direction"] for r in as_dicts(rows)), ["in", "out"])
        self.assertEqual(stats["filtrado_por_ifindex"], 2)

    def test_same_key_sums_and_multiplier_applies(self):
        cfg = config(counter_multiplier=2.0)
        rows = as_dicts(run([flow("8.8.8.8", "45.238.170.10", 53, 40000, packets=10, nbytes=100),
                             flow("8.8.8.8", "45.238.170.10", 53, 40001, packets=5, nbytes=50)], cfg)[0])
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["packets"], rows[0]["bytes"], rows[0]["flows"]), (30.0, 300.0, 2))
        self.assertEqual(rows[0]["bucket"].isoformat(), "2026-10-30T12:00:00")

    def test_non_flow_events_and_bad_records_do_not_stop_ingest(self):
        rows, stats = run([{"type": "EVENT", "src_ip": "1.1.1.1"}, {"foo": 1},
                           flow("8.8.8.8", "45.238.170.10", 53, 40000)])
        self.assertEqual(len(rows), 1)


if __name__ == "__main__":
    unittest.main()
