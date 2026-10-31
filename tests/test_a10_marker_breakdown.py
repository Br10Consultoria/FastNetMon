"""Privacy-preserving class breakdown on synthetic A10 Syslog TCP spans."""
import json
import unittest
from collections import Counter

from fmn_filters.a10_nat_candidate_audit import inspect_candidate_stream
from fmn_filters.a10_tcp_framing import inspect_span

HEADER = b"<135>1 2026-10-31T15:18:00-03:00 A10 CGNAT - - - "
ALLOCATED = b"LSN:PortAllocated:TCP [100.64.64.12 34055 45.238.170.70 34055]"
FREED = b"LSN:PortFreed:UDP [100.64.64.12 34055 45.238.170.70 34055]"


class MarkerBreakdownTests(unittest.TestCase):
    def test_counts_accepted_nat_event_types_without_ip_ports(self):
        data = HEADER + ALLOCATED + HEADER + FREED + HEADER + b"other text"
        counts = inspect_candidate_stream(data)
        self.assertEqual(counts["nat_sintaticamente_candidato"], 2)
        self.assertEqual(counts["detalhe_nat_allocated_tcp"], 1)
        self.assertEqual(counts["detalhe_nat_freed_udp"], 1)
        self.assertNotIn("100.64.64.12", json.dumps(counts))
        self.assertNotIn("34055", json.dumps(counts))

    def test_breaks_down_other_event_markers_with_fixed_labels(self):
        kinds = [b"LSN:ICMP [safe-not-a-mapping]",
                 b"LSN:GRE [safe-not-a-mapping]",
                 b"LSN:ESP [safe-not-a-mapping]",
                 b"LSN:PortBatch [safe-not-a-mapping]",
                 b"LSN:SessionCreated [safe-not-a-mapping]",
                 b"unrelated record"]
        data = HEADER.join([b"", *kinds, ALLOCATED])
        result = inspect_candidate_stream(data)
        self.assertEqual(result["outro_tipo_ou_sem_nat_tcp_udp"], 6)
        for name in ("lsn_icmp", "lsn_gre", "lsn_esp",
                     "lsn_lote_portas", "lsn_sessao", "sem_marcador_lsn"):
            self.assertEqual(result["detalhe_outro_" + name], 1)
        self.assertEqual(sum(value for key, value in result.items()
                             if key.startswith("detalhe_outro_")), 6)

    def test_classifies_icmp_protocol_suffix(self):
        packet = b"LSN:PortAllocated:ICMP [synthetic]"
        result = inspect_candidate_stream(HEADER + packet + HEADER + ALLOCATED)
        self.assertEqual(result["detalhe_outro_lsn_icmp"], 1)

    def test_unknown_marker_never_leaks_user_supplied_string(self):
        private = b"LSN:PrivateSubscriberSecret99999 [sensitive]"
        result = inspect_candidate_stream(HEADER + private + HEADER + ALLOCATED)
        self.assertEqual(result["detalhe_outro_lsn_outro_marcador"], 1)
        self.assertNotIn("PrivateSubscriberSecret99999", json.dumps(result))

    def test_rejects_unbounded_tail_from_detailed_classification(self):
        result = inspect_candidate_stream(HEADER + ALLOCATED)
        self.assertEqual(result["ultimo_evento_sem_fronteira_comprovada"], 1)
        self.assertEqual(result.get("detalhe_nat_allocated_tcp", 0), 0)

    def test_opt_in_reports_details_and_default_does_not(self):
        payload = HEADER + ALLOCATED + HEADER + b"LSN:ICMP [other]" + HEADER + FREED
        base = Counter()
        detailed = Counter()
        inspect_span(payload, base)
        inspect_span(payload, detailed, audit_nat_candidates=True)
        self.assertNotIn("candidate_detalhe_outro_lsn_icmp", base)
        self.assertEqual(detailed["candidate_detalhe_outro_lsn_icmp"], 1)
        self.assertEqual(detailed["candidate_detalhe_nat_allocated_tcp"], 1)
        self.assertEqual(base["cabecalhos_rfc5424"], detailed["cabecalhos_rfc5424"])


if __name__ == "__main__":
    unittest.main()
