import json
import unittest

from fmn_filters.a10_nat_candidate_audit import inspect_candidate_stream
from fmn_filters.a10_tcp_framing import inspect_span
from collections import Counter

HEADER = b"<135>1 2026-10-31T15:18:00-03:00 CGNAT_ENTER A10 - - - "
NAT = b"LSN:PortAllocated:TCP [100.64.64.12 34055 45.238.170.70 34055]"
FREED = b"LSN:PortFreed:UDP [100.64.64.12 34055 45.238.170.70 34055]"


class A10NatCandidateAuditTests(unittest.TestCase):
    def test_valid_bounded_nat_but_last_is_not_accepted(self):
        raw = HEADER + NAT + HEADER + FREED
        result = inspect_candidate_stream(raw)
        self.assertEqual(result["cabecalhos_detectados"], 2)
        self.assertEqual(result["eventos_delimitados_por_outro_cabecalho"], 1)
        self.assertEqual(result["nat_sintaticamente_candidato"], 1)
        self.assertEqual(result["ultimo_evento_sem_fronteira_comprovada"], 1)
        self.assertNotIn("100.64.64.12", json.dumps(result))
        self.assertNotIn("45.238.170.70", json.dumps(result))
        self.assertNotIn("34055", json.dumps(result))

    def test_missing_final_bracket_is_not_valid(self):
        result = inspect_candidate_stream(HEADER + NAT[:-1] + HEADER + FREED)
        self.assertEqual(result["nat_sem_terminador"], 1)
        self.assertNotIn("nat_sintaticamente_candidato", result)

    def test_invalid_public_pool_not_valid(self):
        invalid = NAT.replace(b"45.238.170.70", b"203.0.113.9")
        result = inspect_candidate_stream(HEADER + invalid + HEADER + FREED)
        self.assertEqual(result["nat_mapeamento_invalido_ou_fora_pool"], 1)

    def test_multiple_nat_markers_rejected(self):
        result = inspect_candidate_stream(HEADER + NAT + FREED + HEADER + NAT)
        self.assertEqual(result["marcadores_ambiguos"], 1)

    def test_garbage_prefix_and_unknown_events(self):
        result = inspect_candidate_stream(b"partial" + HEADER + b"LSN:ICMP [some]" + HEADER + NAT)
        self.assertEqual(result["prefixo_sem_cabecalho"], 1)
        self.assertEqual(result["outro_tipo_ou_sem_nat_tcp_udp"], 1)

    def test_invalid_header_priority_is_rejected(self):
        raw = HEADER.replace(b"<135>", b"<999>") + NAT + HEADER + NAT
        result = inspect_candidate_stream(raw)
        self.assertEqual(result["cabecalho_invalido"], 1)
        self.assertNotIn("nat_sintaticamente_candidato", result)

    def test_no_header_in_fragment(self):
        result = inspect_candidate_stream(NAT)
        self.assertEqual(result["trecho_sem_cabecalho"], 1)

    def test_integrates_without_modifying_base_counts(self):
        raw = HEADER + NAT + HEADER + FREED
        a = Counter()
        b = Counter()
        inspect_span(raw, a, audit_nat_candidates=False)
        inspect_span(raw, b, audit_nat_candidates=True)
        self.assertEqual(a["cabecalhos_rfc5424"], b["cabecalhos_rfc5424"])
        self.assertEqual(b["nat_nat_sintaticamente_candidato"], 1)
        self.assertNotIn("nat_nat_sintaticamente_candidato", a)
        self.assertNotIn("100.64.64.12", json.dumps(dict(b)))

if __name__ == "__main__":
    unittest.main()
