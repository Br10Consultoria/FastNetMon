"""No customer information may leave structural TCP gap diagnostics."""
import json
import unittest

from fmn_filters.a10_tcp_gap_edges import classify_gap_edges

HEADER = b"<135>1 2026-10-31T15:18:00-03:00 A10 CGNAT - - - "
NAT = b"LSN:PortAllocated:TCP [100.64.64.12 34055 45.238.170.70 34055]"


class GapEdgeAuditTests(unittest.TestCase):
    def test_gap_between_complete_looking_events_is_still_untrusted(self):
        result = classify_gap_edges([HEADER + NAT, HEADER + NAT])
        self.assertEqual(result["total_de_fronteiras_de_lacuna"], 1)
        edge = result["detalhes"][0]
        self.assertTrue(edge["trecho_anterior_termina_colchete"])
        self.assertTrue(edge["trecho_seguinte_inicia_cabecalho_rfc5424"])
        self.assertEqual(edge["bytes_antes_do_primeiro_cabecalho_seguinte"], 0)
        self.assertTrue(edge["eventos_adjacentes_nao_homologados"])
        output = json.dumps(result)
        for secret in ("100.64.64.12", "45.238.170.70", "34055"):
            self.assertNotIn(secret, output)

    def test_gap_cutting_an_event_reports_prefix_of_next_span(self):
        result = classify_gap_edges([HEADER + NAT[:-5], b"partial" + HEADER + NAT])
        edge = result["detalhes"][0]
        self.assertFalse(edge["trecho_anterior_termina_colchete"])
        self.assertFalse(edge["trecho_seguinte_inicia_cabecalho_rfc5424"])
        self.assertTrue(edge["trecho_seguinte_tem_cabecalho_rfc5424"])
        self.assertEqual(edge["bytes_antes_do_primeiro_cabecalho_seguinte"], 7)

    def test_no_valid_header_after_gap_is_unknown(self):
        result = classify_gap_edges([HEADER + NAT, b"partial-or-no-more-header"])
        edge = result["detalhes"][0]
        self.assertFalse(edge["trecho_seguinte_tem_cabecalho_rfc5424"])
        self.assertIsNone(edge["bytes_antes_do_primeiro_cabecalho_seguinte"])

    def test_bounds_output_and_has_no_data_when_no_gaps(self):
        self.assertEqual(classify_gap_edges([HEADER + NAT])["detalhes"], [])
        result = classify_gap_edges([HEADER + NAT] * 5, max_details=2)
        self.assertEqual(result["total_de_fronteiras_de_lacuna"], 4)
        self.assertEqual(len(result["detalhes"]), 2)
        self.assertEqual(result["detalhes_omitidos"], 2)
        with self.assertRaises(ValueError):
            classify_gap_edges([HEADER + NAT], max_details=101)


if __name__ == "__main__":
    unittest.main()
