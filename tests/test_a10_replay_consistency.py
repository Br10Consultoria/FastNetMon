import unittest
from fmn_filters.a10_replay_consistency import compare_replay_counters


def counters():
    return {
        "candidate_eventos_delimitados_por_outro_cabecalho": 69190,
        "replay_eventos_delimitados_por_cabecalho_seguinte": 69190,
        "candidate_nat_sintaticamente_candidato": 65277,
        "replay_nat_sintaticamente_candidato": 65277,
        "candidate_detalhe_nat_allocated_tcp": 12646,
        "replay_nat_allocated_tcp": 12646,
        "candidate_detalhe_nat_freed_tcp": 13113,
        "replay_nat_freed_tcp": 13113,
        "candidate_detalhe_nat_allocated_udp": 19720,
        "replay_nat_allocated_udp": 19720,
        "candidate_detalhe_nat_freed_udp": 19798,
        "replay_nat_freed_udp": 19798,
        "candidate_outro_tipo_ou_sem_nat_tcp_udp": 3913,
        "replay_outro_tipo_ou_sem_nat_tcp_udp": 3913,
        "candidate_detalhe_outro_lsn_icmp": 3913,
        "replay_outro_lsn_icmp": 3913,
        "candidate_ultimo_evento_sem_fronteira_comprovada": 6,
        "replay_eventos_finais_sem_fronteira_confiavel": 6,
        "lacunas_tcp": 1,
    }


class A10ReplayConsistencyTests(unittest.TestCase):
    def test_real_aggregate_counts_100percent_agree_without_homologation(self):
        data = compare_replay_counters(counters())
        self.assertEqual(data["status"], "contagens_equivalentes")
        self.assertTrue(data["contagens_replay_consistentes_com_auditoria"])
        self.assertEqual(data["comparacoes"], 9)
        self.assertEqual(data["divergencias"], [])
        self.assertEqual(data["lacunas_tcp_observadas"], 1)
        self.assertEqual(data["eventos_finais_sem_fronteira"], 6)
        self.assertFalse(data["historico_nat_automatico_permitido"])
        self.assertFalse(data["homologacao_de_entrega_fim_a_fim"])

    def test_mismatched_counter_rejected(self):
        sample = counters()
        sample["replay_nat_allocated_tcp"] = 12645
        data = compare_replay_counters(sample)
        self.assertFalse(data["contagens_replay_consistentes_com_auditoria"])
        self.assertEqual(len(data["divergencias"]), 1)

    def test_total_does_not_add_up(self):
        sample = counters()
        sample["candidate_outro_tipo_ou_sem_nat_tcp_udp"] = 3912
        sample["replay_outro_tipo_ou_sem_nat_tcp_udp"] = 3912
        data = compare_replay_counters(sample)
        self.assertEqual(data["status"], "divergencia_ou_sem_eventos")
        self.assertEqual(len(data["divergencias"]), 1)

    def test_buffer_overflow_prevents_agreement(self):
        sample = counters()
        sample["replay_buffers_acima_do_limite"] = 1
        data = compare_replay_counters(sample)
        self.assertFalse(data["contagens_replay_consistentes_com_auditoria"])
        self.assertEqual(len(data["divergencias"]), 1)

    def test_empty_input_cannot_pass(self):
        self.assertFalse(compare_replay_counters({})["contagens_replay_consistentes_com_auditoria"])


if __name__ == "__main__":
    unittest.main()
