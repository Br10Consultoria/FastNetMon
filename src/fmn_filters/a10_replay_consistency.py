"""Compare two independent *counting passes* over an A10 PCAP.

Matching the structural candidate counts of the direct analyzer and an
incremental replay is necessary but NOT sufficient for trustworthy logs.
Neither pass verifies RFC6587 framing or delivery to rsyslog.
"""
from __future__ import annotations

from collections.abc import Mapping

# The values are fixed metric labels, never derived from customer data.
COUNTER_PAIRS = (
    ("candidate_eventos_delimitados_por_outro_cabecalho",
     "replay_eventos_delimitados_por_cabecalho_seguinte"),
    ("candidate_nat_sintaticamente_candidato",
     "replay_nat_sintaticamente_candidato"),
    ("candidate_detalhe_nat_allocated_tcp", "replay_nat_allocated_tcp"),
    ("candidate_detalhe_nat_freed_tcp", "replay_nat_freed_tcp"),
    ("candidate_detalhe_nat_allocated_udp", "replay_nat_allocated_udp"),
    ("candidate_detalhe_nat_freed_udp", "replay_nat_freed_udp"),
    ("candidate_outro_tipo_ou_sem_nat_tcp_udp",
     "replay_outro_tipo_ou_sem_nat_tcp_udp"),
    ("candidate_detalhe_outro_lsn_icmp", "replay_outro_lsn_icmp"),
    ("candidate_ultimo_evento_sem_fronteira_comprovada",
     "replay_eventos_finais_sem_fronteira_confiavel"),
)


def compare_replay_counters(stats: Mapping[str, int]) -> dict:
    """Return aggregate agreement only, never an ingestion authorization."""
    mismatches: list[dict[str, int | str]] = []
    for original, replay in COUNTER_PAIRS:
        original_count = stats.get(original, 0)
        replay_count = stats.get(replay, 0)
        if original_count != replay_count:
            mismatches.append({
                "contagem_auditoria": original,
                "valor_auditoria": original_count,
                "contagem_replay": replay,
                "valor_replay": replay_count,
            })
    original_total = stats.get("candidate_eventos_delimitados_por_outro_cabecalho", 0)
    classified = (
        stats.get("candidate_nat_sintaticamente_candidato", 0)
        + stats.get("candidate_outro_tipo_ou_sem_nat_tcp_udp", 0)
    )
    if classified != original_total:
        mismatches.append({
            "contagem_auditoria": "eventos_total_classificados",
            "valor_auditoria": classified,
            "contagem_replay": "eventos_delimitados",
            "valor_replay": original_total,
        })
    buffer_overflow = stats.get("replay_buffers_acima_do_limite", 0)
    if buffer_overflow:
        mismatches.append({
            "contagem_auditoria": "replay_buffers_acima_do_limite",
            "valor_auditoria": buffer_overflow,
            "contagem_replay": "limite_aceitavel",
            "valor_replay": 0,
        })
    agreeing = bool(original_total) and not mismatches
    return {
        "status": "contagens_equivalentes" if agreeing else "divergencia_ou_sem_eventos",
        "contagens_replay_consistentes_com_auditoria": agreeing,
        "comparacoes": len(COUNTER_PAIRS),
        "divergencias": mismatches,
        "lacunas_tcp_observadas": stats.get("lacunas_tcp", 0),
        "eventos_finais_sem_fronteira": stats.get(
            "candidate_ultimo_evento_sem_fronteira_comprovada", 0
        ),
        "homologacao_de_entrega_fim_a_fim": False,
        "historico_nat_automatico_permitido": False,
        "observacao": (
            "Contagens coincidentes validam o comportamento dos dois analisadores "
            "na amostra; nao demonstram perda zero, framing RFC6587, entrega ao "
            "rsyslog, integridade do historico ou identificacao de assinantes."
        ),
    }
