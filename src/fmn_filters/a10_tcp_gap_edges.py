"""Aggregate-only structural observations at missing TCP sequence intervals.

This is an offline forensic aid, NOT proof that the A10 emitted or dropped a
complete event. Never copies payloads, IPs, ports, timestamps or sequence IDs
into the output.
"""
from __future__ import annotations

from .a10_nat_candidate_audit import HEADER


def classify_gap_edges(spans: list[bytes], *, max_details: int = 10) -> dict:
    """Report boundary conditions between adjacent *contiguous* TCP spans.

    Missing sequence bytes lie between each pair of spans. The first and last
    events at each gap are untrusted, even if their syntax looks complete.
    """
    if not 0 <= max_details <= 100:
        raise ValueError("Limite de diagnostico fora do intervalo")
    details: list[dict] = []
    for index, (before, after) in enumerate(zip(spans, spans[1:]), 1):
        if len(details) == max_details:
            break
        previous = before.rstrip(b" \t\r\n\x00")
        next_header = HEADER.search(after)
        details.append({
            "indice_da_lacuna_na_conexao": index,
            "trecho_anterior_termina_colchete": previous.endswith(b"]"),
            "trecho_seguinte_inicia_cabecalho_rfc5424": bool(HEADER.match(after)),
            "trecho_seguinte_tem_cabecalho_rfc5424": next_header is not None,
            "bytes_antes_do_primeiro_cabecalho_seguinte": (
                next_header.start() if next_header is not None else None
            ),
            "eventos_adjacentes_nao_homologados": True,
        })
    return {
        "total_de_fronteiras_de_lacuna": max(0, len(spans) - 1),
        "detalhes": details,
        "detalhes_omitidos": max(0, len(spans) - 1 - len(details)),
    }
