"""A10: conservative, aggregate-only checks of RFC5424 NAT event candidates.

This does NOT prove TCP/Syslog reliability, legally complete NAT logs, or
subscriber ownership. No IP address/port from the captured payload is returned
or printed. Designed solely for offline PCAP analysis.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
import re

from .a10_syslog_inspect import candidate_mappings

# Header recognition is provisional: it cannot substitute RFC6587 framing.
HEADER = re.compile(
    rb"<(?P<priority>\d{1,3})>1[ ]+"
    rb"(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    rb"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))(?=\s)"
)
NAT_MARKER = re.compile(rb"LSN:Port(?:Allocated|Allocation|Freed):(?:TCP|UDP)", re.I)

# The unknown-event histogram uses only fixed, non-sensitive category names.
# Never use arbitrary values from payload as a JSON key or print event text.
OTHER_LSN_MARKER = re.compile(rb"LSN:([A-Za-z][A-Za-z0-9_-]{0,31})", re.I)


def _other_event_group(payload: bytes) -> str:
    """Return a fixed label for non-TCP/UDP-PortAllocated/PortFreed events."""
    match = OTHER_LSN_MARKER.search(payload)
    if match is None:
        return "sem_marcador_lsn"
    marker = match.group(1).lower()
    if marker.startswith(b"icmp"):
        return "lsn_icmp"
    if marker.startswith(b"gre"):
        return "lsn_gre"
    if marker.startswith(b"esp"):
        return "lsn_esp"
    if b"batch" in marker or marker.startswith(b"portblock"):
        return "lsn_lote_portas"
    if marker.startswith(b"session"):
        return "lsn_sessao"
    return "lsn_outro_marcador"


def _classify_event(payload: bytes) -> str:
    """Classify only the structure. IP/port data never leave this function."""
    if len(payload) > 8192:
        return "corpo_acima_limite"
    marker_count = len(NAT_MARKER.findall(payload))
    if not marker_count:
        return "outro_tipo_ou_sem_nat_tcp_udp"
    if marker_count != 1 or payload.count(b"LSN:") != 1:
        return "marcadores_ambiguos"
    if not payload.rstrip().endswith(b"]"):
        return "nat_sem_terminador"
    # A10's documented format is ASCII. Decoding failures are not
    # repaired or silently discarded for forensic purposes.
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError:
        return "corpo_nao_ascii"
    mappings = list(candidate_mappings(text))
    if len(mappings) != 1:
        return "nat_mapeamento_invalido_ou_fora_pool"
    # Reject trailing fields after the candidate mapping's closing bracket.
    # Only whitespace is permitted after the final ']' in this test.
    if text.rstrip()[-1:] != "]":
        return "nat_sem_terminador"
    return "nat_sintaticamente_candidato"


def inspect_candidate_stream(data: bytes) -> dict[str, int]:
    """Count only structurally bounded events: two successive RFC5424 headers.

    A last event (even with a closing bracket) has no authenticated boundary.
    An initial fragment before the first header is excluded. This function
    does not know TCP sequence continuity; caller must report gaps separately.
    """
    stats: Counter[str] = Counter()
    headers = list(HEADER.finditer(data))
    stats["cabecalhos_detectados"] = len(headers)
    if not headers:
        if data:
            stats["trecho_sem_cabecalho"] = 1
        return dict(stats)
    if headers[0].start() > 0:
        stats["prefixo_sem_cabecalho"] = 1
    # A span end does not define the end of an individual Syslog event.
    stats["ultimo_evento_sem_fronteira_comprovada"] = 1
    for h, following in zip(headers, headers[1:]):
        stats["eventos_delimitados_por_outro_cabecalho"] += 1
        try:
            priority = int(h.group("priority"))
            ts = datetime.fromisoformat(h.group("time").decode("ascii").replace("Z", "+00:00"))
            if not 0 <= priority <= 191 or ts.tzinfo is None:
                raise ValueError("invalid header")
        except (ValueError, UnicodeDecodeError):
            stats["cabecalho_invalido"] += 1
            continue
        payload = data[h.end():following.start()]
        status = _classify_event(payload)
        stats[status] += 1
        if status == "outro_tipo_ou_sem_nat_tcp_udp":
            stats["detalhe_outro_" + _other_event_group(payload)] += 1
        elif status == "nat_sintaticamente_candidato":
            # The event and protocol are from strict whitelists in
            # candidate_mappings, not user-supplied output strings.
            mapping = next(candidate_mappings(payload.decode("ascii")), None)
            if mapping:
                stats["detalhe_nat_" + mapping["event"] + "_" + mapping["protocol"]] += 1
    return dict(stats)
