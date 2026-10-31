"""Offline TCP framing probe for A10 Syslog PCAP (read-only, aggregate-only).

Input may contain confidential NAT events. It is never printed or persisted by
this program. No subscriber identity or NAT mapping is derived here.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass, field
import ipaddress
import json
from pathlib import Path
import re
import struct
import sys

HEADER = re.compile(rb"<\d{1,3}>1\s+\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\s")
OCTET = re.compile(rb"([1-9][0-9]{0,7}) $")
MAGIC = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
         b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}


@dataclass
class Stream:
    seen_syn: bool = False
    seen_fin: bool = False
    seen_rst: bool = False
    initial_seq: int | None = None
    final_seq: int | None = None
    segments: list[tuple[int, bytes]] = field(default_factory=list)


def read_pcap(path: Path, stats: Counter, *, max_file_bytes: int):
    if not path.is_file() or path.is_symlink():
        raise ValueError("Arquivo PCAP regular obrigatorio (sem link simbolico)")
    if path.stat().st_size > max_file_bytes:
        raise ValueError("Captura excede o limite de leitura; dividir a captura localmente")
    with path.open("rb") as handle:
        hdr = handle.read(24)
        if len(hdr) != 24 or hdr[:4] not in MAGIC:
            raise ValueError("PCAP classico invalido; pcapng nao e suportado")
        endian = MAGIC[hdr[:4]]
        major, minor, _, _, snaplen, link = struct.unpack(endian + "HHiIII", hdr[4:])
        if (major, minor) != (2, 4) or not 64 <= snaplen <= 1048576:
            raise ValueError("Cabecalho PCAP invalido")
        link &= 0xFFFF
        if link not in (1, 101, 113, 276):
            raise ValueError("Tipo de enlace nao suportado (Ethernet/SLL/SLL2/RAW)")
        while True:
            rec = handle.read(16)
            if not rec:
                return
            if len(rec) != 16:
                stats["pacotes_incompletos"] += 1
                return
            _, _, included, original = struct.unpack(endian + "IIII", rec)
            if included > snaplen or included > 1048576 or included > original:
                stats["pacotes_incompletos"] += 1
                return
            pkt = handle.read(included)
            if len(pkt) != included:
                stats["pacotes_incompletos"] += 1
                return
            stats["pacotes_total"] += 1
            if included != original:
                stats["pacotes_truncados_snaplen"] += 1
                continue
            yield link, pkt


def tcp_packet(link: int, pkt: bytes):
    if link == 1:
        if len(pkt) < 14:
            return None
        kind = int.from_bytes(pkt[12:14], "big")
        pos = 14
        while kind in (0x8100, 0x88A8, 0x9100):
            if len(pkt) < pos + 4:
                return None
            kind = int.from_bytes(pkt[pos + 2:pos + 4], "big")
            pos += 4
    elif link == 113:
        if len(pkt) < 16:
            return None
        kind = int.from_bytes(pkt[14:16], "big")
        pos = 16
    elif link == 276:
        if len(pkt) < 20:
            return None
        kind = int.from_bytes(pkt[:2], "big")
        pos = 20
    else:
        pos = 0
        kind = 0x0800 if pkt and pkt[0] >> 4 == 4 else 0
    if kind != 0x0800 or len(pkt) < pos + 20:
        return None
    ip = pkt[pos:]
    ihl = (ip[0] & 15) * 4
    total = int.from_bytes(ip[2:4], "big")
    fragment = int.from_bytes(ip[6:8], "big")
    if (ip[0] >> 4 != 4 or ihl < 20 or len(ip) < total or
            total < ihl + 20 or ip[9] != 6 or fragment & 0x3FFF):
        return None
    tcp = ip[ihl:total]
    off = (tcp[12] >> 4) * 4
    if off < 20 or off > len(tcp):
        return None
    source_port, dest_port, seq = struct.unpack_from("!HHI", tcp)
    return (ip[12:16], source_port, ip[16:20], dest_port,
            seq + bool(tcp[13] & 2), bool(tcp[13] & 2),
            bool(tcp[13] & 1), bool(tcp[13] & 4), tcp[off:])


def spans_for_stream(stream: Stream, stats: Counter):
    """Sorted TCP reassembly; gaps create separate spans, never invented bytes."""
    if not stream.segments:
        return []
    segments = sorted(stream.segments, key=lambda item: item[0])
    if stream.initial_seq is not None and segments[0][0] != stream.initial_seq:
        stats["lacunas_tcp_inicio"] += 1
        stats["lacunas_tcp_inicio_bytes"] += segments[0][0] - stream.initial_seq
    if segments[-1][0] - segments[0][0] > 0x80000000:
        stats["fluxos_com_seq_wrap_nao_suportado"] += 1
        return []
    spans = []
    current = bytearray()
    expected = None
    for seq, chunk in segments:
        if expected is None:
            current.extend(chunk)
            expected = seq + len(chunk)
        elif seq > expected:
            stats["lacunas_tcp"] += 1
            stats["lacunas_tcp_bytes"] += seq - expected
            spans.append(bytes(current))
            current = bytearray(chunk)
            expected = seq + len(chunk)
        elif seq == expected:
            current.extend(chunk)
            expected += len(chunk)
        else:
            overlap = min(expected - seq, len(chunk))
            if seq >= expected - len(current):
                begin = seq - (expected - len(current))
                if current[begin:begin + overlap] != chunk[:overlap]:
                    stats["sobreposicoes_conflitantes"] += 1
            if overlap == len(chunk):
                stats["retransmissoes_ou_duplicacoes"] += 1
            else:
                current.extend(chunk[overlap:])
                expected += len(chunk) - overlap
    if stream.final_seq is not None and expected != stream.final_seq:
        stats["lacunas_tcp_fim"] += 1
    if current:
        spans.append(bytes(current))
    stats["trechos_tcp_contiguos"] += len(spans)
    return spans


def inspect_span(data: bytes, stats: Counter, *, audit_nat_candidates=False):
    if audit_nat_candidates:
        from .a10_nat_candidate_audit import inspect_candidate_stream
        nat_counts = inspect_candidate_stream(data)
        for key, value in nat_counts.items():
            stats["candidate_" + key] += value
    headers = list(HEADER.finditer(data))
    stats["cabecalhos_rfc5424"] += len(headers)
    if not headers:
        return
    for m in headers[1:]:
        previous = data[m.start() - 1]
        if previous == ord("]"):
            stats["fronteiras_coladas_apos_colchete"] += 1
        elif previous == 10:
            stats["fronteiras_com_lf"] += 1
        elif previous == 0:
            stats["fronteiras_com_nul"] += 1
        elif previous == 32:
            stats["fronteiras_com_espaco"] += 1
        else:
            stats["fronteiras_outras"] += 1
    # RFC6587 octet counting: validate the length against the next prefix,
    # not only the existence of a number before an RFC5424 header.
    for m in headers:
        begin = max(0, m.start() - 10)
        prefix = OCTET.search(data[begin:m.start()])
        if prefix is None or begin + prefix.end() != m.start():
            continue
        stats["prefixos_octet_counting_candidatos"] += 1
        length = int(prefix.group(1))
        end = m.start() + length
        if end > len(data):
            stats["frames_octet_truncados_no_recorte"] += 1
        elif end == len(data) or re.match(rb"[1-9][0-9]{0,7} <\d{1,3}>1\s", data[end:]):
            stats["frames_octet_com_comprimento_coerente"] += 1
        else:
            stats["frames_octet_com_comprimento_incoerente"] += 1


def audit(path: Path, *, source_ip: str = "10.100.10.10", port: int = 5514,
          max_file_bytes: int = 128000000, max_payload_bytes: int = 32000000,
          audit_nat_candidates: bool = False, audit_offline_replay: bool = False):
    try:
        address = ipaddress.IPv4Address(source_ip).packed
    except ipaddress.AddressValueError as exc:
        raise ValueError("Origem IPv4 invalida") from exc
    if not (1 <= port <= 65535 and 1024 <= max_payload_bytes <= 128000000
            and max_payload_bytes <= max_file_bytes <= 512000000):
        raise ValueError("Limites invalidos")
    stats = Counter()
    current = {}
    sessions = []
    payload_stored = 0
    for link, raw in read_pcap(path, stats, max_file_bytes=max_file_bytes):
        decoded = tcp_packet(link, raw)
        if decoded is None:
            stats["pacotes_nao_ipv4_tcp_validos"] += 1
            continue
        src, sport, dst, dport, seq, syn, fin, rst, payload = decoded
        if src != address or dport != port:
            continue
        stats["pacotes_syslog_a10"] += 1
        key = (src, sport, dst, dport)
        if syn or key not in current:
            stream = Stream()
            current[key] = stream
            sessions.append(stream)
        stream = current[key]
        stream.seen_syn |= syn
        stream.seen_fin |= fin
        stream.seen_rst |= rst
        if syn:
            stream.initial_seq = seq
        if fin:
            stream.final_seq = seq + len(payload)
        if payload:
            if payload_stored + len(payload) > max_payload_bytes:
                stats["segmentos_descartados_por_limite"] += 1
                continue
            stream.segments.append((seq, payload))
            payload_stored += len(payload)
    stats["conexoes_observadas"] = len(sessions)
    stats["conexoes_sem_syn_na_captura"] = sum(not s.seen_syn for s in sessions)
    stats["conexoes_sem_fin_na_captura"] = sum(not s.seen_fin for s in sessions)
    stats["conexoes_com_rst"] = sum(s.seen_rst for s in sessions)
    stats["conexoes_sem_fin_nem_rst_na_captura"] = sum(
        not s.seen_fin and not s.seen_rst for s in sessions
    )
    # Identify exactly which observed TCP connection has sequence gaps,
    # without exporting 4-tuples, raw packet bytes or sequence numbers.
    gap_details = []
    for index, stream in enumerate(sessions, 1):
        local = Counter()
        spans = spans_for_stream(stream, local)
        stats.update(local)
        if local["lacunas_tcp"] or local["lacunas_tcp_inicio"] or local["lacunas_tcp_fim"]:
            detail = {
                "conexao_indice_na_captura": index,
                "syn_observado": stream.seen_syn,
                "fin_observado": stream.seen_fin,
                "rst_observado": stream.seen_rst,
                "segmentos_com_payload": len(stream.segments),
                "trechos_tcp_contiguos": len(spans),
                "lacunas_tcp": local["lacunas_tcp"],
                "lacunas_tcp_bytes": local["lacunas_tcp_bytes"],
                "lacunas_tcp_inicio": local["lacunas_tcp_inicio"],
                "lacunas_tcp_inicio_bytes": local["lacunas_tcp_inicio_bytes"],
                "lacunas_tcp_fim": local["lacunas_tcp_fim"],
            }
            if local["lacunas_tcp"]:
                from .a10_tcp_gap_edges import classify_gap_edges
                detail["contexto_estrutural_das_lacunas"] = classify_gap_edges(spans)
            if len(gap_details) < 20:
                gap_details.append(detail)
            else:
                stats["conexoes_com_lacunas_omitidas_por_limite"] += 1
        for span in spans:
            inspect_span(span, stats, audit_nat_candidates=audit_nat_candidates)
            if audit_offline_replay:
                from .a10_rfc5424_replay import OfflineA10Replay
                probe = OfflineA10Replay()
                # Artificial chunks exercise stream-boundary handling on
                # already reconstructed TCP spans, never on raw packets.
                for offset in range(0, len(span), 4096):
                    probe.feed(span[offset:offset + 4096])
                probe.close_span()
                for key, value in probe.snapshot().items():
                    stats["replay_" + key] += value
    if stats["fronteiras_coladas_apos_colchete"]:
        classification = "concatenacao_sem_delimitador_visivel"
    elif stats["frames_octet_com_comprimento_coerente"]:
        classification = "octet_counting_compativel_na_amostra"
    elif stats["fronteiras_com_lf"] or stats["fronteiras_com_nul"]:
        classification = "delimitacao_lf_ou_nul_compativel_na_amostra"
    else:
        classification = "inconclusivo"
    can_rely_on_capture = (bool(stats["cabecalhos_rfc5424"]) and not any(stats[key] for key in
        ("pacotes_truncados_snaplen", "pacotes_incompletos", "lacunas_tcp",
         "lacunas_tcp_inicio", "lacunas_tcp_fim",
         "sobreposicoes_conflitantes", "segmentos_descartados_por_limite",
         "fluxos_com_seq_wrap_nao_suportado", "conexoes_sem_syn_na_captura",
         "conexoes_sem_fin_na_captura", "conexoes_com_rst")))
    result = {
        "status": "ok", "classificacao_framing_na_amostra": classification,
        "captura_tcp_completa_no_intervalo_observado": can_rely_on_capture,
        "contadores": dict(sorted(stats.items())),
        "diagnostico_de_lacunas_por_conexao": gap_details,
        "correlacao_automatica_permitida": False,
        "aviso": "Nao comprova integridade de historico NAT, entrega ao rsyslog, identificacao de assinantes ou conformidade legal. Nao habilita persistencia."
    }
    if audit_nat_candidates and audit_offline_replay:
        from .a10_replay_consistency import compare_replay_counters
        result["verificacao_de_consistencia_offline"] = compare_replay_counters(stats)
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description="Auditoria offline PCAP A10 TCP Syslog, somente contadores")
    ap.add_argument("--pcap", type=Path, required=True)
    ap.add_argument("--source-ip", default="10.100.10.10")
    ap.add_argument("--port", type=int, default=5514)
    ap.add_argument("--max-file-bytes", type=int, default=128000000)
    ap.add_argument("--audit-nat-candidates", action="store_true",
                    help="Apenas contagens estruturais; nunca persiste mapeamentos NAT")
    ap.add_argument("--audit-offline-replay", action="store_true",
                    help="Replay isolado de spans TCP em blocos; apenas contadores agregados")
    ap.add_argument("--max-payload-bytes", type=int, default=32000000)
    args = ap.parse_args(argv)
    try:
        result = audit(args.pcap, source_ip=args.source_ip, port=args.port,
                       max_file_bytes=args.max_file_bytes,
                       max_payload_bytes=args.max_payload_bytes,
                       audit_nat_candidates=args.audit_nat_candidates,
                       audit_offline_replay=args.audit_offline_replay)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except (OSError, ValueError, struct.error) as exc:
        print("Falha na auditoria PCAP A10: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
