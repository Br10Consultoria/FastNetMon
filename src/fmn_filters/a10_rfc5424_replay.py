"""Offline A10 RFC5424 stream replay with bounded buffering (aggregate only).

This module is a read-only prototype for replay of captured TCP payloads.
It recognizes *candidate* event boundaries using a following RFC5424
header. The A10's TCP stream has no observed RFC6587 delimiter: a
syntactically recognizable message is NOT a proven delivered NAT record.

No subscriber address, port, timestamp, raw event or credential is
ever returned or persisted. TCP gaps and unbounded trailing events are
quarantined by design.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime

from .a10_nat_candidate_audit import (
    HEADER, _classify_event, _other_event_group,
)
from .a10_syslog_inspect import candidate_mappings


class OfflineA10Replay:
    """Classifies candidates across arbitrary read() boundaries.

    Call feed() for each byte chunk in a *single TCP-contiguous span*.
    Call close_span() at each TCP gap, stream end or snapshot boundary.
    This is NOT a network server, rsyslog input, DB writer or collector.
    """

    def __init__(self, *, max_pending_bytes: int = 8192):
        if not 256 <= max_pending_bytes <= 1048576:
            raise ValueError("Limite de buffer fora do intervalo permitido")
        self._max_pending = max_pending_bytes
        self._pending = bytearray()
        self._counters: Counter[str] = Counter()

    def feed(self, chunk: bytes) -> None:
        if not isinstance(chunk, bytes):
            raise TypeError("Um chunk de bytes e obrigatorio")
        if not chunk:
            return
        self._counters["bytes_processados"] += len(chunk)
        self._pending.extend(chunk)
        matches = list(HEADER.finditer(self._pending))
        if len(matches) >= 2:
            if matches[0].start():
                self._counters["prefixos_sem_cabecalho"] += 1
            for first, second in zip(matches, matches[1:]):
                raw_header = self._pending[first.start():first.end()]
                try:
                    pri = int(first.group("priority"))
                    ts = datetime.fromisoformat(
                        first.group("time").decode("ascii").replace("Z", "+00:00")
                    )
                    if not 0 <= pri <= 191 or ts.tzinfo is None:
                        raise ValueError("header invalido")
                except (ValueError, UnicodeDecodeError):
                    self._counters["cabecalhos_invalidos"] += 1
                    continue
                # The next candidate header is the heuristic boundary. Do
                # not interpret appended data after ']' as legal NAT records.
                payload = bytes(self._pending[first.end():second.start()])
                self._count_payload(payload)
            self._pending = bytearray(self._pending[matches[-1].start():])
        elif len(matches) == 1 and matches[0].start():
            self._counters["prefixos_sem_cabecalho"] += 1
            self._pending = bytearray(self._pending[matches[0].start():])

        if len(self._pending) > self._max_pending:
            # Fail closed, preserving only enough tail to recognize a header
            # split across subsequent reads. No oversized body is accepted.
            self._counters["buffers_acima_do_limite"] += 1
            self._pending = self._pending[-min(100, self._max_pending):]

    def _count_payload(self, payload: bytes) -> None:
        self._counters["eventos_delimitados_por_cabecalho_seguinte"] += 1
        status = _classify_event(payload)
        self._counters[status] += 1
        if status == "outro_tipo_ou_sem_nat_tcp_udp":
            self._counters["outro_" + _other_event_group(payload)] += 1
        elif status == "nat_sintaticamente_candidato":
            # candidate_mappings returns an internal object but we export
            # only the whitelisted protocol and operation, never its fields.
            record = next(candidate_mappings(payload.decode("ascii")), None)
            if record is not None:
                protocol = record["protocol"]
                operation = record["event"]
                self._counters["nat_" + operation + "_" + protocol] += 1

    def close_span(self) -> None:
        """Discard ambiguous tail at each TCP gap/stream-end."""
        if self._pending:
            if HEADER.search(self._pending):
                self._counters["eventos_finais_sem_fronteira_confiavel"] += 1
            else:
                self._counters["trechos_terminais_sem_cabecalho"] += 1
        self._pending.clear()
        self._counters["trechos_fechados"] += 1

    def snapshot(self) -> dict[str, int]:
        """Aggregate counters only; never return the pending byte buffer."""
        return dict(sorted(self._counters.items()))
