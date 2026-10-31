"""Offline RFC5424 replay tests: read boundaries, loss isolation and privacy."""
import json
import unittest

from fmn_filters.a10_rfc5424_replay import OfflineA10Replay

HEADER = b"<135>1 2026-10-31T15:18:00-03:00 A10 CGNAT - - - "
ALLOCATED = b"LSN:PortAllocated:TCP [100.64.64.12 34055 45.238.170.70 34055]"
FREED = b"LSN:PortFreed:UDP [100.64.64.12 34055 45.238.170.70 34055]"
ICMP = b"LSN:ICMP [icmp event with synthetic content]"


class OfflineReplayTests(unittest.TestCase):
    def test_arbitrary_chunk_boundaries_and_all_event_classes(self):
        payload = HEADER + ALLOCATED + HEADER + FREED + HEADER + ICMP + HEADER
        replay = OfflineA10Replay()
        for pos in range(0, len(payload), 7):
            replay.feed(payload[pos:pos + 7])
        replay.close_span()
        stats = replay.snapshot()
        self.assertEqual(stats["eventos_delimitados_por_cabecalho_seguinte"], 3)
        self.assertEqual(stats["nat_sintaticamente_candidato"], 2)
        self.assertEqual(stats["nat_allocated_tcp"], 1)
        self.assertEqual(stats["nat_freed_udp"], 1)
        self.assertEqual(stats["outro_lsn_icmp"], 1)
        self.assertEqual(stats["eventos_finais_sem_fronteira_confiavel"], 1)
        self.assertEqual(stats["trechos_fechados"], 1)
        self.assertEqual(stats["bytes_processados"], len(payload))
        for sensitive in ("100.64.64.12", "34055", "45.238.170.70", "15:18:00"):
            self.assertNotIn(sensitive, json.dumps(stats))

    def test_do_not_bridge_gaps_even_when_event_looks_complete(self):
        replay = OfflineA10Replay()
        replay.feed(HEADER + ALLOCATED)
        replay.close_span()
        replay.feed(HEADER + FREED + HEADER)
        replay.close_span()
        stats = replay.snapshot()
        self.assertEqual(stats["eventos_delimitados_por_cabecalho_seguinte"], 1)
        self.assertEqual(stats["nat_freed_udp"], 1)
        self.assertEqual(stats["eventos_finais_sem_fronteira_confiavel"], 2)
        self.assertEqual(stats["trechos_fechados"], 2)

    def test_invalid_priority_not_accepted(self):
        replay = OfflineA10Replay()
        replay.feed(HEADER.replace(b"<135>", b"<999>") + ALLOCATED + HEADER)
        replay.close_span()
        stats = replay.snapshot()
        self.assertEqual(stats["cabecalhos_invalidos"], 1)
        self.assertEqual(stats.get("nat_sintaticamente_candidato", 0), 0)

    def test_bounded_buffer_fails_closed(self):
        replay = OfflineA10Replay(max_pending_bytes=256)
        replay.feed(HEADER + b"x" * 4000)
        replay.close_span()
        stats = replay.snapshot()
        self.assertGreater(stats["buffers_acima_do_limite"], 0)
        self.assertEqual(stats.get("nat_sintaticamente_candidato", 0), 0)

    def test_first_header_midstream_does_not_accept_prefix(self):
        replay = OfflineA10Replay()
        replay.feed(b"orphaned-secret-fragment" + HEADER + ALLOCATED + HEADER)
        replay.close_span()
        stats = replay.snapshot()
        self.assertEqual(stats["prefixos_sem_cabecalho"], 1)
        self.assertEqual(stats["nat_sintaticamente_candidato"], 1)
        self.assertNotIn("orphaned-secret-fragment", json.dumps(stats))

    def test_non_bytes_and_invalid_buffer_rejected(self):
        with self.assertRaises(ValueError):
            OfflineA10Replay(max_pending_bytes=16)
        probe = OfflineA10Replay()
        with self.assertRaises(TypeError):
            probe.feed("not bytes")


if __name__ == "__main__":
    unittest.main()
