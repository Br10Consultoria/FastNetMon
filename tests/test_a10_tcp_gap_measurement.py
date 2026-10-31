import unittest
from collections import Counter

from fmn_filters.a10_tcp_framing import Stream, spans_for_stream


class A10TcpGapMeasurementsTests(unittest.TestCase):
    def test_exact_missing_byte_count_from_contiguous_segments(self):
        stream = Stream(initial_seq=101, final_seq=108,
                        segments=[(101, b"abc"), (106, b"xy")])
        stats = Counter()
        spans = spans_for_stream(stream, stats)
        self.assertEqual(spans, [b"abc", b"xy"])
        self.assertEqual(stats["lacunas_tcp"], 1)
        self.assertEqual(stats["lacunas_tcp_bytes"], 2)
        self.assertEqual(stats["trechos_tcp_contiguos"], 2)
        self.assertEqual(stats["lacunas_tcp_fim"], 0)

    def test_out_of_order_segments_are_not_a_gap(self):
        stream = Stream(initial_seq=101, final_seq=108,
                        segments=[(106, b"fg"), (101, b"abcde")])
        stats = Counter()
        spans = spans_for_stream(stream, stats)
        self.assertEqual(spans, [b"abcdefg"])
        self.assertEqual(stats["lacunas_tcp"], 0)
        self.assertEqual(stats["lacunas_tcp_bytes"], 0)
        self.assertEqual(stats["trechos_tcp_contiguos"], 1)

    def test_missing_initial_bytes_are_accounted_separately(self):
        stream = Stream(initial_seq=100, segments=[(108, b"abc")])
        stats = Counter()
        spans_for_stream(stream, stats)
        self.assertEqual(stats["lacunas_tcp_inicio"], 1)
        self.assertEqual(stats["lacunas_tcp_inicio_bytes"], 8)
        self.assertEqual(stats["lacunas_tcp"], 0)


if __name__ == "__main__":
    unittest.main()
