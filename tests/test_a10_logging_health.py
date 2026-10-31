import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from fmn_filters.a10_logging_health import (
    compare, parse_snapshot, read_snapshot,
)

PREVIOUS = """NAT Logging Statistics:
-----------------------
TCP Port Allocated                                           62276450
TCP Port Freed                                               62254966
UDP Port Allocated                                           95469644
UDP Port Freed                                               95446525
ICMP Resource Allocated                                      10323807
ICMP Resource Freed                                          10323800
Log Packets Sent                                             336092243
Log Packets Dropped                                          2629
TCP Connection Established                                   15
TCP Connection Lost                                          30
"""

NEXT = """NAT Logging Statistics:
-----------------------
TCP Port Allocated                                           62277450
TCP Port Freed                                               62255966
UDP Port Allocated                                           95471644
UDP Port Freed                                               95448525
ICMP Resource Allocated                                      10323817
ICMP Resource Freed                                          10323809
Log Packets Sent                                             336102243
Log Packets Dropped                                          2632
TCP Connection Established                                   16
TCP Connection Lost                                          31
"""


class A10LoggingHealthTests(unittest.TestCase):
    def test_parse_and_counter_deltas(self):
        a = parse_snapshot(PREVIOUS)
        b = parse_snapshot(NEXT)
        result = compare(a, b, 60)
        self.assertEqual(result["delta"]["log_packets_sent"], 10000)
        self.assertEqual(result["delta"]["log_packets_dropped"], 3)
        self.assertEqual(result["delta"]["icmp_resource_allocated"], 10)
        self.assertEqual(result["conexoes_tcp_de_logging_perdidas_no_intervalo"], 1)
        self.assertEqual(result["pacotes_log_enviados_por_segundo"], 166.67)
        self.assertEqual(result["status"], "incrementos_de_erro")
        self.assertFalse(result["integridade_do_logging_comprovada"])
        self.assertFalse(result["framing_rfc6587_homologado"])

    def test_zero_delta_does_not_claim_integrity(self):
        a = parse_snapshot(PREVIOUS)
        result = compare(a, a, 60)
        self.assertIsNone(result["proporcao_descartada_dos_pacotes_contabilizados_percentual"])
        self.assertEqual(result["status"], "sem_incremento_de_erro_nos_contadores")
        self.assertFalse(result["integridade_do_logging_comprovada"])

    def test_counter_reset_rejects_rates(self):
        before = parse_snapshot(PREVIOUS)
        after = parse_snapshot(NEXT)
        after["Log Packets Sent"] = 2
        result = compare(before, after, 60)
        self.assertEqual(result["status"], "contadores_reiniciados_ou_wrap")
        self.assertFalse(result["taxas_validas"])
        self.assertNotIn("pacotes_log_enviados_por_segundo", result)

    def test_duplicate_and_missing_required_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicado"):
            parse_snapshot(PREVIOUS + "Log Packets Sent    999\n")
        with self.assertRaisesRegex(ValueError, "incompleto"):
            parse_snapshot("Log Packets Sent    1\n")

    def test_interval_guardrails(self):
        a = parse_snapshot(PREVIOUS)
        with self.assertRaises(ValueError):
            compare(a, a, 0)
        with self.assertRaises(ValueError):
            compare(a, a, 90000)

    def test_confidential_text_is_not_reported(self):
        a = parse_snapshot(PREVIOUS + "password = dont-share-this-secret\n")
        out = json.dumps(compare(a, a, 60))
        self.assertNotIn("dont-share-this-secret", out)

    def test_file_parsing_and_symlink_rejection(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "stats.txt"
            path.write_text(PREVIOUS)
            self.assertEqual(read_snapshot(path)["Log Packets Dropped"], 2629)
            symlink = Path(directory) / "shortcut"
            symlink.symlink_to(path)
            with self.assertRaisesRegex(ValueError, "regular"):
                read_snapshot(symlink)


if __name__ == "__main__":
    unittest.main()
