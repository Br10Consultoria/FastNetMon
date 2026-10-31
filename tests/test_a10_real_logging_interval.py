"""Reconcile measured A10 interval statistics without equating counters to delivery."""
import unittest

from fmn_filters.a10_logging_health import (
    compare, parse_snapshot, reconcile_log_sent_with_events,
)

BEFORE = """NAT Logging Statistics:
TCP Port Allocated                                          64473214
TCP Port Freed                                              64451447
UDP Port Allocated                                          98746827
UDP Port Freed                                              98724267
ICMP Resource Allocated                                     10655007
ICMP Resource Freed                                         10654962
Log Packets Sent                                            347702775
Log Packets Dropped                                         2629
TCP Connection Established                                  15
TCP Connection Lost                                         30
"""
AFTER = """NAT Logging Statistics:
TCP Port Allocated                                          64522289
TCP Port Freed                                              64501236
UDP Port Allocated                                          98817707
UDP Port Freed                                              98797250
ICMP Resource Allocated                                     10662314
ICMP Resource Freed                                         10662317
Log Packets Sent                                            347960164
Log Packets Dropped                                         2629
TCP Connection Established                                  15
TCP Connection Lost                                         30
"""


class A10RealCounterReconciliationTests(unittest.TestCase):
    def test_real_flow_interval_exact_reconciliation(self):
        report = compare(parse_snapshot(BEFORE), parse_snapshot(AFTER), 73)
        self.assertEqual(report["status"], "sem_incremento_de_erro_nos_contadores")
        self.assertEqual(report["delta"]["log_packets_sent"], 257389)
        self.assertEqual(report["delta"]["log_packets_dropped"], 0)
        self.assertEqual(report["delta"]["tcp_connection_lost"], 0)
        self.assertEqual(report["pacotes_log_enviados_por_segundo"], 3525.88)
        r = report["reconciliacao_contadores_nat_e_log_sent"]
        self.assertEqual(r["eventos_tcp"], 98864)
        self.assertEqual(r["eventos_udp"], 143863)
        self.assertEqual(r["eventos_icmp"], 14662)
        self.assertEqual(r["soma_eventos_nat"], 257389)
        self.assertEqual(r["log_packets_sent_delta"], 257389)
        self.assertEqual(r["diferenca_log_sent_menos_eventos"], 0)
        self.assertTrue(r["concordancia_contadores_internos"])
        self.assertFalse(r["entrega_ao_servidor_comprovada"])
        self.assertFalse(report["integridade_do_logging_comprovada"])

    def test_divergence_is_explicit_not_silent(self):
        delta = {
            "tcp_port_allocated": 1, "tcp_port_freed": 1,
            "udp_port_allocated": 1, "udp_port_freed": 1,
            "icmp_resource_allocated": 1, "icmp_resource_freed": 1,
            "log_packets_sent": 7,
        }
        r = reconcile_log_sent_with_events(delta)
        self.assertEqual(r["status"], "contadores_internos_divergem")
        self.assertEqual(r["diferenca_log_sent_menos_eventos"], 1)
        self.assertFalse(r["entrega_ao_servidor_comprovada"])

    def test_missing_optional_events_never_claims_reconciliation(self):
        delta = {"log_packets_sent": 10}
        r = reconcile_log_sent_with_events(delta)
        self.assertEqual(r["status"], "inconclusivo_sem_todos_os_contadores")
        self.assertIsNone(r["concordancia_contadores_internos"])
        self.assertEqual(len(r["contadores_ausentes"]), 6)

    def test_reset_remains_fail_closed(self):
        before = parse_snapshot(BEFORE)
        after = parse_snapshot(AFTER)
        after["UDP Port Allocated"] = 0
        r = compare(before, after, 73)
        self.assertEqual(r["status"], "contadores_reiniciados_ou_wrap")
        self.assertNotIn("reconciliacao_contadores_nat_e_log_sent", r)


if __name__ == "__main__":
    unittest.main()
