"""Zabbix output must contain only fixed numeric metrics, never customer data."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from fmn_filters.a10_zabbix_sender import (
    METRIC_NAMES, format_sender_lines, read_health,
)


def report(**updates):
    data = {
        "status": "operacional_na_amostra",
        "alertas_criticos": [], "alertas_atencao": [],
        "verificacoes_indisponiveis": [],
        "rsyslog_ativo": True,
        "tcp_5514": {"escutando": True, "fila_recebimento_maxima": 0},
        "timer_rotacao_ativo": True,
        "resultado_ultima_rotacao": "success",
        "segundos_desde_ultima_rotacao": 3316.4,
        "arquivo_ativo_modificado_ha_segundos": 0.0,
        "disco_livre_percentual": 77.71,
        "disco_livre_gib": 74.14, "total_logs_gib": 6.54,
        "arquivos_compactados": 29,
        "homologacao_entrega_syslog": False,
        "historico_cgnat_integral_comprovado": False,
        "inventario_de_armazenamento": {
            "other": "LSN:PortAllocated:TCP [100.64.64.12 34567 45.238.170.70 34567]"
        },
    }
    data.update(updates)
    return data


class A10SenderTests(unittest.TestCase):
    def test_real_flow_health_metrics_are_exact_and_scrubbed(self):
        result = format_sender_lines(report(), "flow")
        self.assertEqual(len(result.splitlines()), len(METRIC_NAMES))
        self.assertIn("flow orbymon.a10.health.state 0\n", result)
        self.assertIn("flow orbymon.a10.disk.free.pct 77.71\n", result)
        self.assertIn("flow orbymon.a10.rotate.last.age 3316.4\n", result)
        self.assertIn("flow orbymon.a10.logs.total.gib 6.54\n", result)
        for private in ("100.64.64.12", "34567", "45.238.170.70", "LSN:"):
            self.assertNotIn(private, result)

    def test_attention_critical_and_unknown_state(self):
        for key, number in [("atencao", "1"), ("critico", "2"), ("inconclusivo", "3")]:
            output = format_sender_lines(report(status=key), "flow")
            self.assertIn(f"flow orbymon.a10.health.state {number}\n", output)
        unknown = format_sender_lines(report(rsyslog_ativo=None, resultado_ultima_rotacao=None), "flow")
        self.assertIn("flow orbymon.a10.rsyslog.active -1\n", unknown)
        self.assertIn("flow orbymon.a10.rotate.last.success -1\n", unknown)

    def test_reject_malicious_hostname(self):
        with self.assertRaises(ValueError):
            format_sender_lines(report(), "flow\nalert harmful 1")
        with self.assertRaises(ValueError):
            format_sender_lines(report(), "host with spaces")

    def test_reject_report_that_claims_homologation(self):
        with self.assertRaises(ValueError):
            format_sender_lines(report(homologacao_entrega_syslog=True), "flow")
        with self.assertRaises(ValueError):
            format_sender_lines(report(homologacao_entrega_syslog=None), "flow")

    def test_invalid_numbers_rejected(self):
        for value in (float("nan"), float("inf"), -50, "oops"):
            with self.assertRaises(ValueError):
                format_sender_lines(report(disco_livre_gib=value), "flow")

    def test_read_file_with_size_and_symlink_safety(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "health.json"
            path.write_text(json.dumps(report()))
            self.assertEqual(read_health(path)["status"], "operacional_na_amostra")
            link = Path(tmp) / "link"
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                read_health(link)


if __name__ == "__main__":
    unittest.main()
