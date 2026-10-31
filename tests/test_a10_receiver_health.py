"""Receiver health test coverage: passive checks, thresholds and no secrets."""
import json
from unittest import TestCase
from unittest.mock import patch

from fmn_filters.a10_receiver_health import (
    _listener_summary, _rotation_age, evaluate_health, probe,
)


def _storage(**kw):
    result = {
        "arquivo_ativo_existe": True,
        "arquivo_ativo_sem_modificacao_segundos": 0,
        "disco_livre_percentual": 78.59,
        "disco_livre_gib": 74.98,
        "total_de_arquivos_regulares_gib": 5.71,
        "grupos": {"rotacionados_comprimidos": {"arquivos": 29}},
    }
    result.update(kw)
    return result


def _evaluate(**kw):
    data = {
        "rsyslog_active": True,
        "listener": {
            "verificavel": True, "escutando": True, "escutas": 1,
            "fila_recebimento_maxima": 0, "backlog_configurado_maximo": 25,
        },
        "timer_active": True,
        "rotation_result": "success",
        "rotation_last_age_seconds": 1400,
        "storage": _storage(),
    }
    data.update(kw)
    return evaluate_health(**data)


class ReceiverHealthTests(TestCase):
    def test_live_profile_reports_operational_not_homologated(self):
        report = _evaluate()
        self.assertEqual(report["status"], "operacional_na_amostra")
        self.assertFalse(report["homologacao_entrega_syslog"])
        self.assertFalse(report["historico_cgnat_integral_comprovado"])
        self.assertEqual(report["arquivos_compactados"], 29)
        self.assertEqual(report["disco_livre_gib"], 74.98)

    def test_critical_when_rsyslog_or_listener_unavailable(self):
        down = _evaluate(rsyslog_active=False)
        self.assertEqual(down["status"], "critico")
        self.assertIn("rsyslog_inativo", down["alertas_criticos"])
        not_listening = _evaluate(listener={"escutando": False})
        self.assertIn("tcp_5514_sem_escuta", not_listening["alertas_criticos"])

    def test_critical_for_stale_log_and_low_disk(self):
        stale = _evaluate(storage=_storage(
            arquivo_ativo_sem_modificacao_segundos=301,
            disco_livre_percentual=9.5,
        ))
        self.assertEqual(stale["status"], "critico")
        self.assertIn("arquivo_sem_gravacao_recente", stale["alertas_criticos"])
        self.assertIn("disco_livre_abaixo_10_porcento", stale["alertas_criticos"])

    def test_warning_for_rotation_delay_timer_fail_disk_or_queue(self):
        report = _evaluate(
            timer_active=False, rotation_result="exit-code",
            rotation_last_age_seconds=6000,
            listener={"escutando": True, "fila_recebimento_maxima": 10},
            storage=_storage(arquivo_ativo_sem_modificacao_segundos=121,
                             disco_livre_percentual=15),
        )
        self.assertEqual(report["status"], "atencao")
        self.assertEqual(len(report["alertas_atencao"]), 6)

    def test_indeterminate_when_checks_not_available(self):
        result = _evaluate(rsyslog_active=None,
                           listener={"escutando": None},
                           timer_active=None, rotation_result=None,
                           rotation_last_age_seconds=None)
        self.assertEqual(result["status"], "inconclusivo")
        self.assertGreater(len(result["verificacoes_indisponiveis"]), 3)

    def test_socket_summary_never_prints_addresses_or_peer_ports(self):
        sample = (
            "LISTEN 0 25 0.0.0.0:5514 0.0.0.0:*\n"
            "LISTEN 2 32 [::]:5514 [::]:*\n"
            "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
        )
        with patch("fmn_filters.a10_receiver_health._run", return_value=sample):
            report = _listener_summary(5514)
        self.assertTrue(report["escutando"])
        self.assertEqual(report["escutas"], 2)
        self.assertEqual(report["fila_recebimento_maxima"], 2)
        self.assertEqual(report["backlog_configurado_maximo"], 32)
        self.assertNotIn("0.0.0.0", json.dumps(report))

    def test_missing_ss_reports_unknown_not_no_listener(self):
        with patch("fmn_filters.a10_receiver_health._run", return_value=None):
            self.assertIsNone(_listener_summary(5514)["escutando"])

    def test_rotation_no_last_timestamp_is_not_success_evidence(self):
        self.assertIsNone(_rotation_age({"ExecMainExitTimestampMonotonic": "0"}))
        self.assertIsNone(_rotation_age(None))

    def test_full_probe_only_invokes_read_only_helpers(self):
        with (patch("fmn_filters.a10_receiver_health.inventory", return_value=_storage()),
              patch("fmn_filters.a10_receiver_health._systemd_properties") as props,
              patch("fmn_filters.a10_receiver_health._listener_summary",
                    return_value={"escutando": True, "fila_recebimento_maxima": 0}),
              patch("fmn_filters.a10_receiver_health._rotation_age", return_value=1500)):
            props.side_effect = [
                {"ActiveState": "active"}, {"ActiveState": "active"},
                {"Result": "success"},
            ]
            r = probe(port=5514)
        self.assertEqual(r["status"], "operacional_na_amostra")
        self.assertEqual(r["porta_tcp_observada"], 5514)
        self.assertFalse(r["historico_cgnat_integral_comprovado"])
        self.assertNotIn("100.64.64.12", json.dumps(r))


if __name__ == "__main__":
    import unittest
    unittest.main()
