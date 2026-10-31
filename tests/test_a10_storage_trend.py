"""Net A10 storage growth measures compressed retention, not raw ingest."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from fmn_filters.a10_storage_trend import compare_snapshots, read_snapshot


def sample(ts, total, free):
    return {
        "status": "ok", "arquivo_ativo_existe": True,
        "observado_em_utc": ts,
        "total_de_arquivos_regulares_bytes": total,
        "disco_livre_gib": free,
    }


class A10StorageTrendTests(unittest.TestCase):
    def test_growth_across_two_hourly_rotations(self):
        before = sample("2026-10-31T19:00:00+00:00", 6 * (1024 ** 3), 75)
        after = sample("2026-10-31T21:00:00+00:00", 7 * (1024 ** 3), 74)
        result = compare_snapshots(before, after)
        self.assertEqual(result["status"], "crescimento_liquido_observado")
        self.assertEqual(result["intervalo_segundos"], 7200)
        self.assertEqual(result["diretorio_cgnat_delta_gib"], 1.0)
        self.assertEqual(result["crescimento_liquido_estimado_gib_dia"], 12.0)
        self.assertEqual(result["dias_livres_estimados_pelo_crescimento_liquido"], 6.17)
        self.assertFalse(result["integridade_logs_comprovada"])
        self.assertFalse(result["retencao_homologada"])

    def test_short_interval_reports_no_projection(self):
        before = sample("2026-10-31T19:00:00+00:00", 1000, 75)
        after = sample("2026-10-31T19:15:00+00:00", 1000000, 74)
        result = compare_snapshots(before, after)
        self.assertEqual(result["status"], "intervalo_curto_para_projecao")
        self.assertIsNone(result["crescimento_liquido_estimado_gib_dia"])

    def test_compression_can_make_net_negative(self):
        before = sample("2026-10-31T19:00:00+00:00", 10 * (1024 ** 3), 75)
        after = sample("2026-10-31T21:00:00+00:00", 9 * (1024 ** 3), 76)
        result = compare_snapshots(before, after)
        self.assertEqual(result["status"], "sem_crescimento_liquido_positivo")
        self.assertIsNone(result["dias_livres_estimados_pelo_crescimento_liquido"])

    def test_invalid_or_unsorted_time_rejected(self):
        before = sample("2026-10-31T19:00:00+00:00", 1000, 75)
        after = sample("2026-10-31T18:00:00+00:00", 1000, 74)
        with self.assertRaises(ValueError):
            compare_snapshots(before, after)
        after["observado_em_utc"] = "2026-10-31T21:00:00"
        with self.assertRaises(ValueError):
            compare_snapshots(before, after)

    def test_missing_or_nonpositive_input_rejected(self):
        before = sample("2026-10-31T19:00:00+00:00", 1000, 75)
        after = sample("2026-10-31T21:00:00+00:00", 2000, 74)
        for bad in [{}, {"status": "ok", "arquivo_ativo_existe": False}]:
            with self.assertRaises(ValueError):
                compare_snapshots(bad, after)
        with self.assertRaises(ValueError):
            compare_snapshots(before, after, min_seconds=0)

    def test_snapshot_reader_refuses_symlinks(self):
        with TemporaryDirectory() as directory:
            p = Path(directory) / "a.json"
            p.write_text(json.dumps(sample("2026-10-31T19:00:00+00:00", 1000, 75)))
            self.assertEqual(read_snapshot(p)["total_de_arquivos_regulares_bytes"], 1000)
            target = Path(directory) / "alias.json"
            target.symlink_to(p)
            with self.assertRaises(ValueError):
                read_snapshot(target)


if __name__ == "__main__":
    unittest.main()
