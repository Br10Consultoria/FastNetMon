"""Storage inventory never reads or emits sensitive CGNAT log contents."""
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import time
import unittest

from fmn_filters.a10_storage_inventory import inventory


class A10StorageInventoryTests(unittest.TestCase):
    def test_group_sizes_and_no_payload_leakage(self):
        with TemporaryDirectory() as root:
            base = Path(root)
            active = base / "a10-current.ndjson"
            active.write_text("LSN:PortAllocated:TCP [100.64.64.12 34055 45.238.170.70 34055]")
            (base / "a10-current.ndjson-20261031-16.gz").write_bytes(b"z" * 300)
            (base / "a10-current.ndjson-20261031-17").write_bytes(b"r" * 100)
            (base / "notes.txt").write_bytes(b"other" * 10)
            (base / "symlink").symlink_to(active)
            output = inventory(base, now=active.stat().st_mtime + 60,
                               expected_rotation_mib=128)
            self.assertEqual(output["status"], "ok")
            self.assertEqual(output["grupos"]["arquivo_ativo"]["arquivos"], 1)
            self.assertEqual(output["grupos"]["rotacionados_comprimidos"]["bytes"], 300)
            self.assertEqual(output["grupos"]["rotacionados_nao_comprimidos"]["bytes"], 100)
            self.assertEqual(output["grupos"]["outros_regulares"]["bytes"], 50)
            self.assertEqual(output["grupos"]["links_simbolicos_ignorados"]["arquivos"], 1)
            self.assertEqual(output["arquivo_ativo_sem_modificacao_segundos"], 60.0)
            self.assertFalse(output["retencao_homologada"])
            self.assertFalse(output["timer_e_ultima_rotacao_verificados"])
            for private in ["100.64.64.12", "45.238.170.70", "34055", "LSN:PortAllocated"]:
                self.assertNotIn(private, json.dumps(output))

    def test_no_active_file_is_explicit(self):
        with TemporaryDirectory() as root:
            r = inventory(Path(root))
            self.assertEqual(r["status"], "sem_arquivo_ativo_unico")
            self.assertFalse(r["arquivo_ativo_existe"])
            self.assertIsNone(r["arquivo_ativo_ultima_modificacao_utc"])

    def test_directory_symlink_rejected(self):
        with TemporaryDirectory() as root:
            actual = Path(root) / "logs"
            actual.mkdir()
            alias = Path(root) / "alias"
            alias.symlink_to(actual, target_is_directory=True)
            with self.assertRaises(ValueError):
                inventory(alias)

    def test_entry_limit_fails_closed(self):
        with TemporaryDirectory() as root:
            b = Path(root)
            (b / "x").write_text("x")
            (b / "y").write_text("y")
            with self.assertRaises(ValueError):
                inventory(b, max_entries=1)

    def test_invalid_configuration_rejected(self):
        with TemporaryDirectory() as root:
            with self.assertRaises(ValueError):
                inventory(Path(root), expected_rotation_mib=0)
            with self.assertRaises(ValueError):
                inventory(Path(root), max_entries=0)


if __name__ == "__main__":
    unittest.main()
