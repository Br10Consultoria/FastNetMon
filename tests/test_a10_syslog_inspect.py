import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from fmn_filters.a10_syslog_inspect import (
    candidate_mapping, classify, inspect, IP
)


class A10SyslogInspectTests(unittest.TestCase):
    def test_vendor_sample_candidate_only(self):
        s="LSN:PortAllocation:TCP [100.64.64.12 12345 45.238.170.70 30001 - -]"
        self.assertEqual(classify(s),"port_allocation")
        mapped=candidate_mapping(s)
        self.assertEqual(mapped["inside_ip"],"100.64.64.12")
        self.assertEqual(mapped["public_ip"],"45.238.170.70")
        self.assertEqual(mapped["status"],"unverified_candidate")
        self.assertEqual(mapped["public_port"],30001)

    def test_no_false_mapping_outside_ranges_or_port_block(self):
        self.assertIsNone(candidate_mapping(
            "LSN:PortAllocation:TCP [100.64.200.12 12345 45.238.170.70 30001 - -]"))
        self.assertIsNone(candidate_mapping(
            "LSN:PortAllocation:TCP [100.64.64.12 12345 187.87.201.198 30001 - -]"))
        self.assertIsNone(candidate_mapping(
            "LSN:PortAllocation:TCP [100.64.64.12 12345 45.238.170.70 30001-30016 - -]"))
        self.assertIsNone(candidate_mapping(
            "LSN:PortAllocation:TCP [100.64.64.12 12345 45.238.170.70 0 - -]"))

    def test_categories_not_identity(self):
        self.assertEqual(classify("SessionCreated:TCP data"),"session_created")
        self.assertEqual(classify("LSN:PortFreed:UDP data"),"port_freed")
        self.assertEqual(classify("other log message"),"unrecognized")

    def test_anonymized_inspection_and_bad_lines(self):
        with TemporaryDirectory() as temp:
            path=Path(temp)/"sample.ndjson"
            good=json.dumps({"source_ip":"10.100.10.10",
                "received_at":"2026-10-30T10:00:00Z",
                "raw":"LSN:PortAllocation:TCP [100.64.64.12 12345 45.238.170.70 30001 - -]"})
            path.write_text(good+"\n"+"not json\n",encoding="utf-8")
            result=inspect(path,last=10)
            self.assertEqual(result["categorias"] if "categorias" in result else result["tipos_identificados"],
                             {"port_allocation":1})
            self.assertEqual(result["linhas_invalidas"],1)
            self.assertEqual(result["candidatos_mapeamento_formato_publicado"],1)
            self.assertNotIn("100.64.64.12",json.dumps(result["exemplos_com_ips_ocultos"]))
            self.assertNotIn("45.238.170.70",json.dumps(result["exemplos_com_ips_ocultos"]))

    def test_missing_file_is_not_misreported_as_empty_database(self):
        with TemporaryDirectory() as d:
            self.assertEqual(inspect(Path(d)/"none.ndjson")["status"],"sem_mensagens")

    def test_large_lines_never_processed(self):
        with TemporaryDirectory() as d:
            f=Path(d)/"oversized.ndjson"
            f.write_text("a"*70000+"\n")
            self.assertEqual(inspect(f)["linhas_invalidas"],1)

    def test_installer_maintains_group_access_for_future_files(self):
        installer = Path(__file__).resolve().parent.parent / "scripts/setup-a10-syslog.sh"
        script = installer.read_text(encoding="utf-8")
        self.assertIn('fileOwner="syslog" fileGroup="orbymon"', script)
        self.assertIn('chown syslog:orbymon /var/log/orbymon/a10/a10-current.ndjson', script)
        self.assertIn('chmod 0640 /var/log/orbymon/a10/a10-current.ndjson', script)
        self.assertIn('if [[ -L /var/log/orbymon/a10/a10-current.ndjson ]]', script)
        self.assertIn('create 0640 syslog orbymon', script)


if __name__ == "__main__":
    unittest.main()
