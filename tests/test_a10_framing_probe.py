import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from fmn_filters.a10_framing_probe import classify_preceding, probe

MESSAGE = ("<135>1 2026-10-30T23:00:00-03:00 CGNAT_ENTER APP - - - "
           "LSN:PortAllocated:TCP [100.64.64.12 34055 45.238.170.70 34055]")

class A10FramingProbeTests(unittest.TestCase):
    def test_classify_delimiters(self):
        for prefix,expected in [
            ("]","colado_apos_fechamento_colchete"),
            ("\n","delimitador_LF_visivel"),
            ("\r","delimitador_CR_visivel"),
            ("\x00","delimitador_NUL_visivel"),
            ("123 ","prefixo_comprimento_candidato"),
            (" ","espaco_antes_cabecalho")
        ]:
            with self.subTest(prefix=repr(prefix)):
                self.assertEqual(classify_preceding(prefix+MESSAGE,len(prefix)),expected)

    def test_large_blocks_and_no_sensitive_output(self):
        with TemporaryDirectory() as d:
            path=Path(d)/"a10.ndjson"
            raw=MESSAGE*600
            path.write_text(json.dumps({"raw":raw,"source_ip":"10.100.10.10"})+"\n")
            out=probe(path)
            self.assertGreater(out["rawmsg_bytes_max"],65536)
            self.assertEqual(out["cabecalhos_rfc5424"],600)
            self.assertEqual(out["fronteiras_internas_analisadas"],599)
            self.assertEqual(out["tipos_de_fronteira"]["colado_apos_fechamento_colchete"],599)
            self.assertFalse(out["limite_correlacao_liberado"])
            self.assertNotIn("100.64.64.12",json.dumps(out))
            self.assertNotIn("45.238.170.70",json.dumps(out))

    def test_missing_and_invalid(self):
        with TemporaryDirectory() as d:
            path=Path(d)/"bad.ndjson"
            path.write_text("not json\n")
            self.assertEqual(probe(path)["linhas_invalidas"],1)
            self.assertEqual(probe(Path(d)/"missing")["status"],"sem_mensagens")

if __name__=="__main__":
    unittest.main()
