import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from fmn_filters.a10_syslog_audit import audit


def message(verb="Allocated",t="10",private="100.64.64.12"):
    return ("<135>1 2026-10-30T07:11:"+t+"-03:00 10.100.10.10 CGNAT_ENTER - "
            "LSN:Port"+verb+":TCP ["+private+" 34055 45.238.170.70 34055]")


class AuditTests(unittest.TestCase):
    def write(self,folder,*raw):
        path=Path(folder)/"syslog.ndjson"
        path.write_text("".join(
            json.dumps({"source_ip":"10.100.10.10","raw":s})+"\n"
            for s in raw),encoding="utf-8")
        return path

    def test_two_headers_one_raw_line(self):
        with TemporaryDirectory() as d:
            p=self.write(d,message()+message("Freed","11"))
            out=audit(p)
            self.assertEqual(out["marcadores_nat"],2)
            self.assertEqual(out["cabecalhos_rfc5424"],2)
            self.assertEqual(out["linhas_com_varios_cabecalhos"],1)
            self.assertEqual(out["eventos_com_timestamp_e_mapeamento_candidato"],2)
            self.assertEqual(out["percentual_estrutural_reconhecido"],100.0)
            self.assertEqual(out["candidatos_por_tipo"],{"allocated":1,"freed":1})
            self.assertFalse(out["correlacao_automatica_permitida"])
            self.assertNotIn("100.64.64.12",json.dumps(out))
            self.assertNotIn("45.238.170.70",json.dumps(out))

    def test_fragment_without_header_not_paired_with_next(self):
        with TemporaryDirectory() as d:
            raw=("LSN:PortFreed:TCP [100.64.64.12 34055 45.238.170.70 34055]"
                 +message("Allocated"))
            out=audit(self.write(d,raw))
            self.assertEqual(out["marcadores_nat"],2)
            self.assertEqual(out["fragmentos_antes_do_cabecalho"],1)
            self.assertEqual(out["eventos_com_timestamp_e_mapeamento_candidato"],1)

    def test_outside_pool_never_accepted(self):
        with TemporaryDirectory() as d:
            out=audit(self.write(d,message(private="100.64.200.1")))
            self.assertEqual(out["eventos_sem_mapeamento_completo"],1)
            self.assertEqual(out["eventos_com_timestamp_e_mapeamento_candidato"],0)

    def test_size_distribution_and_timestamp_skew_without_sensitive_output(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"clock.ndjson"
            frame=message("Allocated","10")
            p.write_text(json.dumps({
                "source_ip":"10.100.10.10",
                "received_at":"2026-10-30T09:11:10-03:00",
                "raw":frame
            })+"\\n",encoding="utf-8")
            result=audit(p)
            self.assertEqual(result["amostras_com_horarios_comparaveis"],1)
            self.assertEqual(result["delta_coletor_menos_a10_segundos_p50"],7200)
            self.assertEqual(result["rawmsg_bytes_max"],len(frame.encode()))
            self.assertEqual(result["rawmsg_bytes_p95"],len(frame.encode()))
            self.assertNotIn("100.64.64.12",json.dumps(result))

    def test_invalid_and_absent_file(self):
        with TemporaryDirectory() as d:
            missing=Path(d)/"missing"
            self.assertEqual(audit(missing)["status"],"sem_mensagens")
            p=Path(d)/"bad.ndjson"
            p.write_text("BAD\\n")
            self.assertEqual(audit(p)["linhas_invalidas"],1)

    def test_no_timestamp_not_auto_correlated(self):
        with TemporaryDirectory() as d:
            raw="LSN:PortAllocated:TCP [100.64.64.12 34055 45.238.170.70 34055]"
            out=audit(self.write(d,raw))
            self.assertEqual(out["linhas_sem_cabecalho"],1)
            self.assertEqual(out["eventos_com_timestamp_e_mapeamento_candidato"],0)


if __name__=="__main__":
    unittest.main()
