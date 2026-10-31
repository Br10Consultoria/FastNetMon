import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from fmn_filters.a10_stream_continuity import bridge_status, bridge_detail, probe

def message(kind="Allocated"):
    return ("<135>1 2026-10-30T23:00:00-03:00 A10 CGNAT_ENTER - - - "
            "LSN:Port"+kind+":TCP [100.64.64.12 34055 45.238.170.70 34055]")

class A10StreamContinuityTests(unittest.TestCase):
    def test_reconstruct_split_nat_event(self):
        event=message()
        cut=len(event)-11
        before=message("Freed")+event[:cut]
        after=event[cut:]+message("Freed")
        self.assertEqual(bridge_status(before,after),"candidato_nat_recuperado_na_juncao")

    def test_identifies_damaged_cross_boundary_events(self):
        event=message()
        cut=len(event)-11
        before=message("Freed")+event[:cut]
        after="garbled"+message("Freed")
        self.assertEqual(bridge_status(before,after),"sem_terminador_apos_juncao")

    def test_ambiguous_reason_zero_tcp_udp_markers(self):
        prefix=message("Freed")+message("Allocated").split("LSN:")[0]
        before=prefix+"Other:ICMP [fragment"
        after=" remainder]"+message("Freed")
        self.assertEqual(
            bridge_detail(before,after),
            ("sem_evento_nat_unico","sem_marcador_nat_tcp_udp_nem_LSN"),
        )

    def test_ambiguous_reason_other_lsn_but_no_port_markers(self):
        before=message("Freed")+message("Allocated").split("LSN:")[0]
        before+="LSN:Other:ICMP [fragment"
        after=" remainder]"+message("Freed")
        self.assertEqual(
            bridge_detail(before,after),
            ("sem_evento_nat_unico","sem_marcador_nat_tcp_udp_com_outro_LSN"),
        )

    def test_ambiguous_multiple_nat_markers(self):
        before=message("Freed")+message("Allocated")[:-1]+" LSN:PortFreed:UDP [partial"
        after=" done]"+message("Freed")
        self.assertEqual(
            bridge_detail(before,after),
            ("sem_evento_nat_unico","multiplos_marcadores_nat_tcp_udp"),
        )

    def test_ambiguous_one_nat_and_other_lsn(self):
        before=message("Freed")+message("Allocated")[:-1]+" LSN:Other [partial"
        after=" done]"+message("Freed")
        self.assertEqual(
            bridge_detail(before,after),
            ("sem_evento_nat_unico","marcador_nat_unico_com_outros_LSN"),
        )

    def test_breakdown_matches_total_without_sensitive_values(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"a10.ndjson"
            prefix=message("Freed")+message("Allocated").split("LSN:")[0]
            data=[prefix+"LSN:Other:ICMP [partial"," done]"+message("Freed")]
            p.write_text("".join(
                json.dumps({"source_ip":"10.100.10.10","raw":raw})+"\n" for raw in data
            ))
            result=probe(p)
            breakdown=result["detalhamento_sem_evento_nat_unico"]
            self.assertEqual(sum(breakdown.values()),
                             result["classificacao_das_juncoes"]["sem_evento_nat_unico"])
            self.assertEqual(breakdown["sem_marcador_nat_tcp_udp_com_outro_LSN"],1)
            self.assertFalse(result["correlacao_automatica_permitida"])
            self.assertNotIn("100.64.64.12",json.dumps(result))

    def test_no_false_pair_when_next_starts_full_header(self):
        self.assertEqual(bridge_status(message(),message()),
                         "proximo_bloco_inicia_com_cabecalho")

    def test_probe_safe_output(self):
        with TemporaryDirectory() as d:
            event=message()
            cut=len(event)-11
            p=Path(d)/"a10.ndjson"
            rows=[message("Freed")+event[:cut],event[cut:]+message("Freed")]
            p.write_text("".join(json.dumps({"source_ip":"10.100.10.10","raw":s})+"\n"
                                 for s in rows))
            result=probe(p)
            self.assertEqual(result["pares_adjacentes_analisados"],1)
            self.assertEqual(result["candidatos_nat_recuperados_entre_blocos"],1)
            self.assertFalse(result["correlacao_automatica_permitida"])
            self.assertNotIn("100.64.64.12",json.dumps(result))
            self.assertNotIn("45.238.170.70",json.dumps(result))

    def test_different_senders_cannot_be_joined(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"a10.ndjson"
            p.write_text("".join(json.dumps({"source_ip":source,"raw":message()})+"\n"
                     for source in ("10.100.10.10","10.100.10.11")))
            out=probe(p)
            self.assertEqual(out["pares_com_origem_diferente"]
                             if "pares_com_origem_diferente" in out else
                             out["classificacao_das_juncoes"]["pares_com_origem_diferente"],1)
            self.assertEqual(out["pares_adjacentes_analisados"],0)

if __name__=="__main__":
    unittest.main()
