import ipaddress
import json
from pathlib import Path
import struct
import tempfile
import unittest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from fmn_filters.a10_tcp_framing import audit

SRC = ipaddress.IPv4Address("10.100.10.10").packed
DST = ipaddress.IPv4Address("192.0.2.5").packed
MESSAGE = (b"<135>1 2026-10-31T12:00:00-03:00 A10 CGNAT - - - "
           b"LSN:PortAllocated:TCP [100.64.64.10 40000 45.238.170.70 40000]")


def packet(seq, data=b"", flags=0x18, link=1):
    tcp = struct.pack("!HHIIHHHH", 44221, 5514, seq, 0, (5 << 12) | flags, 8192, 0, 0) + data
    ip = (b"\x45\x00" + struct.pack("!H", 20 + len(tcp)) + b"\x00\x00\x40\x00"
          + b"\x40\x06\x00\x00" + SRC + DST + tcp)
    if link == 1:
        return b"\xaa" * 12 + b"\x08\x00" + ip
    if link == 276:
        return b"\x08\x00" + b"\x00" * 18 + ip
    raise AssertionError("link unsupported")


def make_pcap(path, frames, link=1, trunc=False):
    out = bytearray(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, link))
    for seq, data, flags in frames:
        wire = packet(seq, data, flags, link)
        inc = len(wire) - (1 if trunc else 0)
        out.extend(struct.pack("<IIII", 0, 0, inc, len(wire)))
        out.extend(wire[:inc])
    path.write_bytes(out)


def frames(payload, start=101):
    half = len(payload) // 2
    return [(100, b"", 0x02), (start, payload[:half], 0x18),
            (start+half, payload[half:], 0x18), (start+len(payload), b"", 0x11)]


class A10TcpFramingTests(unittest.TestCase):
    def run_pcap(self, records, link=1, **kwargs):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "local-capture.pcap"
            make_pcap(p, records, link=link)
            return audit(p, **kwargs)

    def test_unframed_concatenation_is_flagged_and_not_homologated(self):
        out = self.run_pcap(frames(MESSAGE * 3))
        self.assertEqual(out["classificacao_framing_na_amostra"], "concatenacao_sem_delimitador_visivel")
        self.assertEqual(out["contadores"]["fronteiras_coladas_apos_colchete"], 2)
        self.assertTrue(out["captura_tcp_completa_no_intervalo_observado"])
        self.assertFalse(out["correlacao_automatica_permitida"])
        self.assertNotIn("100.64.64.10", json.dumps(out))
        self.assertNotIn("40000", json.dumps(out))

    def test_lf_delimiter(self):
        out = self.run_pcap(frames(MESSAGE + b"\n" + MESSAGE))
        self.assertEqual(out["classificacao_framing_na_amostra"],
                         "delimitacao_lf_ou_nul_compativel_na_amostra")
        self.assertEqual(out["contadores"]["fronteiras_com_lf"], 1)

    def test_length_counting(self):
        framed = str(len(MESSAGE)).encode() + b" " + MESSAGE
        out = self.run_pcap(frames(framed * 2), link=276)
        self.assertEqual(out["classificacao_framing_na_amostra"],
                         "octet_counting_compativel_na_amostra")
        self.assertEqual(out["contadores"]["frames_octet_com_comprimento_coerente"], 2)

    def test_retransmission_and_out_of_order(self):
        p = MESSAGE * 2
        rec = frames(p)
        rec = [rec[0], rec[2], rec[1], rec[1], rec[3]]
        out = self.run_pcap(rec)
        self.assertEqual(out["contadores"]["retransmissoes_ou_duplicacoes"], 1)
        self.assertEqual(out["contadores"].get("lacunas_tcp", 0), 0)
        self.assertTrue(out["captura_tcp_completa_no_intervalo_observado"])

    def test_missing_start_and_end_are_not_complete(self):
        p = MESSAGE * 2
        rec = frames(p)
        out = self.run_pcap([rec[0], rec[2], rec[3]])
        self.assertFalse(out["captura_tcp_completa_no_intervalo_observado"])
        self.assertEqual(out["contadores"]["lacunas_tcp_inicio"], 1)

    def test_snaplen_truncation_not_counted_as_complete(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "capture.pcap"
            make_pcap(path, frames(MESSAGE), trunc=True)
            out = audit(path)
            self.assertGreater(out["contadores"]["pacotes_truncados_snaplen"], 0)
            self.assertFalse(out["captura_tcp_completa_no_intervalo_observado"])

    def test_missing_file_fails_without_exposing_values(self):
        with self.assertRaisesRegex(ValueError, "PCAP"):
            audit(Path("/definitely-not-present/pcap"))


if __name__ == "__main__":
    unittest.main()
