"""Ferramentas: validacao de alvo, RDAP, AS, DNS, ping e traceroute (sem rede: respostas simuladas)."""
import io
import json
import unittest
from unittest import mock

from fmn_filters import tools as tl


class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def opener_for(mapping, seen=None):
    def opener(req, timeout):
        if seen is not None:
            seen.append(req.full_url)
        for key, payload in mapping.items():
            if key in req.full_url:
                return Resp(json.dumps(payload).encode())
        raise OSError("sem rede")
    return opener


RDAP = {"name": "EXEMPLO-NET", "handle": "NET-203-0-113-0-1", "country": "US", "startAddress": "203.0.113.0",
        "endAddress": "203.0.113.255", "cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}],
        "entities": [{"handle": "ABUSE1", "roles": ["abuse"],
                      "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Abuse Desk"],
                                               ["email", {}, "text", "abuse@exemplo.net"]]]},
                     {"handle": "ORG1", "roles": ["registrant"],
                      "vcardArray": ["vcard", [["fn", {}, "text", "Exemplo Inc"]]],
                      "entities": [{"handle": "NOC", "roles": ["technical", "abuse"],
                                    "vcardArray": ["vcard", [["email", {}, "text", "noc@exemplo.net"]]]}]}]}


class ToolTests(unittest.TestCase):
    def test_target_validation(self):
        self.assertEqual(tl.target(" 2001:DB8::1 "), "2001:db8::1")
        self.assertEqual(tl.target("Exemplo.com.BR."), "exemplo.com.br")
        for bad in ("-c 9 x", "a;b", "localhost", "exemplo..com", "x" * 300 + ".com", "", "1.2.3"):
            with self.assertRaises(tl.ToolError, msg=bad):
                tl.target(bad)
        with self.assertRaises(tl.ToolError):
            tl.target("exemplo.com", allow_host=False)

    def test_rdap(self):
        seen = []
        out = tl.rdap_ip("203.0.113.9", opener_for({"rdap.org/ip/203.0.113.9": RDAP}, seen))
        self.assertEqual(out["abuse"], ["abuse@exemplo.net", "noc@exemplo.net"])
        self.assertEqual(out["cidrs"], ["203.0.113.0/24"])
        self.assertEqual((out["nome"], out["pais"]), ("EXEMPLO-NET", "US"))
        self.assertEqual(seen, ["https://rdap.org/ip/203.0.113.9"])

    def test_asn(self):
        op = opener_for({"as-overview": {"data": {"holder": "BR10 - Exemplo", "announced": True}},
                         "announced-prefixes": {"data": {"prefixes": [{"prefix": "187.87.201.0/24"},
                                                                       {"prefix": "2804:4fa8::/32"},
                                                                       {"prefix": "45.238.170.0/23"}]}}})
        out = tl.asn_info("AS262687", op)
        self.assertEqual((out["nome"], out["total"], out["v4"], out["v6"]), ("BR10 - Exemplo", 3, 2, 1))
        self.assertEqual(out["prefixos"][-1], "2804:4fa8::/32")
        with self.assertRaises(tl.ToolError):
            tl.asn_info("ASxyz", op)

    def test_asn_search_local_and_ripestat(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "asn.txt")
            raw = "\n".join(["13335 CLOUDFLARENET - Cloudflare, Inc., US", "262687 BR10 TELECOM LTDA, BR",
                             "15169 GOOGLE - Google LLC, US"] + ["%d FILLER, US" % i for i in range(1, 1200)])

            class R(Resp):
                pass
            n = tl.update_asnames(path, lambda req, timeout: R(("# cabecalho\n" + raw).encode()))
            self.assertEqual(n, 1202)
            self.assertIsNone(tl.update_asnames(path, lambda req, timeout: R(b"")))     # recente: nao baixa
            self.assertEqual(tl.asn_search("cloudflare", path), [(13335, "CLOUDFLARENET - Cloudflare, Inc., US")])
            self.assertEqual(tl.asn_search("br10 telecom", path), [(262687, "BR10 TELECOM LTDA, BR")])
            self.assertEqual(len(tl.asn_search("filler", path)), 50)
            with self.assertRaises(tl.ToolError):
                tl.update_asnames(path, lambda req, timeout: R(b"1 x\n"), max_age_h=0)
            self.assertEqual(tl.asn_search("google", path)[0][0], 15169)                 # lista anterior mantida
        op = opener_for({"searchcomplete": {"data": {"categories": [
            {"category": "ASNs", "suggestions": [{"value": "AS13335", "label": "AS13335",
                                                  "description": "CLOUDFLARENET - Cloudflare, Inc."}]},
            {"category": "Prefixes", "suggestions": [{"value": "1.1.1.0/24"}]}]}}})
        self.assertEqual(tl.asn_search("cloudflare", "/nao/existe", op), [(13335, "CLOUDFLARENET - Cloudflare, Inc.")])
        for bad in ("a", "x;rm", "x" * 90):
            with self.assertRaises(tl.ToolError):
                tl.asn_search(bad, "/nao/existe", op)

    def test_commands_use_argument_lists(self):
        calls = []
        run = lambda args, timeout: calls.append((args, timeout)) or "ok"
        tl.ping("203.0.113.9", run)
        tl.traceroute("exemplo.com.br", run, which=lambda n: "/usr/bin/" + n)
        tl.traceroute("203.0.113.9", run, which=lambda n: None)
        tl.dns("exemplo.com.br", "MX", run, which=lambda n: "/usr/bin/dig")
        tl.dns("203.0.113.9", "A", run, which=lambda n: "/usr/bin/dig")          # IP vira PTR
        self.assertEqual(calls[0][0][0], "ping")
        self.assertEqual(calls[0][0][-1], "203.0.113.9")
        self.assertEqual(calls[1][0][0], "traceroute")
        self.assertEqual(calls[2][0][0], "tracepath")
        self.assertEqual(calls[3][0][-2:], ["exemplo.com.br", "MX"])
        self.assertEqual(calls[4][0][-2:], ["-x", "203.0.113.9"])
        with self.assertRaises(tl.ToolError):
            tl.dns("exemplo.com.br", "ANY", run)
        with self.assertRaises(tl.ToolError):
            tl.dns("exemplo.com.br", "PTR", run, which=lambda n: "/usr/bin/dig")
        with self.assertRaises(tl.ToolError):
            tl.dns("exemplo.com.br", "MX", run, which=lambda n: None)          # sem dig


if __name__ == "__main__":
    unittest.main()
