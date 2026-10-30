import unittest
from fmn_filters.ip_analytics import aggregate,prefix,INSERT_PAIR
from fmn_filters.enrichment import Enricher
from fmn_filters.parsers import parse_record


class FakeASN:
    def asn(self, addr):
        return type("ASN",(),{"autonomous_system_number":15169,
                              "autonomous_system_organization":"Empresa ASN Exemplo"})()


class FakeCity:
    def city(self, addr):
        return type("City",(),{
            "country":type("Country",(),{"iso_code":"US"})(),
            "location":type("Location",(),{"latitude":37.4,"longitude":-122.0})()
        })()


def sample():
    return {"type":"FLOW","first":"2026-10-29T19:04:57.000",
            "last":"2026-10-29T19:04:57.000",
            "src4_addr":"8.8.8.8","dst4_addr":"1.1.1.1",
            "src_net":"8.8.8.0","src_mask":24,
            "dst_net":"1.1.1.0","dst_mask":24,
            "proto":6,"dst_port":443,"src_as":28209,"dst_as":0,
            "input_snmp":86,"output_snmp":16,"direction":0,
            "in_packets":2048,"in_bytes":143360,"sampled":1}


class IPAnalyticsTests(unittest.TestCase):
    def test_huawei_input_output_ifindex(self):
        event=parse_record(sample(),assume_utc=True)
        self.assertEqual((event.input_if,event.output_if),(86,16))

    def test_prefix_comes_from_exporter_mask(self):
        self.assertEqual(prefix(sample(),"src","8.8.8.8"),"8.8.8.0/24")
        self.assertEqual(prefix({"src_mask":0},"src","8.8.8.8"),"")
        self.assertEqual(prefix({"src_net":"10.0.0.0","src_mask":24},
                                "src","8.8.8.8"),"")

    def test_sample_expansion_and_grouping(self):
        e=Enricher(asn_reader=FakeASN(),city_reader=FakeCity())
        rows,count=aggregate([sample(),sample()],"huawei",e)
        self.assertEqual(count,2)
        self.assertEqual(len(rows),1)
        r=rows[0]
        self.assertEqual((r[2],r[3]),("8.8.8.8","1.1.1.1"))
        self.assertEqual(r[6:9],(86,16,0))
        self.assertEqual(r[9],"8.8.8.0/24")
        self.assertEqual(r[11],28209)
        self.assertEqual(r[13],"") # ASN diferente da fonte nao ganha nome falso.
        self.assertEqual(r[-3:],(4096,286720,2))
        self.assertEqual(len(r),24)
        self.assertEqual(INSERT_PAIR.count("%s"),24)

    def test_geo_only_when_asn_matches(self):
        e=Enricher(asn_reader=FakeASN(),city_reader=FakeCity())
        flow=sample()
        flow["src_as"]=15169
        rows,count=aggregate([flow],"huawei",e)
        self.assertEqual(rows[0][13],"Empresa ASN Exemplo")
        self.assertEqual(rows[0][15],"US")
        self.assertEqual(rows[0][17],37.4)

    def test_unknown_ips_are_not_invented(self):
        row=sample()
        del row["dst4_addr"]
        rows,count=aggregate([row],"huawei",Enricher())
        self.assertEqual((rows,count),([],0))

    def test_esp_protocol_huawei(self):
        row=sample()
        row["proto"]=50
        self.assertEqual(parse_record(row,assume_utc=True).protocol,"esp")


if __name__=="__main__":
    unittest.main()
