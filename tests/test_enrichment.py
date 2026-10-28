import unittest
from fmn_filters.enrichment import Enricher
from fmn_filters.parsers import parse_record
from fmn_filters.engine import Detector, Rule


class FakeASN:
    def __init__(self):
        self.calls = 0
    def asn(self, addr):
        self.calls += 1
        return type('ASN', (), {'autonomous_system_number': 64510, 'autonomous_system_organization': 'Operadora Exemplo'})()


class FakeCity:
    def city(self, addr):
        return type('City', (), {'country': type('Country', (), {'iso_code': 'BR'})(),
                                  'location': type('Location', (), {'latitude': -12.97, 'longitude': -38.51})()})()


class EnrichmentTests(unittest.TestCase):
    def test_asn_country_and_cache(self):
        provider = FakeASN()
        e = Enricher(asn_reader=provider, city_reader=FakeCity())
        source = {'src_ip':'8.8.8.8','dst_ip':'1.1.1.1','src_port':12345,'dst_port':53,'protocol':'udp','timestamp':100}
        enriched = e.enrich(source)
        self.assertEqual(enriched['src_asn'], 64510)
        self.assertEqual(enriched['src_asn_name'], 'Operadora Exemplo')
        self.assertEqual(enriched['src_country'], 'BR')
        self.assertEqual(enriched['src_latitude'], -12.97)
        self.assertEqual(parse_record(enriched).src_asn, 64510)
        e.enrich(source)
        self.assertEqual(provider.calls, 2)

    def test_private_ip_not_looked_up(self):
        provider = FakeASN()
        e = Enricher(asn_reader=provider)
        self.assertEqual(e.lookup('10.0.0.1'), {})
        self.assertEqual(provider.calls, 0)

    def test_grouped_by_src_asn_reports_asn_not_coords(self):
        enriched = {'src_ip': '8.8.8.8','dst_ip':'1.1.1.1','src_port':12345,'dst_port':53,
                    'protocol':'udp','timestamp':100,'src_asn':15169,'src_asn_name':'Example',
                    'src_country':'US','src_latitude':37.4,'src_longitude':-122.1,
                    'packets':5000,'bytes':500000}
        r = Rule.from_dict({'name':'asn','kind':'flow','match':{'src_asns':[15169], 'src_countries':['US']},
            'group_by':['src_asn','dst_ip'],'window_seconds':1,'thresholds':{'min_pps':100}})
        output = Detector([r]).process(parse_record(enriched))
        self.assertEqual(output[0]['context']['src_asn_name'], 'Example')
        self.assertNotIn('src_country', output[0]['context'])
        self.assertNotIn('src_latitude', output[0]['context'])

    def test_source_ip_group_has_geo(self):
        raw = {'src_ip':'8.8.8.8','dst_ip':'1.1.1.1','timestamp':100,'src_port':1,
               'dst_port':53,'protocol':'udp','src_country':'US',
               'src_latitude':37.4,'src_longitude':-122.1,'packets':200,'bytes':1000}
        r = Rule.from_dict({'name':'ip','kind':'flow','match':{},'group_by':['src_ip','dst_ip'],
                            'window_seconds':1,'thresholds':{'min_pps':100}})
        alert=Detector([r]).process(parse_record(raw))[0]
        self.assertEqual(alert['context']['src_country'], 'US')
        self.assertEqual(alert['context']['src_latitude'], 37.4)

if __name__ == '__main__':
    unittest.main()

class UnknownGeoTests(unittest.TestCase):
    def test_unknown_geo_does_not_pass_negation(self):
        from fmn_filters.engine import matches
        from fmn_filters.parsers import parse_record
        event = parse_record({'src_ip':'192.0.2.1','dst_ip':'198.51.100.2','timestamp':100})
        self.assertFalse(matches(event, {'not': {'src_countries': ['BR']}}))

    def test_ranged_metrics_and_not_flags(self):
        from fmn_filters.engine import matches
        from fmn_filters.parsers import parse_record
        event = parse_record({'src_ip':'192.0.2.1','dst_ip':'198.51.100.2','timestamp':100,
                              'packets':200,'bytes':5000,'ttl':64,'protocol':'tcp','tcp_flags':'S'})
        self.assertTrue(matches(event, {'packets_min':100,'bytes_max':6000,'ttl_min':60,
                                        'tcp_flags_all':'S','tcp_flags_none':'A'}))
        self.assertFalse(matches(event, {'tcp_flags_none':'S'}))
