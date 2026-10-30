import pathlib
import unittest
from fmn_filters.interface_names import parse_text, validated

ROOT=pathlib.Path(__file__).resolve().parent.parent

class InterfaceNameTests(unittest.TestCase):
    def test_snmpwalk_parses_names(self):
        data='IF-MIB::ifName.86 = STRING: "100GE0/1/48"\niso.3.6.1.2.1.31.1.1.1.1.16 = STRING: "Eth-Trunk2"\n'
        self.assertEqual(parse_text(data),{86:'100GE0/1/48',16:'Eth-Trunk2'})
    def test_csv_and_unknown_index(self):
        self.assertEqual(parse_text('ifindex,ifname\n86,100GE0/1/48\n'),{86:'100GE0/1/48'})
        with self.assertRaises(ValueError): validated(0,'GE0/1/1')
    def test_conflict_rejected(self):
        with self.assertRaises(ValueError):
            parse_text('ifindex,ifname\n2,GE0/1/1\n2,GE0/1/2\n')
    def test_no_fake_name_or_router_changes(self):
        d=(ROOT/'sql/interface_names.sql').read_text()
        self.assertIn('CREATE TABLE IF NOT EXISTS orby_interface_names',d)
        sh=(ROOT/'scripts/setup-interface-names.sh').read_text()
        self.assertNotIn('snmpset',sh)
        self.assertNotIn('ssh ',sh)
    def test_unknown_file_rejected(self):
        with self.assertRaises(ValueError):parse_text('no interfaces\n',fmt='snmpwalk')

if __name__=='__main__':
    unittest.main()
