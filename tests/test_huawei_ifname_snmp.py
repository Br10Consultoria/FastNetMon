import pathlib
import unittest
from fmn_filters.interface_names import parse_text,validated

ROOT=pathlib.Path(__file__).resolve().parent.parent

class HuaweiIfnameSNMPTests(unittest.TestCase):
    def test_numeric_snmp_walk_values(self):
        raw='.1.3.6.1.2.1.31.1.1.1.1.86 = STRING: "100GE0/1/48"\n'
        self.assertEqual(parse_text(raw,'snmpwalk'),{86:'100GE0/1/48'})
    def test_reject_no_such_snmp_errors(self):
        for invalid in ('No Such Instance currently exists at this OID',
                        'No Such Object available on this agent at this OID',
                        'End of MIB'):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    validated(86,invalid)
    def test_sync_script_read_only(self):
        s=(ROOT/'scripts/sync-huawei-ifnames-snmp.sh').read_text()
        self.assertIn('snmpwalk -v2c -On',s)
        self.assertIn('defCommunity',s)
        self.assertNotIn('snmpset',s)
        self.assertIn('trap ',s)
        self.assertIn('interface_names',s)
        self.assertIn('--dry-run',s)

if __name__=='__main__':
    unittest.main()
