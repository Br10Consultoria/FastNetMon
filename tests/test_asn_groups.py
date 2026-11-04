import unittest

from fmn_filters import asn_groups as ag


class ParseTests(unittest.TestCase):
    def test_asns_and_blocks(self):
        self.assertEqual(ag.parse_members("AS15169, 36040\n177.10.0.0/22 as36040 2804:1::/32"),
                         ([15169, 36040], ["177.10.0.0/22", "2804:1::/32"]))
        self.assertEqual(ag.parse_members(""), ([], []))

    def test_invalid(self):
        for bad in ("google", "AS0", "64512", "AS4200000001", "10.0.0.0/4", "1.2.3.4; DROP TABLE x"):
            with self.assertRaises(ValueError, msg=bad):
                ag.parse_members(bad)


class BuildTests(unittest.TestCase):
    def test_first_group_wins_and_ipv4_blocks_only(self):
        asns, blocks, notes = ag.build([("Google", "15169 177.10.0.0/24 2804:1::/32"), ("Outro", "15169 32934"),
                                        ("Quebrado", "xyz")])
        self.assertEqual(asns, [(15169, "Google"), (32934, "Outro")])
        self.assertEqual(blocks, [("group", "177.10.0.0/24", "Google", 2970222592, 2970222847)])
        self.assertEqual(len(notes), 2)


class SyncTests(unittest.TestCase):
    def test_sync_rewrites_only_group_prefixes(self):
        log = []

        class Cur:
            def execute(self, sql, params=None):
                log.append(sql)

            def executemany(self, sql, rows):
                log.append((sql, list(rows)))

            def fetchall(self):
                return [("Google", "15169 177.10.0.0/24")]

        class Db:
            def cursor(self):
                return Cur()

            def commit(self):
                log.append("commit")

        self.assertEqual(ag.sync(Db())[:2], (1, 1))
        self.assertIn("DELETE FROM orby_net_prefixes WHERE kind='group'", log)
        self.assertNotIn("DELETE FROM orby_net_prefixes", log)
