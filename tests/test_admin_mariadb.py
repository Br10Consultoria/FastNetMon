"""Store do painel num MariaDB real com as permissoes minimas do setup-admin.sh.
Roda com ORBYMON_TEST_DB=1 e ORBYMON_ADMIN_DB_USER/ORBYMON_ADMIN_DB_PASSWORD (usuario orbymon_admin)."""
import os
import unittest

from fmn_filters.admin import security

ENABLED = os.environ.get("ORBYMON_TEST_DB") == "1" and os.environ.get("ORBYMON_ADMIN_DB_USER")


@unittest.skipUnless(ENABLED, "defina ORBYMON_TEST_DB=1 e ORBYMON_ADMIN_DB_* para testar no MariaDB")
class AdminStoreTests(unittest.TestCase):
    def setUp(self):
        from fmn_filters.admin.db import Store
        self.s = Store()
        self.name = "t_%s" % os.urandom(3).hex()
        self.s.create_user(self.name, security.hash_password("senha-de-teste-1"))
        self.u = self.s.user(username=self.name)

    def tearDown(self):
        self.s.delete_user(self.u["id"])
        self.s.clear_fails(self.name)

    def test_user_lifecycle_and_totp_replay_is_atomic(self):
        self.assertTrue(self.u["must_change_password"])
        self.s.set_totp(self.u["id"], "JBSWY3DPEHPK3PXP", True)
        self.assertTrue(self.s.use_totp_step(self.u["id"], 100))
        self.assertFalse(self.s.use_totp_step(self.u["id"], 100))      # reuso
        self.assertFalse(self.s.use_totp_step(self.u["id"], 99))
        self.assertTrue(self.s.use_totp_step(self.u["id"], 101))
        self.assertIsNotNone(self.s.user(uid=self.u["id"])["last_login"])
        self.s.set_disabled(self.u["id"], True)
        self.assertTrue(self.s.user(uid=self.u["id"])["disabled"])
        self.s.set_password(self.u["id"], security.hash_password("outra-senha-boa"))
        self.assertFalse(self.s.user(uid=self.u["id"])["must_change_password"])

    def test_filter_rules_crud(self):
        rules = self.s.filter_rules()
        self.assertTrue(any(r["builtin"] for r in rules))
        d = {"logic": "and", "conditions": [{"metric": "mbps", "op": "gt", "value": 5.0}], "consecutive": 2,
             "resolve_after": 3, "report": {"agg": "dstip", "top": 3}, "notify": True, "retention_days": 7}
        rid = self.s.save_filter_rule(0, "teste " + self.name, False, "high", "in", "dst net 10.0.0.0/8", d, self.name)
        try:
            r = self.s.filter_rule(rid)
            self.assertEqual((r["name"], r["enabled"], r["definition"]), ("teste " + self.name, False, d))
            self.s.set_filter_rule_enabled(rid, True)
            self.assertTrue(self.s.filter_rule(rid)["enabled"])
            self.assertEqual(self.s.save_filter_rule(rid, "teste2 " + self.name, False, "critical", "out", "any", d,
                                                     self.name), rid)
            self.assertEqual(self.s.filter_rule(rid)["severity"], "critical")
            self.assertEqual(self.s.filter_rule_samples(rid), [])
            self.assertIsInstance(self.s.filter_incidents(rid), list)
        finally:
            self.s.delete_filter_rule(rid)
        self.assertIsNone(self.s.filter_rule(rid))

    def test_exceptions_crud_and_baseline_read(self):
        from fmn_filters import exceptions as ex
        e = ex.validate("cidr", "198.51.100.%d" % (os.urandom(1)[0]), "local", "out", note="teste " + self.name,
                        days=2)
        eid = self.s.save_exception(e, self.name)
        try:
            self.assertEqual(self.s.save_exception(dict(e, note="renovada"), self.name), eid)
            item = [x for x in self.s.exceptions() if x["id"] == eid][0]
            self.assertEqual((item["note"], item["side"]), ("renovada", "local"))
            self.assertIsNotNone(item["expires_at"])
            self.assertIsInstance(self.s.baseline_table(), dict)
        finally:
            self.assertEqual(self.s.delete_exception(eid), 1)

    def test_customers_crud(self):
        from fmn_filters import customers as cu
        c = cu.validate_customer("teste " + self.name, "X1", "198.51.100.8/30\n2001:db8:5::/48")
        cid = self.s.save_customer(0, c, self.name)
        try:
            got = [x for x in self.s.customers() if x["id"] == cid][0]
            self.assertEqual(got["prefixes"], ["198.51.100.8/30", "2001:db8:5::/48"])
            self.s.save_customer(cid, dict(c, prefixes=["198.51.100.12/30"]), self.name)
            got = [x for x in self.s.customers() if x["id"] == cid][0]
            self.assertEqual(got["prefixes"], ["198.51.100.12/30"])
        finally:
            self.assertEqual(self.s.delete_customer(cid), 1)

    def test_fails_audit_interfaces_health(self):
        for _ in range(3):
            self.s.fail("192.0.2.77", self.name)
        by_ip, by_user = self.s.fails("192.0.2.77", self.name)
        self.assertGreaterEqual(by_ip, 3)
        self.assertEqual(by_user, 3)
        self.s.clear_fails(self.name)
        self.assertEqual(self.s.fails("192.0.2.77", self.name)[1], 0)
        self.s.audit(self.name, "192.0.2.77", "teste", "detalhe")
        self.assertEqual(self.s.audit_list(1)[0][3], "teste")
        self.s.upsert_interface(4000000001, "Teste0/0/1")
        self.s.upsert_interface(4000000001, "Teste0/0/2")
        self.assertIn((4000000001, "Teste0/0/2"), [tuple(r) for r in self.s.interfaces()])
        self.s.delete_interface(4000000001)
        self.s.seen_interfaces()
        self.assertIn("eventos_24h", self.s.health())
        self.s.recent_events()

    def test_cannot_write_pipeline_tables(self):
        import pymysql
        with self.assertRaises(pymysql.err.OperationalError):
            self.s._q("DELETE FROM orby_attack_events WHERE 1=0", fetch=False)
        with self.assertRaises(pymysql.err.OperationalError):
            self.s._q("UPDATE orby_admin_audit SET detail='x' WHERE 1=0", fetch=False)   # auditoria so cresce


if __name__ == "__main__":
    unittest.main()
