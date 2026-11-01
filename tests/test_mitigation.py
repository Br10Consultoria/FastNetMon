"""Mitigacao por blackhole: configuracao, travas de seguranca, ciclo completo com BGP falso e comandos do GoBGP."""
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import unittest

from fmn_filters import mitigation as mt
from fmn_filters.bidir_config import build_scopes, validate_config

ROOT = Path(__file__).resolve().parent.parent
BIDIR = validate_config(json.loads((ROOT / "rules/bidir.example.json").read_text()))
PROFILE = json.loads((ROOT / "rules/cgnat-profiles.a10.json").read_text())
SCOPES = build_scopes(BIDIR, PROFILE)
DB_ENABLED = os.environ.get("ORBYMON_TEST_DB") == "1" and os.environ.get("ORBYMON_DB_USER")


class FakeBGP:
    def __init__(self):
        self.rib, self.calls = set(), []

    def announce(self, prefix, test=False):
        self.calls.append(("add", prefix, test))
        self.rib.add(prefix)

    def withdraw(self, prefix):
        self.calls.append(("del", prefix))
        self.rib.discard(prefix)

    def announced(self):
        return set(self.rib)

    def session(self):
        return "10.0.0.1 262687 Establ"


class ConfigTests(unittest.TestCase):
    def test_defaults_and_validation(self):
        c = mt.validate({})
        self.assertEqual((c["mode"], c["bgp"]["enabled"], c["trigger"]["scopes"]), ("simulate", False, ["dedicated"]))
        for bad in ({"mode": "x"}, {"bgp": {"next_hop": "100::1"}}, {"bgp": {"communities": ["666"]}},
                    {"trigger": {"scopes": ["cgnat_pool"]}}, {"max_active": 0}, {"nada": 1},
                    {"bgp": {"api": "0.0.0.0"}}, {"bgp": {"communities": ["262687:666"]}}):
            with self.assertRaises((mt.MitigationError, ValueError), msg=bad):
                mt.validate(bad)

    def test_eligibility(self):
        c = mt.validate({"protected": ["187.87.201.50/32"]})
        self.assertEqual(mt.eligible("187.87.201.40", c, BIDIR, SCOPES), (True, "dedicated"))
        for ip, why in (("8.8.8.8", "fora"), ("100.64.70.12", "privada"), ("45.238.170.70", "pool"),
                        ("187.87.201.50", "protegido"), ("187.87.201.193", "infra")):
            ok, msg = mt.eligible(ip, c, BIDIR, SCOPES)
            self.assertFalse(ok, ip)
            self.assertIn(why, msg.lower().replace("infraestrutura", "infra"), ip)
        self.assertTrue(mt.eligible("45.238.170.70", mt.validate({"allow_cgnat_pool": True}), BIDIR, SCOPES)[0])
        self.assertEqual(mt.prefix_of("2804:4fa8::10"), "2804:4fa8::10/128")

    def test_gobgp_commands(self):
        calls = []
        g = mt.GoBGP(mt.validate({"bgp": {"enabled": True, "communities": ["65535:666", "262687:0:666"]}}),
                     run=lambda args: calls.append(args) or '{"187.87.201.40/32": []}')
        g.announce("187.87.201.40/32")
        g.announce("2804:4fa8::10/128", test=True)
        g.withdraw("187.87.201.40/32")
        self.assertEqual(calls[0], ["global", "rib", "add", "-a", "ipv4", "187.87.201.40/32", "nexthop", "192.0.2.1",
                                    "community", "65535:666,65535:65281", "large-community", "262687:0:666",
                                    "origin", "igp"])
        self.assertIn("100::1", calls[1])
        self.assertTrue(calls[1][calls[1].index("community") + 1].endswith("65535:65282"))   # teste: NO_ADVERTISE
        self.assertEqual(calls[2], ["global", "rib", "del", "-a", "ipv4", "187.87.201.40/32"])
        self.assertEqual(g.announced(), {"187.87.201.40/32"})

    def test_message(self):
        text = mt.message([("proposto", "187.87.201.40", "IN UDP · 2000 Mbps"), ("retirado", "1.2.3.4/32", "")],
                          "https://painel:8443")
        self.assertIn("aprove no painel", text)
        self.assertIn("https://painel:8443/mitigacao", text)


@unittest.skipUnless(DB_ENABLED, "defina ORBYMON_TEST_DB=1 e ORBYMON_DB_*")
class LifecycleTests(unittest.TestCase):
    def setUp(self):
        from fmn_filters.mysql_sink import connection_from_env
        self.db = connection_from_env()
        c = self.db.cursor()
        c.execute("DELETE FROM orby_mitigations")
        c.execute("DELETE FROM orby_attack_events WHERE rule_name LIKE 'teste mit%%'")
        self.db.commit()
        self.now = datetime(2026, 11, 1, 15, 0)

    def tearDown(self):
        c = self.db.cursor()
        c.execute("DELETE FROM orby_mitigations")
        c.execute("DELETE FROM orby_attack_events WHERE rule_name LIKE 'teste mit%%'")
        self.db.commit()
        self.db.close()

    def attack(self, ip, when, mbps=2000, sev="critical", eid=None):
        self.db.cursor().execute(
            "INSERT INTO orby_attack_events (event_id,event_time,rule_name,severity,detection,direction,scope,local_ip,"
            "pps,mbps,details) VALUES (%s,%s,'teste mit UDP',%s,'flow','in','dedicated',%s,%s,%s,'{}')",
            (eid or "%s-%s" % (ip, when.isoformat()), when, sev, ip, mbps * 100, mbps))
        self.db.commit()

    def rows(self):
        c = self.db.cursor()
        c.execute("SELECT ip,status,origin FROM orby_mitigations ORDER BY id")
        return c.fetchall()

    def test_simulate_manual_auto(self):
        sim = mt.validate({})
        self.attack("187.87.201.40", self.now - timedelta(minutes=1))
        self.attack("187.87.201.41", self.now - timedelta(minutes=1), mbps=10)            # abaixo do gatilho
        self.attack("45.238.170.70", self.now - timedelta(minutes=1))                    # pool: nunca
        self.attack("187.87.201.42", self.now - timedelta(minutes=1), sev="high")         # severidade baixa
        bgp = FakeBGP()
        ev = mt.run(self.db, sim, BIDIR, SCOPES, bgp, now=self.now, log=lambda *a: None)
        self.assertEqual(ev, [("simulado", "187.87.201.40", "teste mit UDP · 2000 Mbps / 200000 pps")])
        self.assertEqual(self.rows(), (("187.87.201.40", "simulated", "auto"),))
        self.assertEqual(bgp.calls, [])                                                 # BGP desligado: nada
        mt.run(self.db, sim, BIDIR, SCOPES, bgp, now=self.now + timedelta(minutes=1))
        self.assertEqual(len(self.rows()), 1)                                           # nao duplica
        mt.run(self.db, sim, BIDIR, SCOPES, bgp, now=self.now + timedelta(minutes=40))
        self.assertEqual(self.rows()[0][1], "ended")
        # manual: propoe, operador aprova, anuncia; ataque continua e segura; depois retira
        man = mt.validate({"mode": "manual", "bgp": {"enabled": True}})
        self.attack("187.87.201.40", self.now + timedelta(minutes=50))
        t = self.now + timedelta(minutes=51)
        self.assertEqual(mt.run(self.db, man, BIDIR, SCOPES, bgp, now=t)[0][0], "proposto")
        c = self.db.cursor()
        c.execute("UPDATE orby_mitigations SET status='approved' WHERE status='proposed'")
        self.db.commit()
        self.assertEqual(mt.run(self.db, man, BIDIR, SCOPES, bgp, now=t)[0][:2], ("anunciado", "187.87.201.40"))
        self.assertEqual(bgp.rib, {"187.87.201.40/32"})
        self.attack("187.87.201.40", t + timedelta(minutes=29))                         # ainda atacando
        mt.run(self.db, man, BIDIR, SCOPES, bgp, now=t + timedelta(minutes=31))
        self.assertEqual(bgp.rib, {"187.87.201.40/32"})                                 # nao retira com ataque
        ev = mt.run(self.db, man, BIDIR, SCOPES, bgp, now=t + timedelta(minutes=45))
        self.assertEqual(ev, [("retirado", "187.87.201.40", "")])
        self.assertEqual(bgp.rib, set())
        # reconciliacao: anuncio orfao sai; ativo sumido volta
        bgp.rib.add("187.87.201.99/32")
        mt.run(self.db, man, BIDIR, SCOPES, bgp, now=t + timedelta(minutes=46))
        self.assertNotIn("187.87.201.99/32", bgp.rib)
        # auto com limite de 1 simultaneo
        auto = mt.validate({"mode": "auto", "bgp": {"enabled": True}, "max_active": 1})
        t2 = t + timedelta(hours=2)
        self.attack("187.87.201.43", t2)
        self.attack("187.87.201.44", t2)
        kinds = sorted(k for k, _, _ in mt.run(self.db, auto, BIDIR, SCOPES, bgp, now=t2 + timedelta(minutes=1)))
        self.assertEqual(kinds, ["anunciado", "aprovado", "aprovado", "falhou"])
        self.assertEqual(len(bgp.rib), 1)
        bgp.rib.clear()                                                                 # gobgpd reiniciou
        mt.run(self.db, auto, BIDIR, SCOPES, bgp, now=t2 + timedelta(minutes=2))
        self.assertEqual(len(bgp.rib), 1)                                               # reanunciado
        # modo off retira tudo
        mt.run(self.db, mt.validate({"mode": "off", "bgp": {"enabled": True}}), BIDIR, SCOPES, bgp,
               now=t2 + timedelta(minutes=3))
        self.assertEqual(bgp.rib, set())

    def test_test_announcement_and_expiry_of_proposals(self):
        bgp = FakeBGP()
        c = self.db.cursor()
        c.execute("INSERT INTO orby_mitigations (ip,prefix,status,origin,duration_min,created_at,last_seen_at) VALUES "
                  "('187.87.201.60','187.87.201.60/32','approved','test',5,%s,%s)", (self.now, self.now))
        self.db.commit()
        cfg = mt.validate({"bgp": {"enabled": True}})                                   # simulacao + BGP ligado
        ev = mt.run(self.db, cfg, BIDIR, SCOPES, bgp, now=self.now)
        self.assertEqual(ev, [("anunciado", "187.87.201.60", "teste (no-advertise)")])
        self.assertEqual(bgp.calls[0], ("add", "187.87.201.60/32", True))
        mt.run(self.db, cfg, BIDIR, SCOPES, bgp, now=self.now + timedelta(minutes=6))
        self.assertEqual(bgp.rib, set())
        man = mt.validate({"mode": "manual", "bgp": {"enabled": True}, "approval_timeout_min": 5})
        self.attack("187.87.201.40", self.now)
        mt.run(self.db, man, BIDIR, SCOPES, bgp, now=self.now + timedelta(minutes=1))
        mt.run(self.db, man, BIDIR, SCOPES, bgp, now=self.now + timedelta(minutes=7))
        self.assertIn(("187.87.201.40", "expired", "auto"), self.rows())


if __name__ == "__main__":
    unittest.main()
