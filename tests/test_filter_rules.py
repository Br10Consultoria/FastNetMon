"""Alarmes por filtro: validacao, condicoes e ciclo completo (nfdump real + MariaDB)."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from fmn_filters import filter_rules as fr
from fmn_filters import flow_query as fq

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "nfcapd.20261101120000"
CFG = json.loads((ROOT / "rules" / "bidir.example.json").read_text())
PROFILE = json.loads((ROOT / "rules" / "cgnat-profiles.a10.json").read_text())
DB_ENABLED = os.environ.get("ORBYMON_TEST_DB") == "1" and os.environ.get("ORBYMON_DB_USER") and \
    os.path.exists(fq.NFDUMP)


def d(**kw):
    base = {"conditions": [{"metric": "mbps", "op": "gt", "value": 5}], "consecutive": 2, "resolve_after": 3,
            "report": {"agg": "dstip", "top": 3}}
    base.update(kw)
    return fr.validate("Regra teste", "@dst_rede", base, table=fq.macros(CFG, PROFILE))[2]


class ValidateTests(unittest.TestCase):
    def test_defaults_and_description(self):
        x = d()
        self.assertEqual(x["logic"], "and")
        self.assertEqual(x["retention_days"], 7)
        self.assertEqual(fr.describe(x), "Mbps > 5 · 2 min seguido(s)")
        y = d(conditions=[{"metric": "flows", "op": "above_avg", "value": 300, "window": 30}], logic="or")
        self.assertIn("300% acima da média de 30 min", fr.describe(y))

    def test_rejects(self):
        t = fq.macros(CFG, PROFILE)
        bad = [{"conditions": []}, {"conditions": [{"metric": "x", "op": "gt", "value": 1}]},
               {"conditions": [{"metric": "mbps", "op": "gt", "value": "abc"}]},
               {"conditions": [{"metric": "mbps", "op": "below_avg", "value": 150, "window": 10}]},
               {"conditions": [{"metric": "mbps", "op": "above_avg", "value": 50, "window": 500}]},
               {"conditions": [{"metric": "mbps", "op": "gt", "value": 1}], "consecutive": 99}]
        for b in bad:
            with self.assertRaises(fr.RuleError):
                fr.validate("Regra", "any", b, table=t)
        with self.assertRaises(fq.QueryError):
            fr.validate("Regra", "any; reboot", {"conditions": [{"metric": "mbps", "op": "gt", "value": 1}]}, table=t)
        with self.assertRaises(fr.RuleError):
            fr.validate("x", "any", {"conditions": [{"metric": "mbps", "op": "gt", "value": 1}]})


class CheckTests(unittest.TestCase):
    def s(self, mbps=0, pps=0, flows=0):
        return {"bps": mbps * 1e6, "pps": pps, "flows": flows, "bpp": 0}

    def test_fixed_and_logic(self):
        x = d(conditions=[{"metric": "mbps", "op": "gt", "value": 100}, {"metric": "pps", "op": "ge", "value": 1000}])
        self.assertTrue(fr.check(x, self.s(150, 1000), []))
        self.assertFalse(fr.check(x, self.s(150, 999), []))
        x["logic"] = "or"
        self.assertTrue(fr.check(x, self.s(150, 1), []))

    def test_average(self):
        x = d(conditions=[{"metric": "flows", "op": "above_avg", "value": 200, "window": 10}])
        hist = [self.s(flows=100)] * 10
        self.assertTrue(fr.check(x, self.s(flows=301), hist))       # > 100 x 3
        self.assertFalse(fr.check(x, self.s(flows=299), hist))
        self.assertFalse(fr.check(x, self.s(flows=1000), hist[:3]))  # pouco historico: nao dispara
        self.assertFalse(fr.check(x, self.s(flows=1000), [self.s()] * 10))   # media zero
        down = d(conditions=[{"metric": "mbps", "op": "below_avg", "value": 50, "window": 5}])
        self.assertTrue(fr.check(down, self.s(mbps=40), [self.s(mbps=100)] * 5))
        self.assertFalse(fr.check(down, self.s(mbps=60), [self.s(mbps=100)] * 5))


@unittest.skipUnless(DB_ENABLED, "defina ORBYMON_TEST_DB=1, ORBYMON_DB_* e instale nfdump")
class LifecycleTests(unittest.TestCase):
    """Minutos simulados: copias da fixture com mtime ajustado (2 arquivos de 30 s por minuto)."""

    def setUp(self):
        from fmn_filters.mysql_sink import connection_from_env
        self.db = connection_from_env()
        cur = self.db.cursor()
        for t in ("orby_filter_rule_samples", "orby_filter_rule_state", "orby_filter_incidents"):
            cur.execute("DELETE FROM " + t)
        cur.execute("DELETE FROM orby_filter_rules WHERE builtin=0")
        cur.execute("UPDATE orby_filter_rules SET enabled=0")
        cur.execute("DELETE FROM orby_attack_events WHERE detection='filter'")
        self.db.commit()
        self.tmp = Path(tempfile.mkdtemp())
        self.dir = self.tmp / "huawei"
        self.dir.mkdir()
        self.empty = self.tmp / "empty.nf"
        self.small = self.tmp / "small.nf"
        subprocess.run([fq.NFDUMP, "-r", str(FIXTURE), "-w", str(self.empty), "proto 250"], check=True,
                       capture_output=True)
        subprocess.run([fq.NFDUMP, "-r", str(FIXTURE), "-w", str(self.small), "dst ip 187.87.201.10"], check=True,
                       capture_output=True)
        self.now = datetime.now(timezone.utc).replace(tzinfo=None, second=0, microsecond=0)
        self.sent = []

    def tearDown(self):
        shutil.rmtree(self.tmp)
        self.db.close()

    def minute(self, minute, src):
        for half in (0, 30):
            t = minute.replace(tzinfo=timezone.utc).timestamp() + half + 30
            name = self.dir / ("nfcapd.%s" % datetime.fromtimestamp(t - 30, timezone.utc).strftime("%Y%m%d%H%M%S"))
            shutil.copy(src, name)
            os.utime(name, (t, t))

    def rule(self, name, expr, definition, enabled=1, direction="in"):
        n, e, dd = fr.validate(name, expr, definition, table=fq.macros(CFG, PROFILE))
        cur = self.db.cursor()
        cur.execute("INSERT INTO orby_filter_rules (name,enabled,severity,direction,expr,definition) "
                    "VALUES (%s,%s,'high',%s,%s,%s)", (n, enabled, direction, e, json.dumps(dd)))
        self.db.commit()
        return cur.lastrowid

    def run_at(self, now):
        class T:
            def __init__(s, out):
                s.out = out

            def send(s, text):
                s.out.append(text)
        from fmn_filters.notify_telegram import Formatter, Settings
        settings = Settings.from_env({"TELEGRAM_BOT_TOKEN": "1:" + "a" * 35, "TELEGRAM_CHAT_IDS": "1"})
        return fr.run(self.db, CFG, PROFILE, self.tmp, now=now, telegram=T(self.sent),
                      formatter=Formatter(settings), log=lambda *a: None)

    def incident(self, rid):
        cur = self.db.cursor()
        cur.execute("SELECT status,started_at,resolved_at,matches,top FROM orby_filter_incidents WHERE rule_id=%s",
                    (rid,))
        return cur.fetchall()

    def test_fixed_threshold_open_remind_close(self):
        rid = self.rule("Flood no pool", "@dst_rede", {"conditions": [{"metric": "mbps", "op": "gt", "value": 5}],
                                                      "consecutive": 2, "resolve_after": 3,
                                                      "report": {"agg": "dstip", "top": 3}})
        base = self.now - timedelta(minutes=14)
        for i in range(3):
            self.minute(base + timedelta(minutes=i), self.empty)
        for i in range(3, 7):
            self.minute(base + timedelta(minutes=i), FIXTURE)          # ~7.8 Mbps contra 45.238.170.70
        for i in range(7, 12):
            self.minute(base + timedelta(minutes=i), self.empty)
        actions, sent = self.run_at(self.now)
        kinds = [a[0] for a in actions]
        self.assertEqual(kinds, ["aberto", "encerrado"])
        inc = self.incident(rid)
        self.assertEqual(len(inc), 1)
        status, started, resolved, matches, top = inc[0]
        self.assertEqual(status, "resolved")
        self.assertEqual(started, base + timedelta(minutes=3))
        self.assertEqual(matches, 4)
        top = json.loads(top)
        self.assertEqual(top[0]["key"], "45.238.170.70")
        self.assertEqual(top[0]["pool"], "NAT-POOL-08")
        self.assertEqual(len(self.sent), 2)
        self.assertIn("Alarme: Flood no pool", self.sent[0])
        self.assertIn("45.238.170.70", self.sent[0])
        self.assertIn("NAT-POOL-08", self.sent[0])
        self.assertIn("Alarme encerrado", self.sent[1])
        cur = self.db.cursor()
        cur.execute("SELECT rule_name,local_ip,scope,notified_at IS NOT NULL FROM orby_attack_events "
                    "WHERE detection='filter'")
        self.assertEqual(cur.fetchall(), (("Filtro: Flood no pool", "45.238.170.70", "cgnat_pool", 1),))
        cur.execute("SELECT COUNT(*),SUM(matched) FROM orby_filter_rule_samples WHERE rule_id=%s", (rid,))
        self.assertEqual(cur.fetchone(), (12, 4))
        # nada novo: segunda execucao nao repete avisos nem reprocessa minutos
        actions, sent = self.run_at(self.now)
        self.assertEqual((actions, sent), ([], 0))

    def test_relative_to_average_and_cooling(self):
        rid = self.rule("Pico relativo", "@dst_rede", {
            "conditions": [{"metric": "mbps", "op": "above_avg", "value": 200, "window": 5}],
            "consecutive": 1, "resolve_after": 10, "report": {"agg": "dstport", "top": 2}})
        base = self.now - timedelta(minutes=12)
        for i in range(6):
            self.minute(base + timedelta(minutes=i), self.small)        # linha de base baixa
        self.minute(base + timedelta(minutes=6), FIXTURE)               # pico muito acima da media
        for i in range(7, 10):
            self.minute(base + timedelta(minutes=i), self.small)
        actions, _ = self.run_at(self.now)
        self.assertEqual([a[0] for a in actions], ["aberto"])
        status = self.incident(rid)[0][0]
        self.assertEqual(status, "cooling")                             # ainda dentro do tempo de encerramento
        cur = self.db.cursor()
        cur.execute("SELECT status FROM orby_filter_rule_state WHERE rule_id=%s", (rid,))
        self.assertEqual(cur.fetchone()[0], "cooling")

    def test_disabled_rules_and_bad_filter(self):
        self.rule("Desligada", "@dst_rede", {"conditions": [{"metric": "mbps", "op": "gt", "value": 0}]}, enabled=0)
        bad = self.rule("Filtro ruim", "@dst_rede", {"conditions": [{"metric": "mbps", "op": "gt", "value": 0}]})
        self.db.cursor().execute("UPDATE orby_filter_rules SET expr='dst ip 1.2.3' WHERE id=%s", (bad,))
        self.db.commit()
        self.minute(self.now - timedelta(minutes=3), FIXTURE)
        actions, _ = self.run_at(self.now)
        self.assertEqual(actions, [])
        cur = self.db.cursor()
        cur.execute("SELECT last_error FROM orby_filter_rule_state WHERE rule_id=%s", (bad,))
        self.assertIn("incomplete IP", cur.fetchone()[0])


@unittest.skipUnless(os.path.exists(fq.NFDUMP), "nfdump nao instalado")
class TestAllTests(unittest.TestCase):
    def test_simulates_every_rule_including_disabled_and_reports_errors(self):
        import io, contextlib
        tmp = Path(tempfile.mkdtemp())
        try:
            d_ = tmp / "huawei"
            d_.mkdir()
            now = datetime.now(timezone.utc).replace(tzinfo=None, second=0, microsecond=0)
            for i in range(3, 0, -1):
                m = now - timedelta(minutes=i)
                for half in (0, 30):
                    t = m.replace(tzinfo=timezone.utc).timestamp() + half + 30
                    f = d_ / ("nfcapd.%s" % datetime.fromtimestamp(t - 30, timezone.utc).strftime("%Y%m%d%H%M%S"))
                    shutil.copy(FIXTURE, f)
                    os.utime(f, (t, t))
            rows = [(1, "Tudo", 0, "high", "in", "@dst_rede", json.dumps(d())),
                    (2, "Quebrado", 1, "high", "in", "@inexistente", json.dumps(d()))]

            class Cur:
                def execute(self, sql, params=None):
                    pass

                def fetchall(self):
                    return rows

            class Db:
                def cursor(self):
                    return Cur()
            out = fr.test_all(Db(), CFG, PROFILE, tmp, minutes=5, now=now)
            self.assertGreaterEqual(out[0]["minutos"], 2)          # o minuto mais recente espera fechar
            self.assertFalse(out[0]["ligado"])
            self.assertGreater(out[0]["condicoes"][0]["max"], 0)
            self.assertIn("inexistente", out[1]["erro"])
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                fr.print_test(out, 5)
            self.assertIn("Tudo", buf.getvalue())
            self.assertIn("ERRO", buf.getvalue())
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
