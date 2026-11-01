"""Ciclo completo dos alertas Telegram num MariaDB real (roda com ORBYMON_TEST_DB=1)."""
from datetime import datetime, timedelta, timezone
import hashlib
import os
import unittest

from fmn_filters.notify_telegram import Settings, process

ENABLED = os.environ.get("ORBYMON_TEST_DB") == "1"


class FakeTelegram:
    def __init__(self):
        self.msgs, self.fail = [], False

    def send(self, text):
        if self.fail:
            raise RuntimeError("sem rede")
        self.msgs.append(text)


@unittest.skipUnless(ENABLED, "defina ORBYMON_TEST_DB=1 e ORBYMON_DB_* para testar no MariaDB")
class NotifyLifecycleTests(unittest.TestCase):
    def setUp(self):
        from fmn_filters.mysql_sink import connection_from_env
        self.db = connection_from_env()
        with self.db.cursor() as c:
            c.execute("UPDATE orby_attack_events SET notified_at=UTC_TIMESTAMP() WHERE notified_at IS NULL")
            c.execute("UPDATE orby_notify_incidents SET closed_at=UTC_TIMESTAMP() WHERE closed_at IS NULL")
        self.db.commit()
        self.s = Settings.from_env({"TELEGRAM_BOT_TOKEN": "1:" + "a" * 35, "TELEGRAM_CHAT_IDS": "1"})
        self.t0 = datetime.now(timezone.utc).replace(tzinfo=None, second=0, microsecond=0) - timedelta(hours=3)
        self.tag = hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:6]

    def tearDown(self):
        self.db.close()

    def event(self, minute, sub, sev="high"):
        with self.db.cursor() as c:
            c.execute("""INSERT INTO orby_attack_events (event_id,event_time,rule_name,severity,detection,direction,
scope,pool,local_ip,subscriber_ip,protocol,local_port,remote_port,pps,mbps,remote_ips,syn_ratio,input_if,output_if,details)
VALUES (%s,%s,'IN UDP volumetrico',%s,'flow','in','cgnat_subscriber','P','45.238.170.70',%s,'udp',0,0,1000,10,9,0,0,0,'{}')""",
                      (hashlib.sha256(("%s%s%s%s" % (self.tag, minute, sub, sev)).encode()).hexdigest(),
                       self.t0 + timedelta(minutes=minute), sev, sub))
        self.db.commit()

    def run_at(self, tg, minute):
        return process(self.db, tg, self.s, now=(self.t0 + timedelta(minutes=minute)).replace(tzinfo=timezone.utc))

    def test_open_group_remind_close_reopen(self):
        tg, sub = FakeTelegram(), "100.64.99.%d" % (int(self.tag, 16) % 250)
        self.event(0, sub)
        self.event(0, sub, sev="warning")
        self.assertEqual(self.run_at(tg, 1)["enviadas"], 1)
        self.event(15, sub)
        self.assertEqual(self.run_at(tg, 16)["agrupadas"], 1)
        self.event(31, sub)
        self.assertEqual(self.run_at(tg, 32)["enviadas"], 1)
        self.assertEqual(self.run_at(tg, 60)["encerradas"], 1)
        self.event(70, sub)
        self.assertEqual(self.run_at(tg, 71)["enviadas"], 1)
        self.assertEqual([m.splitlines()[0][:1] for m in tg.msgs], ["🚨", "⏳", "✅", "🚨"])

    def test_network_failure_loses_nothing_and_sends_once(self):
        tg, sub = FakeTelegram(), "100.64.98.%d" % (int(self.tag, 16) % 250)
        self.event(0, sub)
        tg.fail = True
        with self.assertRaises(RuntimeError):
            self.run_at(tg, 1)
        self.db.rollback()
        tg.fail = False
        self.assertEqual(self.run_at(tg, 2)["enviadas"], 1)
        self.assertEqual(self.run_at(tg, 3)["enviadas"], 0)


if __name__ == "__main__":
    unittest.main()
