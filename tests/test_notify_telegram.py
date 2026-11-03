from datetime import datetime, timedelta
import io
import json
import unittest
import urllib.error

from fmn_filters.notify_telegram import (Formatter, Settings, Telegram, fmt_duration, fmt_pps, fmt_rate,
                                         incident_key)

ENV = {"TELEGRAM_BOT_TOKEN": "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "TELEGRAM_CHAT_IDS": "-1001, 42",
       "ORBYMON_GRAFANA_URL": "https://187.87.201.198:3000/", "ORBYMON_SITE_NAME": "POP <Teste>"}


def event(**kw):
    ev = dict(event_id="x" * 64, event_time=datetime(2026, 11, 1, 10, 52), rule_name="IN reflexao/amplificacao UDP",
              severity="high", detection="flow", direction="in", scope="cgnat_subscriber", pool="NAT-POOL-08",
              local_ip="45.238.170.70", subscriber_ip="100.64.80.227", protocol="udp", local_port=0, remote_port=53,
              pps=40960.0, mbps=459.2, remote_ips=30, syn_ratio=0.0, input_if=369, output_if=0, details="{}",
              in_name="Vlanif2511", out_name="")
    ev.update(kw)
    return ev


class FormatTests(unittest.TestCase):
    def setUp(self):
        self.fmt = Formatter(Settings.from_env(ENV))

    def test_units_and_duration(self):
        self.assertEqual(fmt_rate(459.2e6), "459,2 Mb/s")
        self.assertEqual(fmt_rate(2.5e9), "2,5 Gb/s")
        self.assertEqual(fmt_pps(40960), "41,0 mil pps")
        self.assertEqual(fmt_pps(1.5e6), "1,50 mi pps")
        self.assertEqual(fmt_duration(timedelta(minutes=75)), "1h15")

    def test_inbound_cgnat_message(self):
        text = self.fmt.opened(event())
        for part in ("🚨", "Ataque recebido", "alta", "<code>45.238.170.70</code> (NAT-POOL-08)",
                     "Assinante: <code>100.64.80.227</code>", "porta remota 53", "459,2 Mb/s", "41,0 mil pps",
                     "30 IPs de origem", "Entrou por: Vlanif2511", "Início: 01/11 07:52",
                     "[POP &lt;Teste&gt;]", "/d/orbyflow-f4-ataques?var-ip=100.64.80.227"):
            self.assertIn(part, text)
        self.assertNotIn("3000//d", text)

    def test_outbound_and_nat_messages(self):
        out = self.fmt.opened(event(direction="out", scope="cgnat_private", local_ip="100.64.80.9",
                                    subscriber_ip="100.64.80.9", syn_ratio=0.95, out_name="Vlanif460",
                                    in_name="", pool=""))
        self.assertIn("Ataque originado", out)
        self.assertIn("Saiu por: Vlanif460", out)
        self.assertIn("95% SYN", out)
        self.assertIn("IPs de destino", out)
        nat = self.fmt.opened(event(detection="nat", rule_name="NAT taxa de alocacao de portas", direction="out",
                                    scope="cgnat_private", details=json.dumps({"allocs_per_min": 9000,
                                                                               "active_ports": 3000})))
        self.assertIn("excesso de conexões", nat)
        self.assertIn("9000/min", nat)

    def test_html_is_escaped(self):
        text = self.fmt.opened(event(rule_name="<b>x</b>"))
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", text)

    def test_incident_key_groups_by_rule_direction_scope_entity(self):
        self.assertEqual(incident_key(event()), incident_key(event(event_time=datetime(2026, 11, 1, 11, 0))))
        self.assertNotEqual(incident_key(event()), incident_key(event(subscriber_ip="100.64.80.1")))


class SettingsAndClientTests(unittest.TestCase):
    def test_requires_token_and_chat(self):
        with self.assertRaises(ValueError):
            Settings.from_env({"TELEGRAM_BOT_TOKEN": "x"})
        with self.assertRaises(ValueError):
            Settings.from_env(dict(ENV, ORBYMON_NOTIFY_MIN_SEVERITY="info"))
        self.assertEqual(Settings.from_env(ENV).chats, ["-1001", "42"])

    def test_sends_to_every_chat_and_never_leaks_token(self):
        sent = []

        class Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def ok(req, timeout):
            sent.append((req.full_url, json.loads(req.data)))
            return Resp(b'{"ok": true, "result": {}}')
        Telegram(ENV["TELEGRAM_BOT_TOKEN"], ["-1001", "42"], opener=ok).send("oi")
        self.assertEqual([p["chat_id"] for _, p in sent], ["-1001", "42"])
        self.assertEqual(sent[0][1]["parse_mode"], "HTML")

        def denied(req, timeout):
            raise urllib.error.HTTPError(req.full_url, 401, "x", {}, io.BytesIO(b'{"ok":false,"description":"Unauthorized"}'))
        with self.assertRaises(RuntimeError) as ctx:
            Telegram(ENV["TELEGRAM_BOT_TOKEN"], ["1"], opener=denied).send("oi")
        self.assertIn("Unauthorized", str(ctx.exception))
        self.assertNotIn("ABCDEFGHIJ", str(ctx.exception))

        def offline(req, timeout):
            raise urllib.error.URLError("no route")
        with self.assertRaises(RuntimeError) as ctx:
            Telegram(ENV["TELEGRAM_BOT_TOKEN"], ["1"], opener=offline).send("oi")
        self.assertNotIn("ABCDEFGHIJ", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
