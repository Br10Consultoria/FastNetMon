"""Avisos por e-mail e webhook: validacao, formatos, e-mail e semantica do canal principal."""
import json
import os
from pathlib import Path
import tempfile
import unittest

from fmn_filters import channels as ch

MSG = '🚨 <b>Ataque recebido</b> · alta\nIP: <code>45.238.170.10</code> &amp; mais\n<a href="https://g/x">Grafana</a>'


class ValidateTests(unittest.TestCase):
    def test_defaults_and_errors(self):
        v = ch.validate({"SMTP_HOST": "smtp.exemplo.com.br", "SMTP_USER": "noc@exemplo.com.br",
                         "SMTP_TO": "a@exemplo.com.br; b@exemplo.com.br"})
        self.assertEqual((v["SMTP_PORT"], v["SMTP_SECURITY"], v["SMTP_TO"], v["SMTP_FROM"]),
                         ("587", "starttls", "a@exemplo.com.br,b@exemplo.com.br", "noc@exemplo.com.br"))
        self.assertEqual(ch.validate({"WEBHOOK_URL": "https://h/x"})["WEBHOOK_FORMAT"], "json")
        self.assertEqual(ch.validate({})["SMTP_PORT"], "")
        for bad in ({"SMTP_HOST": "smtp x", "SMTP_TO": "a@b.co"}, {"SMTP_HOST": "s", "SMTP_TO": "nao-email"},
                    {"SMTP_HOST": "s", "SMTP_TO": "a@b.co", "SMTP_SECURITY": "tls13"},
                    {"WEBHOOK_URL": "ftp://x"}, {"WEBHOOK_URL": "https://x", "WEBHOOK_FORMAT": "irc"}):
            with self.assertRaises(ch.ChannelError, msg=bad):
                ch.validate(bad)

    def test_to_text(self):
        self.assertEqual(ch.to_text(MSG),
                         "🚨 Ataque recebido · alta\nIP: 45.238.170.10 & mais\nGrafana (https://g/x)")


class Resp:
    def read(self, n=-1):
        return b"ok"

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class SendTests(unittest.TestCase):
    def test_webhook_formats(self):
        seen = []
        for fmt, key in (("json", "texto"), ("slack", "text"), ("teams", "text"), ("discord", "content")):
            env = ch.validate({"WEBHOOK_URL": "https://hooks.exemplo/abc", "WEBHOOK_FORMAT": fmt})
            ch.Webhook(env, lambda req, timeout: seen.append(req) or Resp(), site="POP1").send(MSG)
            body = json.loads(seen[-1].data)
            self.assertIn("45.238.170.10", body[key])
            self.assertNotIn("<b>", body[key])
        self.assertEqual(json.loads(seen[0].data)["site"], "POP1")

    def test_email(self):
        calls = []

        class FakeSMTP:
            def __init__(self, host, port, sec):
                calls.append(("connect", host, port, sec))

            def starttls(self, context=None):
                calls.append(("starttls",))

            def login(self, u, p):
                calls.append(("login", u, p))

            def send_message(self, msg):
                calls.append(("send", msg["Subject"], msg["To"], msg.get_body(("plain",)).get_content()))

            def quit(self):
                pass
        env = ch.validate({"SMTP_HOST": "smtp.exemplo.com.br", "SMTP_USER": "noc@exemplo.com.br",
                           "SMTP_TO": "a@exemplo.com.br,b@exemplo.com.br"})
        env["SMTP_PASSWORD"] = "segredo"
        ch.Email(env, smtp_factory=FakeSMTP).send(MSG)
        self.assertEqual(calls[0], ("connect", "smtp.exemplo.com.br", 587, "starttls"))
        self.assertEqual(calls[1], ("starttls",))
        self.assertEqual(calls[2], ("login", "noc@exemplo.com.br", "segredo"))
        self.assertEqual(calls[3][1:3], ("🚨 Ataque recebido · alta", "a@exemplo.com.br, b@exemplo.com.br"))
        self.assertIn("IP: 45.238.170.10", calls[3][3])

    def test_fanout_primary_raises_extras_do_not(self):
        sent, logs = [], []

        class Ok:
            chats = ["1"]

            def send(self, t):
                sent.append(("tg", t))

        class Boom:
            def send(self, t):
                raise OSError("https://hooks.exemplo/SEGREDO fora do ar")

            def __repr__(self):
                return "webhook"
        f = ch.Fanout(Ok(), [Boom()], log=logs.append)
        f.send("x")
        self.assertEqual(sent, [("tg", "x")])
        self.assertEqual(logs, ["aviso por webhook falhou: OSError"])            # sem a URL secreta
        self.assertEqual(f.chats, ["1"])

        class Down:
            def send(self, t):
                raise OSError("telegram fora")
        with self.assertRaises(OSError):
            ch.Fanout(Down(), [Ok()]).send("y")                                 # principal falha: tenta de novo depois

    def test_wrap(self):
        tg = object()
        self.assertIs(ch.wrap(tg, "/nao/existe"), tg)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "notify.env"
            p.write_text("WEBHOOK_URL='https://hooks.exemplo/abc'\nWEBHOOK_FORMAT='slack'\n")
            w = ch.wrap(tg, str(p), "POP1")
            self.assertIsInstance(w, ch.Fanout)
            self.assertEqual([repr(x) for x in w.extras], ["webhook"])


if __name__ == "__main__":
    unittest.main()
