"""Canais de aviso complementares ao Telegram: e-mail (SMTP) e webhook (JSON generico, Slack, Discord, Teams).

Configuracao em /etc/orbymon/notify.env (editavel no painel, lido como dados, nunca executado):
    SMTP_HOST, SMTP_PORT, SMTP_SECURITY (starttls|ssl|none), SMTP_USER, SMTP_PASSWORD, SMTP_FROM, SMTP_TO (virgula)
    WEBHOOK_URL, WEBHOOK_FORMAT (json|slack|discord|teams)
Todos os avisos que vao ao Telegram (ataques, alarmes por filtro, saude, reputacao) tambem vao para os canais
configurados. O Telegram segue como canal principal: se ele falhar, o aviso e tentado de novo na proxima rodada;
falha de e-mail/webhook so e registrada no log.
"""
from __future__ import annotations

from email.message import EmailMessage
import html
import json
from pathlib import Path
import re
import smtplib
import ssl
import sys
import urllib.request

NOTIFY_KEYS = ("SMTP_HOST", "SMTP_PORT", "SMTP_SECURITY", "SMTP_USER", "SMTP_PASSWORD", "SMTP_FROM", "SMTP_TO",
               "WEBHOOK_URL", "WEBHOOK_FORMAT")
SECRET_KEYS = ("SMTP_PASSWORD", "WEBHOOK_URL")
FORMATS = {"json": "JSON genérico", "slack": "Slack / Mattermost / Rocket.Chat", "discord": "Discord",
           "teams": "Microsoft Teams"}
EMAIL_RE = re.compile(r"^[^@\s,;<>'\"]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


class ChannelError(ValueError):
    pass


def to_text(text_html):
    """HTML simples do Telegram (<b>, <code>, <a>) -> texto puro."""
    t = re.sub(r"<a [^>]*href=\"([^\"]+)\"[^>]*>(.*?)</a>", r"\2 (\1)", text_html or "", flags=re.S)
    t = re.sub(r"<[^>]+>", "", t)
    return html.unescape(t).strip()


def validate(env):
    out = {k: (env.get(k) or "").strip() for k in NOTIFY_KEYS}
    if out["SMTP_HOST"]:
        if not HOST_RE.match(out["SMTP_HOST"]):
            raise ChannelError("servidor SMTP inválido")
        out["SMTP_SECURITY"] = out["SMTP_SECURITY"] or "starttls"
        if out["SMTP_SECURITY"] not in ("starttls", "ssl", "none"):
            raise ChannelError("segurança SMTP: starttls, ssl ou none")
        port = out["SMTP_PORT"] or {"starttls": "587", "ssl": "465", "none": "25"}[out["SMTP_SECURITY"]]
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ChannelError("porta SMTP inválida")
        out["SMTP_PORT"] = port
        to = [x.strip() for x in re.split(r"[,;\s]+", out["SMTP_TO"]) if x.strip()]
        if not to or len(to) > 20 or not all(EMAIL_RE.match(x) for x in to):
            raise ChannelError("destinatários: e-mails separados por vírgula (até 20)")
        out["SMTP_TO"] = ",".join(to)
        out["SMTP_FROM"] = out["SMTP_FROM"] or out["SMTP_USER"]
        if not EMAIL_RE.match(out["SMTP_FROM"]):
            raise ChannelError("remetente inválido")
        if len(out["SMTP_USER"]) > 200:
            raise ChannelError("usuário SMTP longo demais")
    else:
        for k in ("SMTP_PORT", "SMTP_SECURITY", "SMTP_USER", "SMTP_PASSWORD", "SMTP_FROM", "SMTP_TO"):
            out[k] = ""
    if out["WEBHOOK_URL"]:
        if not re.match(r"^https?://[^\s'\\]{3,2000}$", out["WEBHOOK_URL"]):
            raise ChannelError("webhook: URL http(s)://")
        out["WEBHOOK_FORMAT"] = out["WEBHOOK_FORMAT"] or "json"
        if out["WEBHOOK_FORMAT"] not in FORMATS:
            raise ChannelError("formato de webhook inválido")
    else:
        out["WEBHOOK_FORMAT"] = ""
    return out


class Email:
    def __init__(self, env, smtp_factory=None):
        self.env = env
        self.smtp_factory = smtp_factory

    def send(self, text_html):
        plain = to_text(text_html)
        first = plain.splitlines()[0] if plain else "OrbyMon"
        msg = EmailMessage()
        msg["Subject"] = first[:150]
        msg["From"] = self.env["SMTP_FROM"]
        msg["To"] = ", ".join(self.env["SMTP_TO"].split(","))
        msg.set_content(plain + "\n\n-- \nOrbyMon")
        msg.add_alternative("<div style=\"font-family:sans-serif\">%s</div>" %
                            (text_html or "").replace("\n", "<br>\n"), subtype="html")
        host, port, sec = self.env["SMTP_HOST"], int(self.env["SMTP_PORT"]), self.env["SMTP_SECURITY"]
        if self.smtp_factory:
            smtp = self.smtp_factory(host, port, sec)
        elif sec == "ssl":
            smtp = smtplib.SMTP_SSL(host, port, timeout=15, context=ssl.create_default_context())
        else:
            smtp = smtplib.SMTP(host, port, timeout=15)
        try:
            if sec == "starttls":
                smtp.starttls(context=ssl.create_default_context())
            if self.env["SMTP_USER"]:
                smtp.login(self.env["SMTP_USER"], self.env["SMTP_PASSWORD"])
            smtp.send_message(msg)
        finally:
            try:
                smtp.quit()
            except Exception:
                pass

    def __repr__(self):
        return "e-mail"


class Webhook:
    def __init__(self, env, opener=urllib.request.urlopen, site=""):
        self.env, self.opener, self.site = env, opener, site

    def payload(self, text_html):
        plain = to_text(text_html)
        fmt = self.env["WEBHOOK_FORMAT"]
        if fmt == "discord":
            return {"content": plain[:1900]}
        if fmt in ("slack", "teams"):
            return {"text": plain[:3900]}
        return {"origem": "orbymon", "site": self.site, "texto": plain, "html": text_html}

    def send(self, text_html):
        data = json.dumps(self.payload(text_html), ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(self.env["WEBHOOK_URL"], data=data, method="POST",
                                     headers={"Content-Type": "application/json", "User-Agent": "OrbyMon/1.0"})
        with self.opener(req, timeout=10) as resp:
            resp.read(65536)

    def __repr__(self):
        return "webhook"


class Fanout:
    """send(): o principal (Telegram) propaga erro; os complementares so registram falha."""

    def __init__(self, primary, extras, log=None):
        self.primary, self.extras = primary, list(extras)
        self.log = log or (lambda m: print(m, file=sys.stderr))
        self.chats = getattr(primary, "chats", [])

    def send(self, text):
        if self.primary is not None:
            self.primary.send(text)
        for ch in self.extras:
            try:
                ch.send(text)
            except Exception as exc:                  # sem detalhes: a mensagem pode trazer URL com token
                self.log("aviso por %r falhou: %s" % (ch, type(exc).__name__))

    def __getattr__(self, name):                       # call(), etc. do Telegram
        return getattr(self.primary, name)


def extras_from_env(env, site=""):
    env = {k: (env.get(k) or "").strip() for k in NOTIFY_KEYS}
    out = []
    try:
        clean = validate(env)
    except ChannelError as exc:
        print("notify.env ignorado: %s" % exc, file=sys.stderr)
        return out
    clean["SMTP_PASSWORD"], clean["WEBHOOK_URL"] = env["SMTP_PASSWORD"], env["WEBHOOK_URL"]
    if clean["SMTP_HOST"]:
        out.append(Email(clean))
    if clean["WEBHOOK_URL"]:
        out.append(Webhook(clean, site=site))
    return out


def wrap(primary, path="/etc/orbymon/notify.env", site=""):
    """Telegram (ou None) + canais do notify.env. Devolve o proprio Telegram se nao houver canal extra."""
    from .admin.config_store import read_env
    try:
        env = read_env(Path(path)) if path and Path(path).exists() else {}
    except OSError:
        env = {}
    extras = extras_from_env(env, site)
    if not extras:
        return primary
    return Fanout(primary, extras)
