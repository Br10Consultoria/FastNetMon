"""Alertas de ataque no Telegram: inicio, lembrete enquanto continua e encerramento.

Le os eventos gravados pelo detector F4 (orby_attack_events), agrupa em incidentes por
regra + sentido + tipo + IP e envia mensagens. Um evento so e marcado como processado
depois do envio bem-sucedido; falha de rede fica para a proxima execucao.

Configuracao (variaveis de ambiente, ver /etc/orbymon/telegram.env):
  TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_IDS (separados por virgula)
  ORBYMON_NOTIFY_MIN_SEVERITY=high   (warning | high | critical)
  ORBYMON_NOTIFY_REMINDER_MIN=30     ORBYMON_NOTIFY_CLOSE_AFTER_MIN=20
  ORBYMON_GRAFANA_URL=https://187.87.201.198:3000   ORBYMON_TZ=America/Bahia
  ORBYMON_SITE_NAME=                 (prefixo opcional, ex. "POP Salvador")
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import html
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request
from zoneinfo import ZoneInfo

SEVERITY_ORDER = {"warning": 1, "high": 2, "critical": 3}
SEVERITY_PT = {"warning": "aviso", "high": "alta", "critical": "crítica"}
SCOPE_PT = {"dedicated": "IP dedicado", "cgnat_pool": "IP de pool CGNAT", "cgnat_private": "assinante CGNAT",
            "cgnat_subscriber": "assinante CGNAT"}
MAX_MESSAGES_PER_RUN = 15
BACKLOG_HOURS = 6

PENDING_SQL = """SELECT e.event_id,e.event_time,e.rule_name,e.severity,e.detection,e.direction,e.scope,e.pool,
e.local_ip,e.subscriber_ip,e.protocol,e.local_port,e.remote_port,e.pps,e.mbps,e.remote_ips,e.syn_ratio,
e.input_if,e.output_if,e.details,
CASE WHEN e.input_if=0 THEN '' ELSE COALESCE(im.if_name,CONCAT('ifIndex ',e.input_if)) END,
CASE WHEN e.output_if=0 THEN '' ELSE COALESCE(om.if_name,CONCAT('ifIndex ',e.output_if)) END
FROM orby_attack_events AS e
LEFT JOIN orby_interface_names AS im ON im.source='huawei' AND im.if_index=e.input_if
LEFT JOIN orby_interface_names AS om ON om.source='huawei' AND om.if_index=e.output_if
WHERE e.notified_at IS NULL AND e.event_time >= %s ORDER BY e.event_time LIMIT 200"""
EVENT_FIELDS = ("event_id", "event_time", "rule_name", "severity", "detection", "direction", "scope", "pool",
                "local_ip", "subscriber_ip", "protocol", "local_port", "remote_port", "pps", "mbps",
                "remote_ips", "syn_ratio", "input_if", "output_if", "details", "in_name", "out_name")
INCIDENT_FIELDS = ("incident_key", "rule_name", "severity", "direction", "scope", "pool", "local_ip",
                   "subscriber_ip", "protocol", "first_seen", "last_seen", "events", "peak_bps", "peak_pps",
                   "last_sent", "closed_at")


@dataclass
class Settings:
    token: str
    chats: list
    min_severity: str = "high"
    reminder_min: int = 30
    close_after_min: int = 20
    grafana_url: str = ""
    tz: str = "America/Bahia"
    site: str = ""

    @classmethod
    def from_env(cls, env=os.environ):
        token = env.get("TELEGRAM_BOT_TOKEN", "").strip()
        chats = [c.strip() for c in env.get("TELEGRAM_CHAT_IDS", "").split(",") if c.strip()]
        if not token or not chats:
            raise ValueError("defina TELEGRAM_BOT_TOKEN e TELEGRAM_CHAT_IDS em /etc/orbymon/telegram.env")
        s = cls(token, chats, env.get("ORBYMON_NOTIFY_MIN_SEVERITY", "high").strip() or "high",
                int(env.get("ORBYMON_NOTIFY_REMINDER_MIN", "30")), int(env.get("ORBYMON_NOTIFY_CLOSE_AFTER_MIN", "20")),
                env.get("ORBYMON_GRAFANA_URL", "").strip().rstrip("/"), env.get("ORBYMON_TZ", "America/Bahia").strip(),
                env.get("ORBYMON_SITE_NAME", "").strip())
        if s.min_severity not in SEVERITY_ORDER:
            raise ValueError("ORBYMON_NOTIFY_MIN_SEVERITY deve ser warning, high ou critical")
        if not (5 <= s.reminder_min <= 1440 and 5 <= s.close_after_min <= 1440):
            raise ValueError("lembrete e encerramento devem ficar entre 5 e 1440 minutos")
        ZoneInfo(s.tz)
        return s


class Telegram:
    def __init__(self, token, chats, opener=urllib.request.urlopen):
        self.base = "https://api.telegram.org/bot" + token
        self.chats = chats
        self.opener = opener

    def call(self, method, payload=None):
        data = json.dumps(payload or {}).encode()
        req = urllib.request.Request(self.base + "/" + method, data=data,
                                     headers={"Content-Type": "application/json"})
        try:
            with self.opener(req, timeout=15) as resp:
                body = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            try:
                body = json.loads(exc.read().decode())
            except ValueError:
                body = {"ok": False, "description": "HTTP %s" % exc.code}
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RuntimeError("sem acesso a api.telegram.org: %s" % exc) from None
        if not body.get("ok"):
            raise RuntimeError("Telegram recusou: %s" % body.get("description", body))   # nunca imprime o token
        return body.get("result")

    def send(self, text):
        for chat in self.chats:
            self.call("sendMessage", {"chat_id": chat, "text": text, "parse_mode": "HTML",
                                      "disable_web_page_preview": True})


def fmt_rate(bps):
    for limit, unit in ((1e9, "Gb/s"), (1e6, "Mb/s"), (1e3, "kb/s")):
        if bps >= limit:
            return ("%.1f %s" % (bps / limit, unit)).replace(".", ",")
    return "%d b/s" % bps


def fmt_pps(pps):
    if pps >= 1e6:
        return ("%.2f mi pps" % (pps / 1e6)).replace(".", ",")
    if pps >= 1e3:
        return ("%.1f mil pps" % (pps / 1e3)).replace(".", ",")
    return "%d pps" % pps


def fmt_duration(delta):
    minutes = max(1, int(delta.total_seconds() // 60))
    return "%d min" % minutes if minutes < 60 else "%dh%02d" % (minutes // 60, minutes % 60)


def entity_of(ev):
    return ev["subscriber_ip"] or ev["local_ip"]


def incident_key(ev):
    raw = "|".join((ev["rule_name"], ev["direction"], ev["scope"], entity_of(ev)))
    return hashlib.sha256(raw.encode()).hexdigest()


class Formatter:
    def __init__(self, settings: Settings, identify=None):
        self.s = settings
        self.zone = ZoneInfo(settings.tz)
        self.identify = identify          # customers.Identifier: login PPPoE / cliente (opcional)

    def ident(self, ip, when):
        if not self.identify or not ip:
            return ""
        try:
            return self.identify(ip, when) or ""
        except Exception:
            return ""

    def local(self, when):
        return when.replace(tzinfo=timezone.utc).astimezone(self.zone).strftime("%d/%m %H:%M")

    def link(self, ip, when):
        if not self.s.grafana_url:
            return ""
        center = int(when.replace(tzinfo=timezone.utc).timestamp() * 1000)
        query = urllib.parse.urlencode({"var-ip": ip, "from": center - 30 * 60000, "to": center + 30 * 60000})
        return '\n<a href="%s/d/orbymon-f4-ataques?%s">Abrir no painel</a>' % (html.escape(self.s.grafana_url), query)

    def header(self, icon, title):
        site = "[%s] " % html.escape(self.s.site) if self.s.site else ""
        return "%s %s<b>%s</b>" % (icon, site, title)

    def who(self, ev):
        e = html.escape
        lines = []
        if ev["scope"] in ("cgnat_pool", "cgnat_subscriber"):
            lines.append("IP público: <code>%s</code>%s" % (e(ev["local_ip"]), " (%s)" % e(ev["pool"]) if ev["pool"] else ""))
            if ev["subscriber_ip"]:
                lines.append("Assinante: <code>%s</code>" % e(ev["subscriber_ip"]))
            elif ev["scope"] == "cgnat_pool":
                lines.append("Assinante: vários ou não identificado (pool compartilhado)")
        elif ev["scope"] == "cgnat_private":
            lines.append("Assinante: <code>%s</code> (CGNAT, antes do NAT)" % e(ev["local_ip"]))
        else:
            lines.append("IP: <code>%s</code> (%s)" % (e(ev["local_ip"]), SCOPE_PT.get(ev["scope"], ev["scope"])))
        target = ev["local_ip"] if ev["scope"] in ("cgnat_private", "dedicated") else ev["subscriber_ip"]
        who = self.ident(target, ev.get("event_time"))
        if who:
            lines.append("Identificação: %s" % e(who))
        return lines

    def opened(self, ev):
        e = html.escape
        sev = SEVERITY_PT.get(ev["severity"], ev["severity"])
        if ev["detection"] == "nat":
            details = json.loads(ev["details"] or "{}")
            body = [self.header("📤", "Assinante com excesso de conexões (NAT A10)") + " · " + sev,
                    "<b>%s</b>" % e(ev["rule_name"]),
                    "Assinante: <code>%s</code>" % e(ev["subscriber_ip"] or ev["local_ip"]),
                    "Alocações de porta: %s/min · portas ativas: %s" % (details.get("allocs_per_min", "?"),
                                                                       details.get("active_ports", "?")),
                    "Sinal de varredura, flood ou malware no equipamento do cliente."]
        else:
            inbound = ev["direction"] == "in"
            body = [self.header("🚨" if inbound else "📤", "Ataque recebido" if inbound else "Ataque originado")
                    + " · " + sev, "<b>%s</b>" % e(ev["rule_name"])]
            body += self.who(ev)
            proto = (ev["protocol"] or "").upper()
            ports = []
            if ev["remote_port"]:
                ports.append("porta remota %d" % ev["remote_port"])
            if ev["local_port"]:
                ports.append("porta local %d" % ev["local_port"])
            body.append("Protocolo: %s%s" % (proto or "-", (" · " + ", ".join(ports)) if ports else ""))
            extra = []
            if ev["syn_ratio"] and ev["syn_ratio"] >= 0.5:
                extra.append("%d%% SYN" % round(ev["syn_ratio"] * 100))
            body.append("Pico: %s · %s · %d IPs %s%s" % (
                fmt_rate(ev["mbps"] * 1e6), fmt_pps(ev["pps"]), ev["remote_ips"],
                "de origem" if inbound else "de destino", (" · " + ", ".join(extra)) if extra else ""))
            try:
                details = json.loads(ev["details"] or "{}")
            except (TypeError, ValueError):
                details = {}
            lim = details.get("limits") or {}
            why = []
            if details.get("dynamic_limit"):
                why.append("dinâmico da hora")
            if (details.get("limit_multiplier") or 1) != 1:
                why.append("limite próprio ×%g" % details["limit_multiplier"])
            if why and lim:
                body.append("Limite usado: %s (%s)" % (" · ".join(
                    x for x in (fmt_pps(lim["min_pps"]) if "min_pps" in lim else "",
                                fmt_rate(lim["min_mbps"] * 1e6) if "min_mbps" in lim else "") if x),
                    ", ".join(why)))
            iface = ev["in_name"] if inbound else ev["out_name"]
            if iface:
                body.append("%s: %s" % ("Entrou por" if inbound else "Saiu por", e(iface)))
        body.append("Início: %s" % self.local(ev["event_time"]))
        return "\n".join(body) + self.link(entity_of(ev), ev["event_time"])

    def reminder(self, inc, now):
        return "\n".join([
            self.header("⏳", "Ataque ainda em andamento") + " · há " + fmt_duration(now - inc["first_seen"]),
            "<b>%s</b>" % html.escape(inc["rule_name"]),
            "IP: <code>%s</code>%s" % (html.escape(inc["local_ip"]),
                                      " · assinante <code>%s</code>" % html.escape(inc["subscriber_ip"])
                                      if inc["subscriber_ip"] and inc["subscriber_ip"] != inc["local_ip"] else ""),
            "Maior pico: %s · %s · detecções: %d" % (fmt_rate(inc["peak_bps"]), fmt_pps(inc["peak_pps"]), inc["events"]),
        ]) + self.link(inc["subscriber_ip"] or inc["local_ip"], inc["last_seen"])

    def closed(self, inc):
        return "\n".join([
            self.header("✅", "Ataque encerrado"),
            "<b>%s</b>" % html.escape(inc["rule_name"]),
            "IP: <code>%s</code>%s" % (html.escape(inc["local_ip"]),
                                      " · assinante <code>%s</code>" % html.escape(inc["subscriber_ip"])
                                      if inc["subscriber_ip"] and inc["subscriber_ip"] != inc["local_ip"] else ""),
            "Duração: %s (%s a %s)" % (fmt_duration(inc["last_seen"] - inc["first_seen"] + timedelta(minutes=1)),
                                       self.local(inc["first_seen"]), self.local(inc["last_seen"])),
            "Maior pico: %s · %s · detecções: %d" % (fmt_rate(inc["peak_bps"]), fmt_pps(inc["peak_pps"]), inc["events"]),
        ])

    def overflow(self, count):
        return self.header("⚠️", "Muitos ataques simultâneos") + \
            "\n%d detecções novas além das mostradas. Veja o painel F4." % count


def _incident(cur, key):
    cur.execute("SELECT " + ",".join(INCIDENT_FIELDS) + " FROM orby_notify_incidents WHERE incident_key=%s FOR UPDATE",
                (key,))
    row = cur.fetchone()
    return dict(zip(INCIDENT_FIELDS, row)) if row else None


def process(db, telegram, settings, now=None, identify=None):
    """Uma rodada. Retorna contadores. Sempre faz commit do que foi enviado."""
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(tzinfo=None, microsecond=0)
    fmt = Formatter(settings, identify)
    stats = {"enviadas": 0, "ignoradas_severidade": 0, "agrupadas": 0, "encerradas": 0, "excedentes": 0}
    budget = MAX_MESSAGES_PER_RUN
    with db.cursor() as cur:
        cur.execute("UPDATE orby_attack_events SET notified_at=%s WHERE notified_at IS NULL AND event_time < %s",
                    (now, now - timedelta(hours=BACKLOG_HOURS)))
        cur.execute(PENDING_SQL, (now - timedelta(hours=BACKLOG_HOURS),))
        events = [dict(zip(EVENT_FIELDS, r)) for r in cur.fetchall()]
    db.commit()
    overflow = 0
    for ev in events:
        with db.cursor() as cur:
            if SEVERITY_ORDER.get(ev["severity"], 0) < SEVERITY_ORDER[settings.min_severity]:
                stats["ignoradas_severidade"] += 1
                cur.execute("UPDATE orby_attack_events SET notified_at=%s WHERE event_id=%s", (now, ev["event_id"]))
                db.commit()
                continue
            key = incident_key(ev)
            inc = _incident(cur, key)
            bps, pps = float(ev["mbps"]) * 1e6, float(ev["pps"])
            message = None
            if inc is None or inc["closed_at"] is not None:
                if budget > 0:
                    message = fmt.opened(ev)
                else:
                    overflow += 1
                # INSERT ... ON DUPLICATE KEY (e nao REPLACE): o usuario do pipeline nao tem DELETE aqui.
                cur.execute("""INSERT INTO orby_notify_incidents (incident_key,rule_name,severity,direction,scope,
pool,local_ip,subscriber_ip,protocol,first_seen,last_seen,events,peak_bps,peak_pps,last_sent,closed_at)
VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,1,%s,%s,%s,NULL) ON DUPLICATE KEY UPDATE
rule_name=VALUES(rule_name),severity=VALUES(severity),direction=VALUES(direction),scope=VALUES(scope),
pool=VALUES(pool),local_ip=VALUES(local_ip),subscriber_ip=VALUES(subscriber_ip),protocol=VALUES(protocol),
first_seen=VALUES(first_seen),last_seen=VALUES(last_seen),events=1,peak_bps=VALUES(peak_bps),
peak_pps=VALUES(peak_pps),last_sent=VALUES(last_sent),closed_at=NULL""",
                            (key, ev["rule_name"], ev["severity"], ev["direction"], ev["scope"], ev["pool"],
                             ev["local_ip"], ev["subscriber_ip"], ev["protocol"], ev["event_time"], ev["event_time"],
                             bps, pps, now if message else None))   # sem aviso: o lembrete avisa depois
            else:
                inc["events"] += 1
                inc["peak_bps"], inc["peak_pps"] = max(inc["peak_bps"], bps), max(inc["peak_pps"], pps)
                inc["last_seen"] = max(inc["last_seen"], ev["event_time"])
                due = inc["last_sent"] is None or now - inc["last_sent"] >= timedelta(minutes=settings.reminder_min)
                if due and budget > 0:
                    message = fmt.reminder(inc, now)
                else:
                    stats["agrupadas"] += 1
                cur.execute("""UPDATE orby_notify_incidents SET events=%s,peak_bps=%s,peak_pps=%s,last_seen=%s,
last_sent=%s WHERE incident_key=%s""", (inc["events"], inc["peak_bps"], inc["peak_pps"], inc["last_seen"],
                                       now if message else inc["last_sent"], key))
            if message:
                telegram.send(message)          # falha aqui -> rollback, o evento volta na proxima rodada
                budget -= 1
                stats["enviadas"] += 1
            cur.execute("UPDATE orby_attack_events SET notified_at=%s WHERE event_id=%s", (now, ev["event_id"]))
        db.commit()
    if overflow:
        telegram.send(fmt.overflow(overflow))
        stats["enviadas"] += 1
        stats["excedentes"] = overflow
    with db.cursor() as cur:
        cur.execute("SELECT " + ",".join(INCIDENT_FIELDS) + " FROM orby_notify_incidents "
                    "WHERE closed_at IS NULL AND last_seen < %s ORDER BY last_seen LIMIT 50",
                    (now - timedelta(minutes=settings.close_after_min),))
        stale = [dict(zip(INCIDENT_FIELDS, r)) for r in cur.fetchall()]
    for inc in stale:
        with db.cursor() as cur:
            if inc["last_sent"] is not None:           # so encerra no Telegram o que foi avisado
                telegram.send(fmt.closed(inc))
            cur.execute("UPDATE orby_notify_incidents SET closed_at=%s WHERE incident_key=%s",
                        (now, inc["incident_key"]))
        db.commit()
        stats["encerradas"] += 1
    return stats


def main(argv=None):
    ap = argparse.ArgumentParser(description="OrbyFlow: alertas de ataque no Telegram")
    ap.add_argument("--test", action="store_true", help="envia mensagem de teste")
    ap.add_argument("--find-chat", action="store_true",
                    help="lista chats que falaram com o bot (mande uma mensagem ao bot antes)")
    ap.add_argument("--env-file", help="le TELEGRAM_* deste arquivo KEY='valor' (o arquivo nunca e executado)")
    ap.add_argument("--radius-env", default="/etc/orbymon/radius.env",
                    help="RADIUS para mostrar o login PPPoE (lido como dados; ignorado se nao existir)")
    args = ap.parse_args(argv)
    try:
        env = dict(os.environ)
        if args.env_file:
            from .admin.config_store import read_env
            env.update(read_env(Path(args.env_file)))
        if args.find_chat:
            token = env.get("TELEGRAM_BOT_TOKEN", "").strip()
            if not token:
                raise ValueError("defina TELEGRAM_BOT_TOKEN")
            updates = Telegram(token, []).call("getUpdates", {"timeout": 0}) or []
            seen = {}
            for upd in updates:
                msg = upd.get("message") or upd.get("channel_post") or upd.get("my_chat_member") or {}
                chat = msg.get("chat") or {}
                if chat.get("id") is not None:
                    seen[chat["id"]] = chat.get("title") or chat.get("username") or chat.get("first_name") or ""
            if not seen:
                print("Nenhum chat encontrado. Mande uma mensagem ao bot (ou adicione-o ao grupo e escreva algo) "
                      "e rode de novo.")
            for chat_id, name in seen.items():
                print("chat_id=%s  %s" % (chat_id, name))
            return 0
        settings = Settings.from_env(env)
        telegram = Telegram(settings.token, settings.chats)
        if not args.test:
            from .channels import wrap
            telegram = wrap(telegram, os.environ.get("ORBYMON_NOTIFY_ENV", "/etc/orbymon/notify.env"), settings.site)
        if args.test:
            telegram.send(Formatter(settings).header("🛡️", "OrbyFlow conectado ao Telegram") +
                          "\nAlertas de severidade %s ou maior serão enviados aqui."
                          % SEVERITY_PT[settings.min_severity])
            print("mensagem de teste enviada para %d chat(s)" % len(settings.chats))
            return 0
        from .mysql_sink import connection_from_env
        db = connection_from_env()
        from .customers import build_identifier
        identify = build_identifier(db, args.radius_env if os.path.exists(args.radius_env) else None)
        try:
            stats = process(db, telegram, settings, identify=identify)
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
        if any(stats.values()):
            print("Telegram: %s" % stats)
        return 0
    except Exception as exc:
        print("FALHA Telegram: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
