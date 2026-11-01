"""Mitigacao por blackhole (RTBH): anuncia o IP atacado (/32 ou /128) ao roteador de borda via BGP (GoBGP), com
next-hop de descarte e community de blackhole, e retira quando o ataque termina.

Modos (/etc/orbymon/mitigation.json, editavel no painel):
  off       nada e feito; bloqueios ativos sao retirados
  simulate  decide e registra o que bloquearia, sem anunciar (padrao)
  manual    propoe; um operador aprova no painel; so entao anuncia
  auto      anuncia sozinho (so depois da calibracao e da linha de base estaveis)
Pedidos de teste (origem "test", feitos no painel para validar a sessao BGP) sao anunciados com NO_ADVERTISE
mesmo em simulacao, desde que o BGP esteja configurado.

Travas: so IPs dos blocos do provedor; nunca infraestrutura nem rede privada; IP de pool CGNAT so com
allow_cgnat_pool (derruba todos os assinantes do IP); lista "protected"; limite de bloqueios simultaneos;
reconciliacao com o que esta de fato anunciado (anuncio orfao e retirado).

Uso (timer de 30 s): python -m fmn_filters.mitigation --config /etc/orbymon/bidir.json
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import html
from ipaddress import ip_address, ip_network
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

DEFAULT_PATH = "/etc/orbymon/mitigation.json"
MODES = {"off": "desligada", "simulate": "simulação", "manual": "aprovação manual", "auto": "automática"}
SEVERITY = {"warning": 1, "high": 2, "critical": 3}
NO_EXPORT, NO_ADVERTISE = "65535:65281", "65535:65282"
COMMUNITY_RE = re.compile(r"^\d{1,10}:\d{1,10}(:\d{1,10})?$")      # padrao a:b ou large a:b:c (ASN de 4 bytes)
OPEN = ("proposed", "approved", "active", "withdrawing", "simulated")
DEFAULTS = {
    "mode": "simulate",
    "bgp": {"enabled": False, "gobgp": "/usr/bin/gobgp", "api": "127.0.0.1:50051",
            "next_hop": "192.0.2.1", "next_hop_v6": "100::1", "communities": ["65535:666"], "no_export": True},
    "trigger": {"min_severity": "critical", "min_mbps": 1000.0, "min_pps": 300000.0, "scopes": ["dedicated"],
                "rules": []},
    "duration_min": 30, "release_after_min": 15, "approval_timeout_min": 20, "max_active": 10,
    "allow_cgnat_pool": False, "protected": [], "notify": True,
}


class MitigationError(ValueError):
    pass


# ------------------------------------------------------------------ configuracao
def validate(obj):
    obj = obj or {}
    out = json.loads(json.dumps(DEFAULTS))
    for k, v in obj.items():
        if k not in DEFAULTS:
            raise MitigationError("campo desconhecido: %s" % k)
        out[k] = dict(out[k], **v) if isinstance(out[k], dict) and isinstance(v, dict) else v
    if out["mode"] not in MODES:
        raise MitigationError("modo inválido")
    b = out["bgp"]
    if set(b) - set(DEFAULTS["bgp"]):
        raise MitigationError("campo de bgp desconhecido")
    try:
        if ip_address(b["next_hop"]).version != 4 or ip_address(b["next_hop_v6"]).version != 6:
            raise ValueError
    except ValueError:
        raise MitigationError("next-hop inválido (IPv4 e IPv6 de descarte, ex.: 192.0.2.1 e 100::1)")
    if not isinstance(b["communities"], list) or not 1 <= len(b["communities"]) <= 5 or \
            not all(isinstance(c, str) and COMMUNITY_RE.match(c) for c in b["communities"]):
        raise MitigationError("communities: 1 a 5 no formato a:b (ex.: 65535:666) ou large a:b:c (ex.: 262687:0:666)")
    for c in b["communities"]:
        parts = [int(x) for x in c.split(":")]
        if (len(parts) == 2 and max(parts) > 65535) or max(parts) > 4294967295:
            raise MitigationError("community %s fora da faixa (ASN de 4 bytes: use large community a:b:c)" % c)
    if not re.match(r"^[0-9a-f.:\[\]]+:\d{2,5}$", str(b["api"])) or not str(b["gobgp"]).startswith("/"):
        raise MitigationError("endereço da API do GoBGP ou caminho do gobgp inválidos")
    b["enabled"], b["no_export"] = bool(b["enabled"]), bool(b["no_export"])
    t = out["trigger"]
    if set(t) - set(DEFAULTS["trigger"]):
        raise MitigationError("campo de gatilho desconhecido")
    if t["min_severity"] not in SEVERITY:
        raise MitigationError("severidade mínima inválida")
    for k in ("min_mbps", "min_pps"):
        t[k] = float(t[k])
        if t[k] < 0:
            raise MitigationError("limites não podem ser negativos")
    if not set(t["scopes"]) <= {"dedicated", "cgnat_pool"} or not t["scopes"]:
        raise MitigationError("tipos de IP: dedicated e/ou cgnat_pool")
    if not isinstance(t["rules"], list) or len(t["rules"]) > 50:
        raise MitigationError("regras: lista (vazia = todas)")
    for k, low, high in (("duration_min", 5, 1440), ("release_after_min", 2, 240), ("approval_timeout_min", 2, 240),
                         ("max_active", 1, 200)):
        if type(out[k]) is not int or not low <= out[k] <= high:
            raise MitigationError("%s entre %d e %d" % (k, low, high))
    nets = []
    for c in out["protected"]:
        nets.append(str(ip_network(c, strict=False)))
    out["protected"] = nets
    out["allow_cgnat_pool"], out["notify"] = bool(out["allow_cgnat_pool"]), bool(out["notify"])
    if "cgnat_pool" in t["scopes"] and not out["allow_cgnat_pool"]:
        raise MitigationError("para disparar em IP de pool CGNAT, marque allow_cgnat_pool (derruba todos os assinantes do IP)")
    return out


def load(path=DEFAULT_PATH):
    p = Path(path)
    if not p.exists():
        return validate({})
    return validate(json.loads(p.read_text(encoding="utf-8")))


def eligible(ip, cfg, bidir, scopes):
    """(ok, motivo). So IPs dos blocos do provedor que podem ser descartados com seguranca."""
    try:
        a = ip_address(ip)
    except ValueError:
        return False, "IP inválido"
    scope, pool = scopes.classify(ip)[:2]
    if scope == "external":
        return False, "fora dos blocos do provedor"
    if scope in ("infra", "cgnat_private"):
        return False, "infraestrutura ou rede privada nunca é bloqueada"
    if scope == "cgnat_pool" and not cfg["allow_cgnat_pool"]:
        return False, "IP de pool CGNAT (%s): bloquear derruba todos os assinantes do IP" % pool
    for c in cfg["protected"]:
        n = ip_network(c)
        if n.version == a.version and a in n:
            return False, "IP protegido (%s)" % c
    return True, scope


def prefix_of(ip):
    a = ip_address(ip)
    return "%s/%d" % (a, 32 if a.version == 4 else 128)


# ------------------------------------------------------------------ BGP
class GoBGP:
    """Fala com o gobgpd local pelo CLI (gRPC so em 127.0.0.1)."""

    def __init__(self, cfg, run=None):
        self.b = cfg["bgp"]
        self.run = run or self._run

    def _run(self, args, timeout=15):
        if not os.path.exists(self.b["gobgp"]) and not shutil.which(self.b["gobgp"]):
            raise MitigationError("gobgp não instalado (rode scripts/setup-mitigation.sh)")
        host, port = self.b["api"].rsplit(":", 1)
        out = subprocess.run([self.b["gobgp"], "-u", host.strip("[]"), "-p", port] + args, capture_output=True,
                             text=True, timeout=timeout)
        if out.returncode != 0:
            raise MitigationError((out.stderr or out.stdout).strip()[:250] or "gobgp falhou")
        return out.stdout

    def _family(self, prefix):
        return "ipv6" if ":" in prefix else "ipv4"

    def announce(self, prefix, test=False):
        v6 = ":" in prefix
        std = [c for c in self.b["communities"] if c.count(":") == 1]
        large = [c for c in self.b["communities"] if c.count(":") == 2]
        std += ([NO_EXPORT] if self.b["no_export"] else []) + ([NO_ADVERTISE] if test else [])
        args = ["global", "rib", "add", "-a", self._family(prefix), prefix, "nexthop",
                self.b["next_hop_v6"] if v6 else self.b["next_hop"]]
        if std:
            args += ["community", ",".join(std)]
        if large:
            args += ["large-community", ",".join(large)]
        self.run(args + ["origin", "igp"])

    def withdraw(self, prefix):
        self.run(["global", "rib", "del", "-a", self._family(prefix), prefix])

    def announced(self):
        out = set()
        for fam in ("ipv4", "ipv6"):
            text = self.run(["global", "rib", "-a", fam, "-j"])
            try:
                data = json.loads(text or "{}")
            except ValueError:
                continue
            out |= set(data.keys()) if isinstance(data, dict) else set()
        return out

    def session(self):
        """Texto curto do estado do(s) vizinho(s): 'Establ' quando a sessao esta de pe."""
        lines = [l for l in self.run(["neighbor"]).splitlines()[1:] if l.strip()]
        return "; ".join(" ".join(l.split()) for l in lines)[:300] or "sem vizinho configurado"


# ------------------------------------------------------------------ controlador
def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)


def candidates(cur, cfg, since):
    t = cfg["trigger"]
    cur.execute("SELECT local_ip,rule_name,severity,MAX(mbps),MAX(pps),MAX(event_time) FROM orby_attack_events "
                "WHERE event_time>=%s AND direction='in' GROUP BY local_ip,rule_name,severity", (since,))
    out = {}
    for ip, rule, sev, mbps, pps, last in cur.fetchall():
        if SEVERITY.get(sev, 0) < SEVERITY[t["min_severity"]]:
            continue
        if t["rules"] and rule not in t["rules"]:
            continue
        mbps, pps = float(mbps or 0), float(pps or 0)
        if not (mbps >= t["min_mbps"] or pps >= t["min_pps"]):
            continue
        cur_ = out.get(ip)
        if cur_ is None or mbps > cur_["mbps"]:
            out[ip] = {"ip": ip, "rule": rule, "mbps": mbps, "pps": pps, "last": last}
        else:
            cur_["last"] = max(cur_["last"], last)
    return list(out.values())


def _open(cur, ip):
    cur.execute("SELECT id,status,origin FROM orby_mitigations WHERE ip=%s AND status IN (%s) ORDER BY id DESC LIMIT 1"
                % ("%s", ",".join("'%s'" % s for s in OPEN)), (ip,))
    return cur.fetchone()


def _set_status(cur, name, value, now):
    cur.execute("INSERT INTO orby_mitigation_status (name,value,updated_at) VALUES (%s,%s,%s) ON DUPLICATE KEY "
                "UPDATE value=VALUES(value),updated_at=VALUES(updated_at)", (name, str(value)[:500], now))


def run(db, cfg, bidir, scopes, bgp=None, now=None, log=print):
    """Uma rodada. Devolve [(evento, ip, detalhe)] para avisar."""
    now = now or _now()
    cur = db.cursor()
    events = []
    bgp_on = cfg["bgp"]["enabled"] and bgp is not None
    # 1) novos ataques -> pedidos (ou atualizacao dos abertos)
    if cfg["mode"] != "off":
        for c in candidates(cur, cfg, now - timedelta(minutes=10)):
            row = _open(cur, c["ip"])
            if row:
                cur.execute("UPDATE orby_mitigations SET last_seen_at=GREATEST(COALESCE(last_seen_at,%s),%s),"
                            "peak_mbps=GREATEST(peak_mbps,%s),peak_pps=GREATEST(peak_pps,%s) WHERE id=%s",
                            (c["last"], c["last"], c["mbps"], c["pps"], row[0]))
                continue
            ok, why = eligible(c["ip"], cfg, bidir, scopes)
            if not ok:
                continue
            status = {"simulate": "simulated", "manual": "proposed", "auto": "approved"}[cfg["mode"]]
            cur.execute("INSERT INTO orby_mitigations (ip,prefix,status,origin,rule_name,reason,peak_mbps,peak_pps,"
                        "duration_min,created_at,last_seen_at,expires_at,requested_by) VALUES (%s,%s,%s,'auto',%s,%s,"
                        "%s,%s,%s,%s,%s,%s,'detector')",
                        (c["ip"], prefix_of(c["ip"]), status, c["rule"][:120],
                         "%.0f Mbps / %.0f pps" % (c["mbps"], c["pps"]), c["mbps"], c["pps"], cfg["duration_min"], now,
                         c["last"], now + timedelta(minutes=cfg["duration_min"])))
            events.append({"simulated": "simulado", "proposed": "proposto", "approved": "aprovado"}[status])
            events[-1] = (events[-1], c["ip"], "%s · %.0f Mbps / %.0f pps" % (c["rule"], c["mbps"], c["pps"]))
    # 2) pedidos sem decisao expiram
    cur.execute("UPDATE orby_mitigations SET status='expired',ended_at=%s WHERE status='proposed' AND created_at<%s",
                (now, now - timedelta(minutes=cfg["approval_timeout_min"])))
    # 3) fim: simulados e ativos sem ataque ha release_after e depois do prazo minimo
    release = timedelta(minutes=cfg["release_after_min"])
    cur.execute("SELECT id,ip,prefix,status,origin,last_seen_at,expires_at FROM orby_mitigations "
                "WHERE status IN ('simulated','active')")
    for mid, ip, prefix, status, origin, seen, expires in cur.fetchall():
        quiet = seen is None or now - seen >= release
        if (expires is None or now >= expires) and (quiet or origin == "test") or cfg["mode"] == "off" and origin != "test":
            if status == "simulated":
                cur.execute("UPDATE orby_mitigations SET status='ended',ended_at=%s WHERE id=%s", (now, mid))
            else:
                cur.execute("UPDATE orby_mitigations SET status='withdrawing' WHERE id=%s", (mid,))
    # 4) BGP: retira, anuncia (respeitando o limite) e reconcilia
    if bgp_on:
        cur.execute("SELECT id,ip,prefix FROM orby_mitigations WHERE status='withdrawing'")
        for mid, ip, prefix in cur.fetchall():
            try:
                bgp.withdraw(prefix)
                cur.execute("UPDATE orby_mitigations SET status='ended',ended_at=%s WHERE id=%s", (now, mid))
                events.append(("retirado", ip, ""))
            except Exception as exc:
                cur.execute("UPDATE orby_mitigations SET error=%s WHERE id=%s", (str(exc)[:300], mid))
        cur.execute("SELECT COUNT(*) FROM orby_mitigations WHERE status='active' AND origin<>'test'")
        active = int(cur.fetchone()[0])
        cur.execute("SELECT id,ip,prefix,origin,duration_min FROM orby_mitigations WHERE status='approved' ORDER BY id")
        for mid, ip, prefix, origin, dur in cur.fetchall():
            if origin != "test" and active >= cfg["max_active"]:
                cur.execute("UPDATE orby_mitigations SET status='failed',ended_at=%s,error=%s WHERE id=%s",
                            (now, "limite de %d bloqueios simultâneos" % cfg["max_active"], mid))
                events.append(("falhou", ip, "limite de bloqueios simultâneos"))
                continue
            if origin != "test":
                ok, why = eligible(ip, cfg, bidir, scopes)          # confere de novo na hora de anunciar
                if not ok:
                    cur.execute("UPDATE orby_mitigations SET status='failed',ended_at=%s,error=%s WHERE id=%s",
                                (now, why[:300], mid))
                    events.append(("falhou", ip, why))
                    continue
            try:
                bgp.announce(prefix, test=origin == "test")
                cur.execute("UPDATE orby_mitigations SET status='active',announced_at=%s,error='',"
                            "expires_at=%s WHERE id=%s", (now, now + timedelta(minutes=int(dur)), mid))
                active += origin != "test"
                events.append(("anunciado", ip, "teste (no-advertise)" if origin == "test" else ""))
            except Exception as exc:
                cur.execute("UPDATE orby_mitigations SET status='failed',ended_at=%s,error=%s WHERE id=%s",
                            (now, str(exc)[:300], mid))
                events.append(("falhou", ip, str(exc)[:120]))
        try:
            announced = bgp.announced()
            cur.execute("SELECT prefix FROM orby_mitigations WHERE status='active'")
            wanted = {r[0] for r in cur.fetchall()}
            for orphan in announced - wanted:                  # anunciado sem pedido ativo: retira
                bgp.withdraw(orphan)
                events.append(("retirado", orphan, "anúncio sem pedido ativo"))
            for missing in wanted - announced:                 # ativo mas sumiu (gobgpd reiniciou): reanuncia
                cur.execute("SELECT origin FROM orby_mitigations WHERE prefix=%s AND status='active' LIMIT 1", (missing,))
                bgp.announce(missing, test=(cur.fetchone() or ["auto"])[0] == "test")
            _set_status(cur, "bgp", bgp.session(), now)
            _set_status(cur, "anunciados", len(wanted), now)
        except Exception as exc:
            _set_status(cur, "bgp", "erro: %s" % str(exc)[:200], now)
    else:
        # sem BGP: aprovados nao podem ser anunciados; retiradas viram fim
        cur.execute("UPDATE orby_mitigations SET status='ended',ended_at=%s WHERE status='withdrawing'", (now,))
        cur.execute("UPDATE orby_mitigations SET status='failed',ended_at=%s,error='BGP não configurado' "
                    "WHERE status='approved'", (now,))
        _set_status(cur, "bgp", "desativado (configure e valide a sessão antes de anunciar)", now)
    _set_status(cur, "modo", cfg["mode"], now)
    _set_status(cur, "ultima_execucao", now.isoformat(), now)
    db.commit()
    return events


def message(events, panel_url=""):
    icon = {"simulado": "🧪", "proposto": "🛑", "aprovado": "⛔", "anunciado": "⛔", "retirado": "✅", "falhou": "⚠️"}
    title = {"simulado": "Blackhole simulado (nada anunciado)", "proposto": "Blackhole proposto — aprove no painel",
             "aprovado": "Blackhole automático", "anunciado": "Blackhole anunciado", "retirado": "Blackhole retirado",
             "falhou": "Blackhole não aplicado"}
    lines = []
    for kind, ip, detail in events:
        lines.append("%s <b>%s</b>: <code>%s</code>%s" % (icon.get(kind, "•"), title.get(kind, kind), html.escape(ip),
                                                          (" — " + html.escape(detail)) if detail else ""))
    if any(k == "proposto" for k, _, _ in events) and panel_url:
        lines.append("Aprovar: %s/mitigacao" % html.escape(panel_url.rstrip("/")))
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="OrbyFlow: mitigacao por blackhole (RTBH)")
    ap.add_argument("--config", default="/etc/orbymon/bidir.json")
    ap.add_argument("--mitigation", default=DEFAULT_PATH)
    ap.add_argument("--telegram-env", help="telegram.env para avisar (lido como dados)")
    args = ap.parse_args(argv)
    try:
        from .bidir_config import build_scopes, read_config
        from .mysql_sink import connection_from_env
        bidir = read_config(args.config)
        scopes = build_scopes(bidir)
        cfg = load(args.mitigation)
        bgp = GoBGP(cfg) if cfg["bgp"]["enabled"] else None
        db = connection_from_env()
        try:
            events = run(db, cfg, bidir, scopes, bgp)
        finally:
            db.close()
        for e in events:
            print("%s %s %s" % e)
        if events and cfg["notify"] and args.telegram_env:
            from .admin.config_store import read_env
            from .channels import wrap
            from .notify_telegram import Formatter, Settings, Telegram
            env = read_env(Path(args.telegram_env))
            if env.get("TELEGRAM_BOT_TOKEN") and env.get("TELEGRAM_CHAT_IDS"):
                s = Settings.from_env(env)
                tg = wrap(Telegram(s.token, s.chats), os.environ.get("ORBYMON_NOTIFY_ENV", "/etc/orbymon/notify.env"),
                          s.site)
                head = Formatter(s).header("🛡️", "Mitigação") + "\n"
                try:
                    tg.send(head + message(events, env.get("ORBYMON_ADMIN_URL", "")))
                except Exception as exc:
                    print("aviso falhou: %s" % type(exc).__name__, file=sys.stderr)
        return 0
    except Exception as exc:
        print("FALHA mitigacao: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
