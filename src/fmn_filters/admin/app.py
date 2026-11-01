"""Painel web de administracao do OrbyMon (Flask). Execucao: gunicorn com TLS (ver setup-admin.sh)."""
from __future__ import annotations

import copy
from datetime import timedelta
import functools
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for

from . import security
from .config_store import ConfigStore, Paths, parse_cidrs, parse_ints, parse_ips
from .db import Store

IDLE_SECONDS = 30 * 60
MAX_FAILS_USER, MAX_FAILS_IP = 5, 20
USERNAME = re.compile(r"^[a-z0-9_.-]{3,40}$")
SCOPES = ("dedicated", "cgnat_pool", "cgnat_private", "cgnat_subscriber")
SCOPE_PT = {"dedicated": "IP dedicado", "cgnat_pool": "Pool CGNAT", "cgnat_private": "Assinante (pré-NAT)",
            "cgnat_subscriber": "Assinante (via log A10)"}
METRICS = (("min_pps", "Pacotes/s", float), ("min_mbps", "Mbps", float), ("min_remote_ips", "IPs remotos", int),
           ("min_syn_ratio", "Fração SYN", float), ("min_zero_port_ratio", "Fração porta 0", float))
SERVICES = ("orbymon-nfcapd@huawei.service", "orbymon-a10-nat.service", "orbymon-flow-rollup-huawei.timer",
            "orbymon-bidir-huawei.timer", "orbymon-ip-huawei.timer", "orbymon-telegram.timer",
            "orbymon-retention.timer", "orbymon-calibrate.timer", "grafana-server.service", "mariadb.service")


def _secret_key(env):
    path = env.get("ORBYMON_ADMIN_SECRET_FILE")
    if path and Path(path).exists():
        return Path(path).read_bytes()
    if env.get("ORBYMON_ADMIN_TESTING") == "1":
        return b"test-secret-key-only-for-tests-0123456789"
    raise RuntimeError("defina ORBYMON_ADMIN_SECRET_FILE (gerado pelo setup-admin.sh)")


def create_app(store: Store | None = None, config: ConfigStore | None = None, env=os.environ, telegram_factory=None):
    app = Flask(__name__)
    testing = env.get("ORBYMON_ADMIN_TESTING") == "1"
    app.config.update(SECRET_KEY=_secret_key(env), SESSION_COOKIE_SECURE=not testing, SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE="Strict", SESSION_COOKIE_NAME="orbymon_admin",
                      PERMANENT_SESSION_LIFETIME=timedelta(hours=8), MAX_CONTENT_LENGTH=256 * 1024)
    store = store or Store()
    config = config or ConfigStore(Paths(env))
    app.jinja_env.globals.update(SCOPE_PT=SCOPE_PT, METRICS=METRICS, SCOPES=SCOPES)

    def client_ip():
        return request.remote_addr or "?"

    def audit(action, detail=""):
        store.audit(g.user["username"] if g.get("user") else "-", client_ip(), action, detail)

    # ---------------------------------------------------------------- protecoes globais
    @app.before_request
    def guard():
        session.permanent = True
        if "csrf" not in session:
            session["csrf"] = security.new_csrf_token()
        if request.method == "POST" and not security.same_token(request.form.get("csrf"), session.get("csrf")):
            abort(400, "token CSRF invalido: recarregue a pagina")
        g.user = None
        uid = session.get("uid")
        if uid:
            if time.time() - session.get("seen", 0) > IDLE_SECONDS:
                session.clear()
                flash("Sessão expirada por inatividade.")
                return redirect(url_for("login"))
            user = store.user(uid=uid)
            if not user or user["disabled"]:
                session.clear()
                return redirect(url_for("login"))
            session["seen"] = time.time()
            g.user = user
        public = request.endpoint in ("login", "login_2fa", "enroll", "static", "logout")
        if g.user is None and not public:
            return redirect(url_for("login"))
        if g.user is not None and g.user["must_change_password"] and request.endpoint not in ("password", "logout", "static"):
            return redirect(url_for("password"))

    @app.after_request
    def headers(resp):
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data:; style-src 'self'; "
                                                   "script-src 'none'; frame-ancestors 'none'; form-action 'self'")
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        if not testing:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        return resp

    @app.errorhandler(400)
    def bad_request(err):
        return render_template("message.html", title="Requisição recusada", text=str(err.description)), 400

    # ---------------------------------------------------------------- login
    def locked(username):
        by_ip, by_user = store.fails(client_ip(), username)
        return by_ip >= MAX_FAILS_IP or by_user >= MAX_FAILS_USER

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip().lower()[:40]
            password = request.form.get("password", "")
            if locked(username):
                flash("Muitas tentativas. Aguarde 15 minutos.")
                return render_template("login.html"), 429
            user = store.user(username=username) if USERNAME.match(username) else None
            ok = security.verify_password(password, user["pw_hash"] if user else security.DUMMY_HASH)
            if not user or not ok or user["disabled"]:
                store.fail(client_ip(), username)
                store.audit(username or "-", client_ip(), "login_falhou")
                flash("Usuário ou senha incorretos.")
                return render_template("login.html"), 401
            session.clear()                       # nova sessao: impede fixacao
            session.update(pre_uid=user["id"], pre_at=time.time(), csrf=security.new_csrf_token())
            return redirect(url_for("login_2fa" if user["totp_enabled"] else "enroll"))
        return render_template("login.html")

    def pending_user():
        uid = session.get("pre_uid")
        if not uid or time.time() - session.get("pre_at", 0) > 300:
            return None
        return store.user(uid=uid)

    def finish_login(user, step):
        if not store.use_totp_step(user["id"], step):
            return False
        store.clear_fails(user["username"])
        session.clear()
        session.update(uid=user["id"], seen=time.time(), csrf=security.new_csrf_token())
        store.audit(user["username"], client_ip(), "login")
        return True

    @app.route("/login/2fa", methods=["GET", "POST"])
    def login_2fa():
        user = pending_user()
        if not user or not user["totp_enabled"]:
            return redirect(url_for("login"))
        if request.method == "POST":
            if locked(user["username"]):
                flash("Muitas tentativas. Aguarde 15 minutos.")
                return render_template("login_2fa.html"), 429
            step = security.verify_totp(user["totp_secret"], request.form.get("code", ""), user["totp_last_step"])
            if step is not None and finish_login(user, step):
                return redirect(url_for("index"))
            store.fail(client_ip(), user["username"])
            store.audit(user["username"], client_ip(), "2fa_falhou")
            flash("Código inválido.")
            return render_template("login_2fa.html"), 401
        return render_template("login_2fa.html")

    @app.route("/login/enroll", methods=["GET", "POST"])
    def enroll():
        user = pending_user()
        if not user or user["totp_enabled"]:
            return redirect(url_for("login"))
        secret = session.get("enroll_secret") or security.new_totp_secret()
        session["enroll_secret"] = secret
        if request.method == "POST":
            step = security.verify_totp(secret, request.form.get("code", ""))
            if step is not None:
                store.set_totp(user["id"], secret, True)
                user = store.user(uid=user["id"])
                if finish_login(user, step):
                    flash("Autenticação em dois fatores ativada.")
                    return redirect(url_for("index"))
            store.fail(client_ip(), user["username"])
            flash("Código inválido. Confira o horário do celular e tente de novo.")
        import segno
        issuer = re.sub(r"[^\w .-]", "", ("OrbyMon " + config_safe_name()).strip())[:40]
        uri = security.otpauth_uri(secret, user["username"], issuer)
        qr = segno.make(uri, error="m").svg_data_uri(scale=5, dark="#111", light="#fff")
        return render_template("enroll.html", qr=qr, secret=secret, username=user["username"])

    def config_safe_name():
        try:
            return config.bidir().get("provider_name", "").strip()
        except Exception:
            return ""

    @app.route("/logout", methods=["POST"])
    def logout():
        if g.get("user"):
            audit("logout")
        session.clear()
        return redirect(url_for("login"))

    @app.route("/senha", methods=["GET", "POST"])
    def password():
        if request.method == "POST":
            if not security.verify_password(request.form.get("current", ""), g.user["pw_hash"]):
                flash("Senha atual incorreta.")
            elif request.form.get("new") != request.form.get("confirm"):
                flash("A confirmação não confere.")
            else:
                try:
                    store.set_password(g.user["id"], security.hash_password(request.form.get("new", "")))
                    audit("senha_alterada")
                    flash("Senha alterada.")
                    return redirect(url_for("index"))
                except ValueError as exc:
                    flash(str(exc))
        return render_template("password.html")

    # ---------------------------------------------------------------- paginas
    def safe(action, fn, ok_message):
        try:
            detail = fn()
            audit(action, detail if isinstance(detail, str) else json.dumps(detail, ensure_ascii=False, default=str))
            flash(ok_message)
        except (ValueError, KeyError) as exc:
            flash("Não salvo: %s" % exc)

    @app.route("/")
    def index():
        status = {}
        for unit in SERVICES:
            try:
                out = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True, timeout=5)
                status[unit] = out.stdout.strip() or "desconhecido"
            except (OSError, subprocess.SubprocessError):
                status[unit] = "desconhecido"
        disk = shutil.disk_usage("/")
        return render_template("index.html", status=status, health=store.health(), events=store.recent_events(),
                               disk_pct=round(100 * disk.used / disk.total, 1), disk_free=disk.free / 1e9)

    @app.route("/rede", methods=["GET", "POST"])
    def network():
        cfg = config.bidir()
        profile = config.profile(cfg)
        if request.method == "POST":
            def apply():
                f = request.form
                new_cfg, new_prof = copy.deepcopy(cfg), copy.deepcopy(profile)
                new_cfg["provider_name"] = f.get("provider_name", "").strip()[:80]
                new_cfg["asns"] = parse_ints(f.get("asns", ""), 1, 4294967295)
                new_prof["protected_cidrs"] = parse_cidrs(f.get("protected_cidrs", ""), 4, allow_host=False)
                new_cfg["ipv6_protected_cidrs"] = parse_cidrs(f.get("ipv6_protected_cidrs", ""), 6, allow_host=False)
                new_prof["inside_private_cidrs"] = parse_cidrs(f.get("inside_private_cidrs", ""), 4, allow_host=False)
                new_cfg["extra_infrastructure_cidrs"] = parse_cidrs(f.get("extra_infrastructure_cidrs", ""))
                new_cfg["a10_sources"] = parse_ips(f.get("a10_sources", ""))
                pools, meta = [], {}
                for i in range(int(f.get("pool_rows", "0"))):
                    cidr = f.get("pool_cidr_%d" % i, "").strip()
                    if not cidr or f.get("pool_del_%d" % i):
                        continue
                    cidr = str(parse_cidrs(cidr, 4, allow_host=False)[0])
                    name = f.get("pool_name_%d" % i, "").strip() or cidr
                    users = int(f.get("pool_users_%d" % i, "32") or 32)
                    pools.append(cidr)
                    meta[cidr] = {"name": name[:64], "max_users_per_ip": users}
                new_prof["cgnat_pools"], new_prof["cgnat_pool_metadata"] = pools, meta
                config.save_network(new_cfg, new_prof)
                return {"antes": _net_summary(cfg, profile), "depois": _net_summary(new_cfg, new_prof)}
            safe("rede_alterada", apply, "Rede salva. Os serviços usam a configuração nova no próximo ciclo.")
            return redirect(url_for("network"))
        return render_template("network.html", cfg=cfg, profile=profile)

    @app.route("/bordas", methods=["GET", "POST"])
    def borders():
        cfg = config.bidir()
        if request.method == "POST":
            f = request.form
            if f.get("action") == "nome":
                def apply_name():
                    idx = int(f.get("if_index", ""))
                    name = f.get("if_name", "").strip()
                    if not 0 < idx < 4294967296 or not re.fullmatch(r"[\w./:() -]{1,128}", name):
                        raise ValueError("ifIndex ou nome inválido")
                    store.upsert_interface(idx, name)
                    return "ifIndex %d = %s" % (idx, name)
                safe("interface_nomeada", apply_name, "Nome salvo.")
            else:
                def apply_edges():
                    edges = sorted({int(x) for x in f.getlist("edge") if x.isdigit()})
                    extra = parse_ints(f.get("extra_edges", ""), 1, 4294967295)
                    edges = sorted(set(edges) | set(extra))
                    new = copy.deepcopy(cfg)
                    before = list(cfg["observation_ifindexes"]["in"])
                    new["observation_ifindexes"] = {"in": edges, "out": edges}
                    config.save_bidir(new)
                    return {"antes": before, "depois": edges}
                safe("bordas_alteradas", apply_edges, "Interfaces de borda salvas.")
            return redirect(url_for("borders"))
        names = {int(i): n for i, n in store.interfaces()}
        seen = {int(i): float(b or 0) for i, b in store.seen_interfaces()}
        edges = set(cfg["observation_ifindexes"]["in"])
        rows = sorted(set(names) | set(seen) | edges)
        return render_template("borders.html", rows=rows, names=names, seen=seen, edges=edges)

    @app.route("/regras", methods=["GET", "POST"])
    def rules():
        cfg = config.bidir()
        if request.method == "POST":
            f = request.form
            if f.get("action") == "calibracao":
                safe("calibracao_aplicada", lambda: config.apply_calibration() or "sem mudancas",
                     "Proposta de calibração aplicada.")
                return redirect(url_for("rules"))

            def apply():
                new = copy.deepcopy(cfg)
                new["cooldown_minutes"] = int(f.get("cooldown_minutes"))
                new["settle_minutes"] = int(f.get("settle_minutes"))
                for i, rule in enumerate(new["rules"]):
                    rule["enabled"] = f.get("r%d_enabled" % i) == "1"
                    rule["severity"] = f.get("r%d_severity" % i, rule["severity"])
                    rule["consecutive_minutes"] = int(f.get("r%d_consecutive" % i, rule["consecutive_minutes"]))
                    for scope, limits in rule["limits"].items():
                        for metric, _, cast in METRICS:
                            key = "r%d_%s_%s" % (i, scope, metric)
                            if metric in limits and f.get(key, "") != "":
                                limits[metric] = cast(f.get(key).replace(",", "."))
                for i, rule in enumerate(new["nat_rules"]):
                    rule["enabled"] = f.get("n%d_enabled" % i) == "1"
                    rule["severity"] = f.get("n%d_severity" % i, rule["severity"])
                    for metric in ("min_allocs_per_min", "min_active_ports"):
                        if metric in rule and f.get("n%d_%s" % (i, metric), "") != "":
                            rule[metric] = int(float(f.get("n%d_%s" % (i, metric))))
                config.save_bidir(new)
                return _rules_diff(cfg, new)
            safe("regras_alteradas", apply, "Regras salvas. O detector usa os valores novos no próximo minuto.")
            return redirect(url_for("rules"))
        proposal, report = config.calibration_proposal()
        return render_template("rules.html", cfg=cfg, proposal=proposal, report=report)

    @app.route("/telegram", methods=["GET", "POST"])
    def telegram():
        current = config.telegram()
        if request.method == "POST":
            f = request.form
            if f.get("action") in ("teste", "chats"):
                try:
                    from ..notify_telegram import Formatter, Settings, Telegram
                    if f.get("action") == "teste":
                        s = Settings.from_env(current)
                        (telegram_factory or Telegram)(s.token, s.chats).send(
                            Formatter(s).header("🛡️", "Teste do painel OrbyMon") + "\nEnviado por %s." % g.user["username"])
                        flash("Mensagem de teste enviada.")
                        audit("telegram_teste")
                    else:
                        token = current.get("TELEGRAM_BOT_TOKEN", "")
                        updates = (telegram_factory or Telegram)(token, []).call("getUpdates", {"timeout": 0}) or []
                        found = {}
                        for upd in updates:
                            msg = upd.get("message") or upd.get("channel_post") or upd.get("my_chat_member") or {}
                            chat = msg.get("chat") or {}
                            if chat.get("id") is not None:
                                found[str(chat["id"])] = chat.get("title") or chat.get("username") or chat.get("first_name") or ""
                        flash("Chats encontrados: " + (", ".join("%s (%s)" % kv for kv in found.items())
                                                        or "nenhum — mande uma mensagem ao bot e tente de novo"))
                except Exception as exc:
                    flash("Falhou: %s" % exc)
                return redirect(url_for("telegram"))

            def apply():
                token = f.get("token", "").strip() or current.get("TELEGRAM_BOT_TOKEN", "")
                if not re.fullmatch(r"\d+:[A-Za-z0-9_-]{30,}", token):
                    raise ValueError("token do bot com formato inválido")
                chats = ",".join(c.strip() for c in re.split(r"[\s,;]+", f.get("chats", "")) if c.strip())
                if not re.fullmatch(r"-?\d+(,-?\d+)*", chats):
                    raise ValueError("chat_id deve ser numérico (grupos começam com -100)")
                sev = f.get("min_severity", "high")
                if sev not in ("warning", "high", "critical"):
                    raise ValueError("severidade inválida")
                reminder, close = int(f.get("reminder", "30")), int(f.get("close", "20"))
                if not (5 <= reminder <= 1440 and 5 <= close <= 1440):
                    raise ValueError("lembrete e encerramento entre 5 e 1440 minutos")
                grafana = f.get("grafana_url", "").strip()
                if grafana and not re.fullmatch(r"https?://[\w.:\-\[\]]+(/[\w./-]*)?", grafana):
                    raise ValueError("URL do Grafana inválida")
                values = {"TELEGRAM_BOT_TOKEN": token, "TELEGRAM_CHAT_IDS": chats, "ORBYMON_NOTIFY_MIN_SEVERITY": sev,
                          "ORBYMON_NOTIFY_REMINDER_MIN": reminder, "ORBYMON_NOTIFY_CLOSE_AFTER_MIN": close,
                          "ORBYMON_GRAFANA_URL": grafana, "ORBYMON_TZ": current.get("ORBYMON_TZ", "America/Bahia"),
                          "ORBYMON_SITE_NAME": f.get("site", "").strip()[:60]}
                config.save_telegram(values)
                shown = dict(values, TELEGRAM_BOT_TOKEN="(alterado)" if f.get("token", "").strip() else "(mantido)")
                return shown
            safe("telegram_alterado", apply, "Telegram salvo. Vale a partir da próxima verificação (30 s).")
            return redirect(url_for("telegram"))
        masked = current.get("TELEGRAM_BOT_TOKEN", "")
        masked = (masked.split(":")[0] + ":••••••" + masked[-4:]) if masked else ""
        return render_template("telegram.html", t=current, masked=masked)

    @app.route("/retencao", methods=["GET", "POST"])
    def retention():
        if request.method == "POST":
            def apply():
                log_days, flow_days = int(request.form.get("log_days", "")), int(request.form.get("flow_days", ""))
                config.save_retention(log_days, flow_days)
                return {"logs_nat_dias": log_days, "fluxos_dias": flow_days}
            safe("retencao_alterada", apply, "Retenção salva.")
            return redirect(url_for("retention"))
        r = config.retention()
        return render_template("retention.html", r=r, cfg=config.bidir())

    @app.route("/usuarios", methods=["GET", "POST"])
    def users():
        if request.method == "POST":
            f = request.form
            action = f.get("action")
            target = store.user(uid=int(f.get("uid", "0"))) if f.get("uid") else None

            def apply():
                if action == "criar":
                    username = f.get("username", "").strip().lower()
                    if not USERNAME.match(username):
                        raise ValueError("usuário: 3 a 40 caracteres (letras minúsculas, números, . _ -)")
                    if store.user(username=username):
                        raise ValueError("usuário já existe")
                    store.create_user(username, security.hash_password(f.get("password", "")), must_change=True)
                    return "criado %s" % username
                if not target:
                    raise ValueError("usuário não encontrado")
                if target["id"] == g.user["id"] and action in ("desativar", "excluir"):
                    raise ValueError("você não pode desativar ou excluir a si mesmo")
                if action == "desativar":
                    store.set_disabled(target["id"], not target["disabled"])
                elif action == "reset2fa":
                    store.set_totp(target["id"], None, False)
                elif action == "excluir":
                    store.delete_user(target["id"])
                else:
                    raise ValueError("ação inválida")
                return "%s %s" % (action, target["username"])
            safe("usuario_" + str(action), apply, "Feito.")
            return redirect(url_for("users"))
        return render_template("users.html", users=store.users())

    @app.route("/auditoria")
    def audit_page():
        return render_template("audit.html", rows=store.audit_list())

    return app


def _net_summary(cfg, profile):
    return {"asns": cfg.get("asns"), "ipv4": profile["protected_cidrs"], "ipv6": cfg.get("ipv6_protected_cidrs"),
            "pools": profile["cgnat_pools"], "interna": profile["inside_private_cidrs"],
            "infra": cfg["extra_infrastructure_cidrs"], "a10": cfg.get("a10_sources")}


def _rules_diff(old, new):
    out = []
    for a, b in zip(old["rules"] + old["nat_rules"], new["rules"] + new["nat_rules"]):
        for key in sorted(set(a) | set(b)):
            if a.get(key) != b.get(key):
                out.append("%s.%s: %s -> %s" % (a["name"], key, json.dumps(a.get(key)), json.dumps(b.get(key))))
    for key in ("cooldown_minutes", "settle_minutes"):
        if old[key] != new[key]:
            out.append("%s: %s -> %s" % (key, old[key], new[key]))
    return out or ["sem mudancas"]


@functools.lru_cache(maxsize=1)
def wsgi_app():
    """Ponto de entrada do gunicorn: fmn_filters.admin.app:wsgi_app()"""
    return create_app()
