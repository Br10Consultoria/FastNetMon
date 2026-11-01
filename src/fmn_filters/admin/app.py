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
            "orbymon-retention.timer", "orbymon-calibrate.timer", "orbymon-filter-rules.timer",
            "orbymon-exceptions.timer", "grafana-server.service", "mariadb.service")


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
                try:
                    store.sync_prefixes(new_cfg, new_prof)          # dashboards usam os blocos novos
                except Exception as exc:                             # nao desfaz a configuracao salva
                    flash("Aviso: blocos dos dashboards não atualizados (%s)." % str(exc)[:120])
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

    # ---------------------------------------------------------------- etapa 2: reputacao e investigacao
    @app.route("/reputacao", methods=["GET", "POST"])
    def reputation():
        from ..reputation import DNSBLS, SOURCES
        current = config.reputation()
        names = [x.name for x in SOURCES] + [x.name for x in DNSBLS] + ["abuseipdb"]
        if request.method == "POST":
            f = request.form

            def apply():
                key = "" if f.get("clear_key") else (f.get("abuseipdb_key", "").strip() or current.get("ABUSEIPDB_API_KEY", ""))
                if key and not re.fullmatch(r"[A-Za-z0-9]{40,128}", key):
                    raise ValueError("chave do AbuseIPDB com formato inválido")
                every = int(f.get("heavy_every_h", "6"))
                if not 1 <= every <= 168:
                    raise ValueError("intervalo das DNSBL entre 1 e 168 horas")
                enabled = set(f.getlist("src"))
                disabled = [n for n in names if n not in enabled]
                config.save_reputation({"ORBYMON_REP_DISABLED": ",".join(disabled),
                                        "ORBYMON_REP_DNSBL": "1" if f.get("dnsbl") else "0",
                                        "ORBYMON_REP_HEAVY_EVERY_H": every, "ABUSEIPDB_API_KEY": key})
                return {"desativadas": disabled, "dnsbl": bool(f.get("dnsbl")), "intervalo_h": every,
                        "abuseipdb": "configurada" if key else "sem chave"}
            safe("reputacao_alterada", apply, "Configuração salva. Vale na próxima verificação (de hora em hora).")
            return redirect(url_for("reputation"))
        disabled = {n.strip() for n in current.get("ORBYMON_REP_DISABLED", "").split(",") if n.strip()}
        key = current.get("ABUSEIPDB_API_KEY", "")
        return render_template("reputation.html", active=_group_listings(store.reputation_listings(True)),
                               removed=_group_listings(store.reputation_listings(False)),
                               sources=store.reputation_sources(), feeds=SOURCES, dnsbls=DNSBLS, disabled=disabled,
                               dnsbl_on=current.get("ORBYMON_REP_DNSBL", "1") != "0",
                               every=current.get("ORBYMON_REP_HEAVY_EVERY_H", "6"),
                               key_masked=(key[:4] + "••••" + key[-4:]) if key else "")

    @app.route("/investigar", methods=["GET", "POST"])
    def investigate():
        from datetime import timezone as dt_timezone
        from zoneinfo import ZoneInfo
        from .. import abuse_lookup as al
        from ..bidir_config import build_scopes
        f = request.form if request.method == "POST" else request.args
        form = {k: f.get(k, "") for k in ("ip", "time", "port", "protocol", "remote", "remote_port", "window", "email")}
        form["tz"] = f.get("tz") if f.get("tz") in TZ_CHOICES else "America/Sao_Paulo"
        tz = dt_timezone.utc if form["tz"] == "UTC" else ZoneInfo(form["tz"])
        results, history, error = [], None, None
        if form["ip"].strip() or form["email"].strip():
            try:
                cfg = config.bidir()
                scopes = build_scopes(cfg, config.profile(cfg))
                window = int(form["window"] or 10)
                if not 1 <= window <= 120:
                    raise ValueError("janela entre 1 e 120 minutos")
                if form["email"].strip():
                    queries = al.extract_reports(form["email"][:200000], scopes, tz, window)[:10]
                    if not queries:
                        raise ValueError("nenhum IP deste provedor com horário encontrado no texto. Confira se o IP "
                                         "denunciado está nos blocos da página Rede.")
                else:
                    ip = str(parse_ips(form["ip"])[0])
                    if form["time"].strip():
                        when = al.parse_time(form["time"], tz)
                        if when is None:
                            raise ValueError("horário não reconhecido (use 2026-10-30 14:05:00 ou 30/10/2026 14:05)")
                        opt = lambda k: int(form[k]) if form[k].strip() else None
                        queries = [al.Query(ip, when, window, opt("port"), form["protocol"] or None,
                                            str(parse_ips(form["remote"])[0]) if form["remote"].strip() else None,
                                            opt("remote_port"))]
                    else:
                        queries = []
                        scope = scopes.classify(ip)[0]
                        history = store.with_connection(lambda db: al.ip_history(db.cursor(), ip, scope, cfg["source"]))
                        history["pool"] = scopes.classify(ip)[1]
                for q in queries:
                    if q.protocol not in (None, "tcp", "udp", "icmp"):
                        raise ValueError("protocolo inválido")
                results = store.with_connection(lambda db: [
                    (r, al.render_text(r, tz)) for r in
                    (al.investigate(q, scopes, cfg["source"], db, str(config.p.nat_dir)) for q in queries)])
                audit("investigacao", "; ".join("%s %s porta %s" % (q.ip, q.when, q.port) for q in queries)
                      or "historico " + form["ip"].strip())
            except (ValueError, IndexError) as exc:
                error = str(exc)
        return render_template("investigate.html", form=form, results=results, history=history, error=error,
                               tz=tz, tz_choices=TZ_CHOICES, ts=al.fmt_ts)

    # ---------------------------------------------------------------- analise avancada (nfdump)
    @app.route("/analise", methods=["GET", "POST"])
    def analysis():
        from datetime import datetime as dt, timedelta as td, timezone as dt_timezone
        from zoneinfo import ZoneInfo
        from .. import flow_query as fq
        from ..abuse_lookup import fmt_ts, parse_time
        from ..bidir_config import build_scopes
        f = request.form if request.method == "POST" else request.args
        saved = store.saved_filters()
        form = {k: f.get(k, "") for k in ("expr", "start", "end", "name", "description")}
        form["mode"] = f.get("mode") if f.get("mode") in fq.MODES else "dstip"
        form["order"] = f.get("order") if f.get("order") in fq.ORDERS else "bytes"
        form["limit"] = f.get("limit") or "20"
        form["period"] = f.get("period") if f.get("period") in ("15", "60", "180", "360", "1440", "custom") else "60"
        form["tz"] = f.get("tz") if f.get("tz") in TZ_CHOICES else "America/Sao_Paulo"
        tz = dt_timezone.utc if form["tz"] == "UTC" else ZoneInfo(form["tz"])
        if f.get("f"):
            chosen = next((x for x in saved if str(x["id"]) == f.get("f")), None)
            if chosen:
                form["expr"] = chosen["expr"]
        result, error, chart = None, None, ""
        action = f.get("action", "")
        if request.method == "POST" and action == "salvar":
            def apply():
                name = form["name"].strip()
                if not 3 <= len(name) <= 80:
                    raise ValueError("nome do filtro entre 3 e 80 caracteres")
                if not form["expr"].strip() or len(form["expr"]) > fq.MAX_EXPR:
                    raise ValueError("filtro vazio ou longo demais")
                store.save_filter(name, form["expr"].strip(), form["description"].strip()[:300], g.user["username"])
                return {"nome": name, "filtro": form["expr"].strip()}
            safe("filtro_salvo", apply, "Filtro salvo.")
            saved = store.saved_filters()
        elif request.method == "POST" and action == "excluir":
            def apply_del():
                if not store.delete_filter(int(f.get("fid", "0"))):
                    raise ValueError("só filtros criados por usuários podem ser excluídos")
                return "filtro %s" % f.get("fid")
            safe("filtro_excluido", apply_del, "Filtro excluído.")
            return redirect(url_for("analysis"))
        elif form["expr"].strip() and (request.method == "POST" or f.get("run")):
            try:
                cfg = config.bidir()
                profile = config.profile(cfg)
                if form["period"] == "custom":
                    start, end = parse_time(form["start"], tz), parse_time(form["end"], tz)
                    if not start or not end:
                        raise fq.QueryError("início/fim com formato inválido (ex.: 2026-11-01 10:00)")
                else:
                    end = dt.now(dt_timezone.utc).replace(tzinfo=None, microsecond=0)
                    start = end - td(minutes=int(form["period"]))
                result = fq.run(form["expr"], start, end, form["mode"], form["order"], int(form["limit"]),
                                config.p.flow_root / cfg["source"], fq.macros(cfg, profile),
                                lock_path=str(config.p.query_lock))
                fq.annotate(result, build_scopes(cfg, profile), {int(i): n for i, n in store.interfaces()})
                chart = fq.svg_series(result.series)
                audit("analise", "%s | %s | %s a %s" % (form["mode"], form["expr"][:500], start, end))
            except (fq.QueryError, ValueError) as exc:
                error = str(exc)
        macro_names = ["@rede", "@src_rede", "@dst_rede", "@pools", "@src_pools", "@dst_pools",
                       "@assinantes", "@src_assinantes", "@dst_assinantes", "@infra"]
        return render_template("analysis.html", form=form, result=result, error=error, chart=chart, saved=saved,
                               modes=fq.MODES, orders=fq.ORDERS, tz=tz, tz_choices=TZ_CHOICES, ts=fmt_ts,
                               human=fq.human, macro_names=macro_names)

    # ---------------------------------------------------------------- alarmes por filtro
    @app.route("/alarmes")
    def alarms():
        from .. import filter_rules as fr
        from .. import flow_query as fq
        rules = store.filter_rules()
        for r in rules:
            r["desc"] = fr.describe(r["definition"]) if r["definition"].get("conditions") else ""
        return render_template("alarms.html", rules=rules, incidents=store.filter_incidents(limit=30),
                               human=fq.human, aggs=fr.AGGS)

    @app.route("/alarmes/nova", methods=["GET", "POST"], defaults={"rid": 0})
    @app.route("/alarmes/<int:rid>", methods=["GET", "POST"])
    def alarm_edit(rid):
        from datetime import datetime as dt, timezone as dt_timezone
        from .. import filter_rules as fr
        from .. import flow_query as fq
        rule = store.filter_rule(rid) if rid else None
        if rid and not rule:
            abort(404)
        f = request.form
        saved = store.saved_filters()
        if request.method == "POST":
            conds = []
            for i in range(4):
                if f.get("c%d_value" % i, "").strip():
                    conds.append({"metric": f.get("c%d_metric" % i), "op": f.get("c%d_op" % i),
                                  "value": f.get("c%d_value" % i).replace(",", "."),
                                  "window": f.get("c%d_window" % i) or 15})
            definition = {"logic": f.get("logic"), "conditions": conds, "consecutive": f.get("consecutive") or 1,
                          "resolve_after": f.get("resolve_after") or 5,
                          "report": {"agg": f.get("agg"), "top": f.get("top") or 5}, "notify": f.get("notify") == "1",
                          "retention_days": f.get("retention_days") or 7}
            form_rule = {"id": rid, "name": f.get("name", ""), "enabled": f.get("enabled") == "1",
                         "severity": f.get("severity", "high"), "direction": f.get("direction", "in"),
                         "expr": f.get("expr", ""), "definition": definition, "builtin": rule["builtin"] if rule else 0}
        else:
            form_rule = rule or {"id": 0, "name": "", "enabled": False, "severity": "high", "direction": "in",
                                 "expr": next((x["expr"] for x in saved if str(x["id"]) == request.args.get("f")), ""),
                                 "definition": {"logic": "and", "conditions": [{"metric": "mbps", "op": "gt", "value": 100}],
                                                "consecutive": 2, "resolve_after": 5,
                                                "report": {"agg": "dstip", "top": 5}, "notify": True,
                                                "retention_days": 7}, "builtin": 0}
        action = f.get("action", "")
        simulation, chart, error = None, "", None
        if request.method == "POST":
            if action == "usar_filtro":
                chosen = next((x for x in saved if str(x["id"]) == f.get("saved_id")), None)
                if chosen:
                    form_rule["expr"] = chosen["expr"]
            elif action == "excluir" and rid:
                store.delete_filter_rule(rid)
                audit("alarme_excluido", rule["name"])
                flash("Alarme excluído.")
                return redirect(url_for("alarms"))
            elif action == "ligar" and rid:
                store.set_filter_rule_enabled(rid, not rule["enabled"])
                audit("alarme_" + ("desligado" if rule["enabled"] else "ligado"), rule["name"])
                flash("Alarme %s." % ("desligado" if rule["enabled"] else "ligado"))
                return redirect(url_for("alarm_edit", rid=rid))
            else:
                try:
                    cfg = config.bidir()
                    table = fq.macros(cfg, config.profile(cfg))
                    name, expr, definition = fr.validate(form_rule["name"], form_rule["expr"], definition,
                                                         form_rule["severity"], form_rule["direction"], table)
                    form_rule.update(name=name, expr=expr, definition=definition)
                    if action == "testar":
                        now = dt.now(dt_timezone.utc).replace(tzinfo=None, microsecond=0)
                        minutes = min(120, max(5, int(f.get("test_minutes") or 30)))
                        usual_fn = (lambda m, days: store.filter_rule_usual(rid, m, days)) if rid else None
                        simulation = fr.simulate(config.p.flow_root / cfg["source"], expr, definition, table, now,
                                                 minutes, usual_fn=usual_fn)
                        key = {"mbps": "bps"}.get(definition["conditions"][0]["metric"],
                                                  definition["conditions"][0]["metric"])
                        chart = fq.svg_series(simulation, key, marks=[p["matched"] for p in simulation])
                    else:
                        new_id = store.save_filter_rule(rid, name, form_rule["enabled"], form_rule["severity"],
                                                        form_rule["direction"], expr, definition, g.user["username"])
                        audit("alarme_salvo", json.dumps({"nome": name, "filtro": expr, "regra": definition,
                                                          "ligado": form_rule["enabled"]}, ensure_ascii=False))
                        flash("Alarme salvo. %s" % ("Avaliado a cada minuto." if form_rule["enabled"]
                                                    else "Está desligado: ligue quando o teste estiver bom."))
                        return redirect(url_for("alarm_edit", rid=new_id))
                except (fr.RuleError, fq.QueryError, ValueError) as exc:
                    error = str(exc)
                except Exception as exc:                       # ex.: nome repetido
                    error = "não foi possível salvar: %s" % str(exc)[:200]
        history, incidents, hist_chart = [], [], ""
        if rid:
            history = store.filter_rule_samples(rid, 6)
            incidents = store.filter_incidents(rid, 20)
            d0 = form_rule["definition"]["conditions"][0]["metric"] if form_rule["definition"]["conditions"] else "mbps"
            hist_chart = fq.svg_series(history, {"mbps": "bps"}.get(d0, d0), marks=[h["matched"] for h in history])
        return render_template("alarm_edit.html", rule=form_rule, saved=saved, simulation=simulation, chart=chart,
                               error=error, history=history, hist_chart=hist_chart, incidents=incidents,
                               metrics=fr.METRICS, ops=fr.OPS, aggs=fr.AGGS, human=fq.human,
                               describe=fr.describe)

    # ---------------------------------------------------------------- etapa 2: excecoes e linha de base
    @app.route("/excecoes", methods=["GET", "POST"])
    def exceptions_page():
        from .. import exceptions as ex
        cfg = config.bidir()
        rule_names = [r["name"] for r in cfg["rules"]]
        f = request.form
        form = {"kind": request.args.get("kind", "cidr"), "value": request.args.get("value", ""),
                "side": request.args.get("side", "remote"), "direction": request.args.get("direction", "any"),
                "rule_name": request.args.get("rule", ""), "action": request.args.get("action", "ignore"),
                "factor": request.args.get("factor", "3"), "note": "", "days": ""}
        if request.method == "POST":
            action = f.get("action")
            try:
                if action == "excluir":
                    eid = int(f.get("id", 0))
                    item = next((x for x in store.exceptions() if x["id"] == eid), None)
                    if item and store.delete_exception(eid):
                        audit("excecao_excluida", ex.describe(item))
                        flash("Exceção removida. O detector deixa de usá-la no próximo minuto.")
                    return redirect(url_for("exceptions_page"))
                if action == "sincronizar":
                    flash("Prefixos: %s" % (store.sync_exception(int(f.get("id", 0))) or "nada a atualizar"))
                    return redirect(url_for("exceptions_page"))
                if action == "preset":
                    asn = int(f.get("asn", 0))
                    if asn not in dict((a, n) for n, a in ex.PRESETS):
                        raise ex.ExceptionError("grupo desconhecido")
                    name = dict((a, n) for n, a in ex.PRESETS)[asn]
                    e = ex.validate("asn", str(asn), "remote", f.get("direction", "in"), f.get("rule_name", ""),
                                    "ignore", 1, name)
                else:
                    form = {k: f.get(k, "") for k in form}
                    e = ex.validate(form["kind"], form["value"], form["side"], form["direction"], form["rule_name"],
                                    form["action"], form["factor"], form["note"], form["days"] or None)
                if e["rule_name"] and e["rule_name"] not in rule_names:
                    raise ex.ExceptionError("regra desconhecida")
                eid = store.save_exception(e, g.user["username"])
                audit("excecao_salva", ex.describe(e) + (" — " + e["note"] if e["note"] else ""))
                msg = "Exceção salva: %s." % ex.describe(e)
                if e["kind"] == "asn":
                    msg += " Prefixos: %s" % (store.sync_exception(eid) or "consulta pendente (atualização diária)")
                flash(msg)
                return redirect(url_for("exceptions_page"))
            except (ex.ExceptionError, ValueError) as exc:
                flash("Não salvo: %s" % exc)
        return render_template("exceptions.html", items=store.exceptions(), form=form, rule_names=rule_names,
                               presets=ex.PRESETS, describe=ex.describe)

    @app.route("/base", methods=["GET", "POST"])
    def baseline_page():
        from .. import baseline as bl
        cfg = config.bidir()
        if request.method == "POST":
            f = request.form

            def apply():
                new = copy.deepcopy(cfg)
                new["dynamic_thresholds"] = {
                    "enabled": f.get("enabled") == "1", "factor": float(f.get("factor", "2").replace(",", ".")),
                    "min_days": int(f.get("min_days", 3)),
                    "floor_ratio": float(f.get("floor_pct", "25").replace(",", ".")) / 100,
                    "timezone": f.get("timezone", "America/Sao_Paulo")}
                config.save_bidir(new)
                return new["dynamic_thresholds"]
            safe("limite_dinamico", apply, "Configuração salva. O detector usa no próximo minuto.")
            return redirect(url_for("baseline_page", r=request.args.get("r", 0), s=request.args.get("s", "")))
        st = bl.settings(cfg)
        table = store.baseline_table()
        rules = [r for r in cfg["rules"]]
        try:
            ri = min(max(int(request.args.get("r", 0)), 0), len(rules) - 1)
        except ValueError:
            ri = 0
        rule = rules[ri]
        scope = request.args.get("s") if request.args.get("s") in rule["limits"] else next(iter(rule["limits"]))
        prof = bl.profile(table, cfg, rule, scope)
        charts = {(dt, m): _svg_hours(prof[dt], m) for dt in bl.DAYTYPES for m in bl.METRICS
                  if m in rule["limits"][scope]}
        coverage = {}
        for (rn, sc, _dt, _h, _m), (_v, days) in table.items():
            k = (rn, sc)
            coverage[k] = max(coverage.get(k, 0), days)
        _, report = config.calibration_proposal()
        offenders = []
        for e in (report or {}).get("regras", []):
            for o in e.get("reincidentes", []):
                offenders.append(dict(o, regra=e["regra"]))
        offenders.sort(key=lambda o: -o["alarmes"])
        direction = {r["name"]: r["direction"] for r in rules}
        return render_template("baseline.html", st=st, rules=rules, ri=ri, rule=rule, scope=scope, prof=prof,
                               charts=charts, coverage=coverage, offenders=offenders[:20], direction=direction,
                               daytypes=bl.DAYTYPES, tz_choices=TZ_CHOICES, report=report)


    return app


TZ_CHOICES = ("America/Sao_Paulo", "UTC", "America/Bahia", "America/Manaus", "Europe/Berlin", "Europe/London",
              "Europe/Paris", "America/New_York", "America/Chicago", "America/Los_Angeles", "Asia/Tokyo")


def _svg_hours(hours, metric, width=720, height=150):
    """Barras por hora: limite efetivo (cheio) sobre o limite fixo (contorno) e o p99,9 medido (traço)."""
    top = max([h[metric]["static"] for h in hours] + [h[metric]["base"] or 0 for h in hours]) or 1.0
    bw = width / 24.0
    y = lambda v: height - 18 - (v / top) * (height - 30)
    parts = ['<svg class="chart hours" viewBox="0 0 %d %d" role="img" aria-label="Limite por hora">' % (width, height)]
    for h in hours:
        m, x = h[metric], h["hour"] * bw
        parts.append('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" class="static"/>'
                     % (x + 2, y(m["static"]), bw - 4, height - 18 - y(m["static"])))
        parts.append('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" class="%s"/>'
                     % (x + 2, y(m["limit"]), bw - 4, height - 18 - y(m["limit"]), "dyn" if h["dynamic"] else "fix"))
        if m["base"] is not None:
            parts.append('<line x1="%.1f" x2="%.1f" y1="%.1f" y2="%.1f" class="base"/>'
                         % (x + 2, x + bw - 2, y(m["base"]), y(m["base"])))
        if h["hour"] % 3 == 0:
            parts.append('<text x="%.1f" y="%d" class="lbl">%02dh</text>' % (x + 2, height - 4, h["hour"]))
    parts.append('<text x="4" y="12" class="lbl">máx. %s</text></svg>' % ("%g" % round(top, 1)))
    return "".join(parts)


def _group_listings(rows):
    from ..reputation import detail_rank
    groups = {}
    for r in rows:
        g = groups.setdefault(r["entry"], {"entry": r["entry"], "scope": r["scope"], "pool": r["pool"], "lists": [],
                                           "detail": {}, "desde": r["desde"], "saiu": r["saiu"]})
        g["lists"].append(r)
        g["desde"] = min(g["desde"], r["desde"]) if g["desde"] and r["desde"] else g["desde"] or r["desde"]
        try:
            d = json.loads(r["detail"]) if isinstance(r["detail"], (str, bytes)) else (r["detail"] or {})
        except ValueError:
            d = {}
        if detail_rank(d) > detail_rank(g["detail"]):
            g["detail"] = d
    return list(groups.values())


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
