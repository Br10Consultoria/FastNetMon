"""Clientes e RADIUS: validacao, busca por prefixo, login PPPoE por IP e horario, uso nos avisos e na investigacao."""
from datetime import datetime, timedelta
import os
import unittest

from fmn_filters import customers as cu

DB_ENABLED = os.environ.get("ORBYMON_TEST_DB") == "1" and os.environ.get("ORBYMON_DB_USER")


class ValidateTests(unittest.TestCase):
    def test_customer(self):
        c = cu.validate_customer("  Padaria  Central ", "C-1", "187.87.201.40\n187.87.201.40/32, 2804:4fa8:10::/48", "", "")
        self.assertEqual(c["name"], "Padaria Central")
        self.assertEqual(c["prefixes"], ["187.87.201.40/32", "2804:4fa8:10::/48"])
        for bad in (("x", "", "1.2.3.4"), ("Nome", "", ""), ("Nome", "", "10.0.0.0/8"), ("Nome", "", "lixo")):
            with self.assertRaises(cu.CustomerError):
                cu.validate_customer(*bad)

    def test_radius_settings(self):
        self.assertEqual(cu.validate_radius({})["RADIUS_DB_HOST"], "")
        v = cu.validate_radius({"RADIUS_DB_HOST": "10.0.0.5", "RADIUS_DB_NAME": "radius", "RADIUS_DB_USER": "orby"})
        self.assertEqual((v["RADIUS_DB_PORT"], v["RADIUS_TABLE"], v["RADIUS_TZ"]), ("3306", "radacct", "America/Sao_Paulo"))
        self.assertEqual(cu.validate_radius({"RADIUS_MODE": "radacct_pg", "RADIUS_DB_HOST": "h", "RADIUS_DB_NAME": "r",
                                             "RADIUS_DB_USER": "u", "RADIUS_TABLE": "public.radacct"})["RADIUS_DB_PORT"],
                         "5432")
        for bad in ({"RADIUS_TABLE": "radacct; drop"}, {"RADIUS_DB_PORT": "99999"}, {"RADIUS_DB_HOST": "a b"},
                    {"RADIUS_TZ": "Lua/Base"}, {"RADIUS_MODE": "ldap"},
                    {"RADIUS_MODE": "sql_mysql", "RADIUS_SQL_B64": cu.b64e("DELETE FROM radacct WHERE ip={ip}")},
                    {"RADIUS_MODE": "sql_mysql", "RADIUS_SQL_B64": cu.b64e("SELECT 1; DROP TABLE x")},
                    {"RADIUS_MODE": "sql_mysql", "RADIUS_SQL_B64": cu.b64e("SELECT login FROM t")},
                    {"RADIUS_MODE": "http", "RADIUS_HTTP_URL": "ftp://erp/x?ip={ip}"},
                    {"RADIUS_MODE": "http", "RADIUS_HTTP_URL": "https://erp/x"},
                    {"RADIUS_MODE": "http", "RADIUS_HTTP_URL": "https://erp/x?ip={ip}",
                     "RADIUS_HTTP_HEADERS_B64": cu.b64e("Authorization Bearer x")}):
            with self.assertRaises(cu.CustomerError):
                cu.validate_radius(dict({"RADIUS_DB_HOST": "h", "RADIUS_DB_NAME": "r", "RADIUS_DB_USER": "u"}, **bad))


class IndexTests(unittest.TestCase):
    def test_most_specific(self):
        i = cu.CustomerIndex([(1, "Atacado", "", "45.238.170.0/24"), (2, "Loja", "L2", "45.238.170.64/29"),
                              (3, "V6", "", "2804:4fa8:1::/48")])
        self.assertEqual(i.lookup("45.238.170.66")["name"], "Loja")
        self.assertEqual(i.lookup("45.238.170.1")["name"], "Atacado")
        self.assertIsNone(i.lookup("45.238.171.1"))
        self.assertEqual(i.lookup("2804:4fa8:1::9")["name"], "V6")
        self.assertIsNone(i.lookup("nao-ip"))


class FakeCursor:
    def __init__(self, rows, log):
        self.rows, self.log = rows, log

    def execute(self, sql, params):
        self.log.append((sql, params))

    def fetchall(self):
        return self.rows


class FakeConn:
    def __init__(self, rows, log):
        self.rows, self.log = rows, log

    def cursor(self):
        return FakeCursor(self.rows, self.log)

    def close(self):
        pass


ENV = {"RADIUS_DB_HOST": "10.0.0.5", "RADIUS_DB_NAME": "radius", "RADIUS_DB_USER": "orby", "RADIUS_TZ": "America/Bahia"}


class RadiusTests(unittest.TestCase):
    def test_sessions_convert_timezone_and_cache(self):
        log = []
        rows = [("joao123", datetime(2026, 11, 1, 9, 0), None, "AA:BB:CC:00:11:22", "10.1.1.1")]
        r = cu.Radius(ENV, connect=lambda **kw: FakeConn(rows, log))
        got = r.sessions("100.64.70.12", datetime(2026, 11, 1, 15, 0))
        self.assertEqual(got[0]["login"], "joao123")
        self.assertEqual(got[0]["inicio"], datetime(2026, 11, 1, 12, 0))          # 09h Bahia = 12h UTC
        self.assertEqual(log[0][1], ("100.64.70.12", datetime(2026, 11, 1, 12, 0), datetime(2026, 11, 1, 12, 0)))
        self.assertIn("FROM radacct WHERE framedipaddress=%s", log[0][0])
        r.sessions("100.64.70.12", datetime(2026, 11, 1, 15, 0, 30))
        self.assertEqual(len(log), 1)                                             # cache por minuto

    def test_failure_is_contained(self):
        def boom(**kw):
            raise OSError("timeout")
        r = cu.Radius(ENV, connect=boom)
        with self.assertRaises(cu.RadiusError):
            r.sessions("100.64.70.12", datetime(2026, 11, 1, 15, 0))
        self.assertEqual(r.sessions("100.64.70.12", datetime(2026, 11, 1, 15, 0)), [])   # nao tenta de novo
        ident = cu.Identifier(cu.Radius(ENV, connect=boom), cu.CustomerIndex([(1, "Loja", "", "187.87.201.40/32")]))
        self.assertEqual(ident("187.87.201.40", datetime(2026, 11, 1)), "cliente Loja")
        self.assertEqual(ident("100.64.70.12", datetime(2026, 11, 1)), "")

    def test_identifier_in_telegram_and_investigation(self):
        rows = [("joao123", datetime(2026, 11, 1, 9, 0), None, "AA:BB", "10.1.1.1")]
        ident = cu.Identifier(cu.Radius(ENV, connect=lambda **kw: FakeConn(rows, [])), cu.CustomerIndex())
        self.assertEqual(ident("100.64.70.12", datetime(2026, 11, 1, 15)), "login joao123 · MAC AA:BB")
        from fmn_filters.notify_telegram import Formatter, Settings
        fmt = Formatter(Settings.from_env({"TELEGRAM_BOT_TOKEN": "1:" + "a" * 35, "TELEGRAM_CHAT_IDS": "1"}), ident)
        ev = {"scope": "cgnat_subscriber", "local_ip": "45.238.170.70", "pool": "NAT-POOL-08",
              "subscriber_ip": "100.64.70.12", "event_time": datetime(2026, 11, 1, 15)}
        self.assertIn("Identificação: login joao123 · MAC AA:BB", "\n".join(fmt.who(ev)))
        from fmn_filters.filter_rules import fmt_item
        line = fmt_item({"key": "45.238.170.70", "pool": "NAT-POOL-08", "assinantes": ["100.64.70.12"], "bps": 1e6,
                         "pps": 10}, ident, datetime(2026, 11, 1, 15))
        self.assertIn("<code>100.64.70.12</code> (login joao123 · MAC AA:BB)", line)
        from fmn_filters import abuse_lookup as al
        r = al.Result(al.Query("45.238.170.70", datetime(2026, 11, 1, 15), 10, 40000), "cgnat_pool", "NAT-POOL-08",
                      "x", "alta", subscribers=[{"ip": "100.64.70.12", "portas": 1}])
        al.identify_result(r, ident)
        self.assertIn("assinante 100.64.70.12: login joao123", al.render_text(r))


class Resp:
    def __init__(self, data):
        self.data = data

    def read(self, n=-1):
        return self.data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class SourceTests(unittest.TestCase):
    def test_parse_when(self):
        from zoneinfo import ZoneInfo
        tz = ZoneInfo("America/Bahia")
        for raw, want in (("2026-11-01 09:00:00", datetime(2026, 11, 1, 12)), ("2026-11-01T12:00:00Z", datetime(2026, 11, 1, 12)),
                          ("01/11/2026 09:00", datetime(2026, 11, 1, 12)), ("1793534400", datetime(2026, 11, 1, 12)),
                          ("1793534400000", datetime(2026, 11, 1, 12)), (datetime(2026, 11, 1, 9), datetime(2026, 11, 1, 12)),
                          ("0000-00-00 00:00:00", None), ("", None), (None, None), ("lixo", None)):
            self.assertEqual(cu.parse_when(raw, tz), want, raw)

    def test_http_api(self):
        env = {"RADIUS_MODE": "http", "RADIUS_TZ": "America/Bahia",
               "RADIUS_HTTP_URL": "https://erp.exemplo/api/conexoes?ip={ip}&data={data}", "RADIUS_HTTP_METHOD": "POST",
               "RADIUS_HTTP_BODY_B64": cu.b64e('{"filtro": "{ip}", "quando": "{quando}"}'),
               "RADIUS_HTTP_HEADERS_B64": cu.b64e("Authorization: Basic c2VncmVkbw=="),
               "RADIUS_HTTP_LIST": "registros", "RADIUS_HTTP_LOGIN": "login", "RADIUS_HTTP_START": "inicio",
               "RADIUS_HTTP_STOP": "fim", "RADIUS_HTTP_MAC": "equip.mac"}
        payload = {"registros": [
            {"login": "antigo", "inicio": "2026-10-31 08:00:00", "fim": "2026-11-01 08:00:00", "equip": {"mac": "M1"}},
            {"login": "joao123", "inicio": "2026-11-01 08:30:00", "fim": "", "equip": {"mac": "M2"}},
            {"login": "", "inicio": "2026-11-01 08:30:00"}]}
        seen = []

        def opener(req, timeout):
            seen.append(req)
            return Resp(__import__("json").dumps(payload).encode())
        r = cu.Radius(env, opener=opener)
        got = r.sessions("100.64.70.12", datetime(2026, 11, 1, 15))
        self.assertEqual([(s["login"], s["mac"]) for s in got], [("joao123", "M2")])
        self.assertEqual(got[0]["inicio"], datetime(2026, 11, 1, 11, 30))
        req = seen[0]
        self.assertEqual(req.full_url, "https://erp.exemplo/api/conexoes?ip=100.64.70.12&data=2026-11-01")
        self.assertEqual(req.get_method(), "POST")
        self.assertEqual(__import__("json").loads(req.data), {"filtro": "100.64.70.12", "quando": "2026-11-01 12:00:00"})
        self.assertEqual(req.get_header("Authorization"), "Basic c2VncmVkbw==")
        self.assertIn("joao123", r.last_raw)
        old = cu.Radius(env, opener=opener).sessions("100.64.70.12", datetime(2026, 10, 31, 15))
        self.assertEqual([s["login"] for s in old], ["antigo"])
        bad = cu.Radius(env, opener=lambda req, timeout: Resp(b"<html>erro</html>"))
        with self.assertRaises(cu.RadiusError):
            bad.sessions("100.64.70.12", datetime(2026, 11, 1, 15))

    def test_orbycore_preset(self):
        env = dict(cu.apply_preset("orbycore", "https://erp.exemplo.com.br/"), RADIUS_TZ="America/Bahia",
                   RADIUS_HTTP_HEADERS_B64=cu.b64e("Authorization: ServiceToken orby_teste"))
        self.assertEqual(cu.validate_radius(env)["RADIUS_MODE"], "http")
        # formato do RadiusAccountingLogSerializer do OrbyCore (lista na raiz, datas ISO com fuso)
        payload = [
            {"source": "hot", "username": "joao123", "assigned_ip": "100.64.70.12", "mac_address": "AA:BB",
             "started_at": "2026-10-20T08:30:00-03:00", "ended_at": None, "customer_name": "João da Silva",
             "contract_number": "000123"},
            {"source": "archive", "username": "antigo", "assigned_ip": "100.64.70.12", "mac_address": "CC:DD",
             "started_at": "2026-10-01T08:00:00-03:00", "ended_at": "2026-10-19T23:00:00-03:00",
             "customer_name": "Outro", "contract_number": "9"}]
        seen = []

        def opener(req, timeout):
            seen.append(req)
            return Resp(__import__("json").dumps(payload).encode())
        r = cu.Radius(env, opener=opener)
        got = r.sessions("100.64.70.12", datetime(2026, 11, 1, 15))
        self.assertEqual([(x["login"], x["cliente"], x["contrato"]) for x in got], [("joao123", "João da Silva", "000123")])
        url = seen[0].full_url
        self.assertTrue(url.startswith("https://erp.exemplo.com.br/api/v1/network/radius/accounting/?assigned_ip=100.64.70.12"))
        self.assertIn("from=2026-10-01T15%3A00%3A00%2B00%3A00", url)            # 31 dias antes
        self.assertIn("to=2026-11-01T15%3A00%3A00%2B00%3A00", url)
        self.assertEqual(seen[0].get_header("Authorization"), "ServiceToken orby_teste")
        ident = cu.Identifier(cu.Radius(env, opener=opener), cu.CustomerIndex())
        self.assertEqual(ident("100.64.70.12", datetime(2026, 11, 1, 15)),
                         "login joao123 · MAC AA:BB · João da Silva (contrato 000123)")
        with self.assertRaises(cu.CustomerError):
            cu.apply_preset("orbycore", "erp sem http")

    def test_custom_sql_placeholders(self):
        log = []
        sql = "SELECT c.login, s.inicio, s.fim, s.mac FROM sessoes s JOIN clientes c ON c.id=s.cliente " \
              "WHERE s.ip = {ip} AND s.inicio <= {quando} AND (s.fim IS NULL OR s.fim >= {quando}) AND c.obs LIKE '%x%'"
        env = dict(ENV, RADIUS_MODE="sql_mysql", RADIUS_SQL_B64=cu.b64e(sql))
        r = cu.Radius(env, connect=lambda **kw: FakeConn([("maria", datetime(2026, 11, 1, 8), None, "M9")], log))
        self.assertEqual(r.sessions("100.64.70.12", datetime(2026, 11, 1, 15))[0]["login"], "maria")
        q, params = log[0]
        self.assertIn("s.ip = %s AND s.inicio <= %s", q)
        self.assertIn("LIKE '%%x%%'", q)
        self.assertEqual(params, ("100.64.70.12", datetime(2026, 11, 1, 12), datetime(2026, 11, 1, 12)))


@unittest.skipUnless(DB_ENABLED, "defina ORBYMON_TEST_DB=1 e ORBYMON_DB_*")
class MariaDbTests(unittest.TestCase):
    def test_real_radacct_and_customer_index(self):
        import pymysql
        env = {"RADIUS_DB_HOST": os.environ.get("ORBYMON_DB_HOST", "127.0.0.1"), "RADIUS_DB_NAME": "radius_test",
               "RADIUS_DB_USER": os.environ["ORBYMON_DB_USER"], "RADIUS_DB_PASSWORD": os.environ["ORBYMON_DB_PASSWORD"],
               "RADIUS_TZ": "America/Bahia"}
        root = pymysql.connect(unix_socket="/run/mysqld/mysqld.sock", user="root", database="radius_test") \
            if os.path.exists("/run/mysqld/mysqld.sock") and os.geteuid() == 0 else None
        if root is None:
            self.skipTest("precisa de root local para preparar radius_test")
        cur = root.cursor()
        cur.execute("DELETE FROM radacct")
        cur.executemany("INSERT INTO radacct (username,framedipaddress,acctstarttime,acctstoptime,callingstationid) "
                        "VALUES (%s,%s,%s,%s,%s)", [
                            ("antigo", "100.64.70.12", datetime(2026, 10, 31, 8), datetime(2026, 11, 1, 8), "M1"),
                            ("joao123", "100.64.70.12", datetime(2026, 11, 1, 8, 30), None, "M2"),
                            ("outro", "100.64.70.13", datetime(2026, 11, 1, 8), None, "M3")])
        root.commit()
        try:
            r = cu.Radius(env)
            self.assertEqual([s["login"] for s in r.sessions("100.64.70.12", datetime(2026, 11, 1, 12))], ["joao123"])
            self.assertEqual([s["login"] for s in r.sessions("100.64.70.12", datetime(2026, 11, 1, 10, 30))],
                             ["antigo"])                                           # 07h30 Bahia
            self.assertEqual(r.sessions("100.64.70.99", datetime(2026, 11, 1, 12)), [])
            r.close()
        finally:
            cur.execute("DELETE FROM radacct")
            root.commit()
            root.close()
        from fmn_filters.mysql_sink import connection_from_env
        db = connection_from_env()
        try:
            c = db.cursor()
            c.execute("INSERT INTO orby_customers (name) VALUES ('teste cliente')")
            cid = c.lastrowid
            c.execute("INSERT INTO orby_customer_prefixes VALUES (%s,'187.87.201.40/30')", (cid,))
            db.commit()
            self.assertEqual(cu.load_index(db.cursor()).lookup("187.87.201.42")["name"], "teste cliente")
            ident = cu.build_identifier(db, None)
            self.assertEqual(ident("187.87.201.41", datetime(2026, 11, 1)), "cliente teste cliente")
        finally:
            c.execute("DELETE FROM orby_customer_prefixes WHERE customer_id=%s", (cid,))
            c.execute("DELETE FROM orby_customers WHERE id=%s", (cid,))
            db.commit()
            db.close()


if __name__ == "__main__":
    unittest.main()
