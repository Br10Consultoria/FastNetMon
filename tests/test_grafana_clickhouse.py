"""Dashboards no ClickHouse: cada consulta convertida roda no motor real (chdb) com dados de exemplo,
com as macros expandidas como o plugin grafana-clickhouse-datasource faz."""
import calendar
from datetime import datetime, timedelta
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest

from fmn_filters import clickhouse as ch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "grafana"))
import clickhouse_sql as cs  # noqa: E402

try:
    from chdb import session as chs
    HAVE_CHDB = True
except ImportError:
    HAVE_CHDB = False

T0 = datetime(2026, 11, 1, 10, 0)
FROM = calendar.timegm(T0.timetuple())
TO = FROM + 3600                                   # 10:00 a 11:00 UTC


def expand(sql):
    sql = re.sub(r"\$__timeFilter\(([\w.]+)\)", r"\1 >= toDateTime(%d) AND \1 <= toDateTime(%d)" % (FROM, TO), sql)
    return sql.replace("$__fromTime", "toDateTime(%d)" % FROM).replace("$__toTime", "toDateTime(%d)" % TO)


def pair(m, src, dst, proto="udp", port=53, inp=10, out=20, direction=0, sc="US", dc="BR", sasn=15169, pk=2048.0):
    return ("huawei", T0 + timedelta(minutes=m), src, dst, proto, port, inp, out, direction,
            src.rsplit(".", 1)[0] + ".0/24" if "." in src else "", dst.rsplit(".", 1)[0] + ".0/24" if "." in dst else "",
            sasn, 262687, "Google LLC" if sasn else "", "BR10", sc, dc, 37.7 if sc else None, -122.4 if sc else None,
            -12.9, -38.5, pk, pk * 700, 1)


class ConvertTests(unittest.TestCase):
    def test_rules(self):
        sql = ("SELECT src_ip AS 'IP', GROUP_CONCAT(DISTINCT NULLIF(src_prefix,'') ORDER BY src_prefix SEPARATOR ', ' "
               "LIMIT 3) AS b, TIMESTAMPDIFF(SECOND,MAX(bucket_utc),UTC_TIMESTAMP()) AS c FROM orby_ip_pairs_minute "
               "WHERE EXISTS (SELECT 1 FROM orby_net_prefixes np WHERE np.kind='protected' AND INET_ATON(src_ip) "
               "BETWEEN np.v_start AND np.v_end) AND $__timeFilter(bucket_utc)")
        out = cs.convert_sql(sql)
        self.assertIn('AS "IP"', out)
        self.assertIn("groupUniqArray(nullIf(src_prefix,''))", out)
        self.assertIn("dateDiff('second',MAX(bucket_utc),now('UTC'))", out)
        self.assertIn("arrayExists(r -> IPv4StringToNumOrDefault(src_ip)", out)
        with self.assertRaises(ValueError):
            cs.convert_sql("SELECT DATE_FORMAT(x) FROM t WHERE INET_ATON(a.b + 1)")

    def test_generated_files_match(self):
        for name in cs.DASHBOARDS:
            src = json.loads((ROOT / "grafana" / "dashboards" / (name + ".json")).read_text())
            gen = json.loads((ROOT / "grafana" / "dashboards-clickhouse" / (name + ".json")).read_text())
            self.assertEqual(cs.convert_dashboard(src)[0], gen, "%s desatualizado: rode grafana/clickhouse_sql.py"
                             % name)
            self.assertEqual(src["uid"], gen["uid"])                    # mesmo UID: substitui no Grafana


@unittest.skipUnless(HAVE_CHDB, "chdb nao instalado")
class RunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.s = chs.Session(str(cls.tmp / "db"))
        for sql in ch.schema(30):
            cls.s.query(sql)
        cls.s.query("USE orbyflow")
        rows = []
        for m in range(0, 50, 5):
            rows += [pair(m, "8.8.8.%d" % i, "187.87.201.40") for i in range(1, 6)]
            rows += [pair(m, "45.238.170.70", "1.1.1.1", "tcp", 443, 20, 10, 1, "BR", "AU", 262687)]   # pool na origem
            rows += [pair(m, "203.0.113.9", "45.238.171.80", "tcp", 22, sc="CN", sasn=4134)]           # pool no destino
            rows += [pair(m, "100.64.65.10", "9.9.9.9", "tcp", 23, 30, 10, sc="", dc="CH", sasn=0)]     # privado
            rows += [pair(m, "2001:db8::1", "2804:4fa8::5", "udp", 443, sc="", dc="", sasn=0)]          # IPv6
        cls.s.query("INSERT INTO orby_ip_pairs_minute (%s) FORMAT TabSeparated\n%s"
                    % (",".join(ch.PAIRS_COLUMNS), ch.encode_rows(rows).decode()))
        dims = {"orby_interface_names": [("huawei", 10, "100GE0/1/0"), ("huawei", 20, "Eth-Trunk1")],
                "orby_country_names": [("US", "Estados Unidos"), ("BR", "Brasil"), ("CN", "China")],
                "orby_net_prefixes": [("protected", "187.87.201.0/24", "", 3142568192, 3142568447),
                                      ("protected", "45.238.170.0/23", "", 770615808, 770616319),
                                      ("pool", "45.238.170.64/26", "NAT-POOL-08", 770615872, 770615935),
                                      ("pool", "45.238.171.64/26", "NAT-POOL-09", 770616128, 770616191),
                                      ("private", "100.64.64.0/19", "", 1681932288, 1681940479)]}
        for t, r in dims.items():
            cls.s.query("INSERT INTO %s (%s) FORMAT TabSeparated\n%s"
                        % (t, ",".join(ch.DIMENSIONS[t][1]), ch.encode_rows(r).decode()))

    @classmethod
    def tearDownClass(cls):
        cls.s.close()
        shutil.rmtree(cls.tmp)

    def test_every_converted_query_runs(self):
        empty, total = [], 0
        for name in cs.DASHBOARDS:
            dash = json.loads((ROOT / "grafana" / "dashboards-clickhouse" / (name + ".json")).read_text())
            for p in dash["panels"]:
                for t in p.get("targets", []):
                    if t.get("datasource", {}).get("type") != cs.DS["type"]:
                        continue
                    total += 1
                    sql = expand(t["rawSql"]) + " SETTINGS join_use_nulls=1 FORMAT JSON"
                    try:
                        res = json.loads(str(self.s.query(sql)))
                    except Exception as exc:
                        self.fail("%s / %s: %s\n%s" % (name, p["title"], str(exc)[:400], t["rawSql"][:600]))
                    if not res["data"]:
                        empty.append("%s / %s" % (name, p["title"]))
                    if t["queryType"] == "timeseries":
                        self.assertEqual(res["meta"][0]["name"], "time", p["title"])
        self.assertEqual(total, 50)
        self.assertLessEqual(len(empty), 2, empty)

    def test_pool_and_interface_names_resolved(self):
        dash = json.loads((ROOT / "grafana" / "dashboards-clickhouse" / "orbymon-cgnat.json").read_text())
        p = next(p for p in dash["panels"] if "Pool publico na ORIGEM" in p["title"])
        res = json.loads(str(self.s.query(expand(p["targets"][0]["rawSql"]) +
                                          " SETTINGS join_use_nulls=1 FORMAT JSON")))
        row = res["data"][0]
        self.assertEqual(row["Pool"], "NAT-POOL-08")
        self.assertEqual(row["Entrada Huawei"], "Eth-Trunk1")


if __name__ == "__main__":
    unittest.main()
