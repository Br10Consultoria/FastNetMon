"""ClickHouse (opcional): fluxos por minuto com retencao longa, para a tela de Ataques e a investigacao.

O MariaDB continua com cadastro, eventos, alarmes e o detalhado de 2 dias; o ClickHouse guarda as mesmas linhas do
rollup (orby_flow_minute) por 30 dias ou mais, em formato colunar: consultas de dias inteiros por IP em segundos e
pouca memoria. Fala com o servidor pela interface HTTP (127.0.0.1:8123) sem dependencia extra.

Ligado somente se ORBYMON_CH_URL estiver definido (arquivo /etc/orbymon/clickhouse.env, gerado pelo
scripts/setup-clickhouse.sh e lido pelo systemd como dado). Falha do ClickHouse nunca para o rollup: o lote vai para
um spool em disco e e reenviado depois, com o mesmo token (o ClickHouse descarta a repeticao).

  python -m fmn_filters.clickhouse --init --ttl-days 30     (cria/ajusta o banco; usuario administrador)
  python -m fmn_filters.clickhouse --status                 (linhas, periodo e tamanho)
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

DATABASE = "orbyflow"
TABLE = "flow_minute"
COLUMNS = ("source", "bucket", "direction", "scope", "pool", "local_ip", "subscriber_ip", "remote_ip", "protocol",
           "local_port", "remote_port", "input_if", "output_if", "packets", "bytes", "syn_packets",
           "zero_port_packets", "flows")
PAIRS_TABLE = "orby_ip_pairs_minute"
PAIRS_COLUMNS = ("source", "bucket_utc", "src_ip", "dst_ip", "protocol", "dst_port", "input_if", "output_if",
                 "netflow_direction", "src_prefix", "dst_prefix", "src_asn", "dst_asn", "src_asn_name", "dst_asn_name",
                 "src_country", "dst_country", "src_latitude", "src_longitude", "dst_latitude", "dst_longitude",
                 "total_packets", "total_bytes", "flow_records")
# tabelas pequenas do MariaDB copiadas para os dashboards (mesmos nomes: o SQL dos paineis muda pouco)
DIMENSIONS = {
    "orby_interface_names": ("SELECT source,if_index,if_name FROM orby_interface_names", ("source", "if_index", "if_name"),
                             "source LowCardinality(String), if_index UInt64, if_name String", "(source, if_index)"),
    "orby_country_names": ("SELECT code,name FROM orby_country_names", ("code", "name"),
                           "code String, name String", "code"),
    "orby_net_prefixes": ("SELECT kind,cidr,name,v_start,v_end FROM orby_net_prefixes",
                          ("kind", "cidr", "name", "v_start", "v_end"),
                          "kind LowCardinality(String), cidr String, name String, v_start UInt64, v_end UInt64",
                          "(kind, v_start)"),
    "orby_asn_group_members": ("SELECT asn,name FROM orby_asn_group_members", ("asn", "name"),
                               "asn UInt64, name String", "asn"),
}
SPOOL_DIR = "/var/lib/orbymon/clickhouse-spool"
SPOOL_MAX_BYTES = 2 * 1024 ** 3
NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")


def schema(ttl_days=30, database=DATABASE):
    if not 1 <= int(ttl_days) <= 3650:
        raise ValueError("ttl_days entre 1 e 3650")
    if not NAME.match(database):
        raise ValueError("nome de banco invalido")
    t = "%s.%s" % (database, TABLE)
    return [
        "CREATE DATABASE IF NOT EXISTS %s" % database,
        """CREATE TABLE IF NOT EXISTS %s (
 source LowCardinality(String),
 bucket DateTime('UTC') CODEC(DoubleDelta, ZSTD(1)),
 direction LowCardinality(String),
 scope LowCardinality(String),
 pool LowCardinality(String),
 local_ip String CODEC(ZSTD(1)),
 subscriber_ip String CODEC(ZSTD(1)),
 remote_ip String CODEC(ZSTD(1)),
 protocol LowCardinality(String),
 local_port UInt16,
 remote_port UInt16,
 input_if UInt32,
 output_if UInt32,
 packets Float64 CODEC(ZSTD(1)),
 bytes Float64 CODEC(ZSTD(1)),
 syn_packets Float64 CODEC(ZSTD(1)),
 zero_port_packets Float64 CODEC(ZSTD(1)),
 flows UInt64 CODEC(ZSTD(1)),
 INDEX ix_local local_ip TYPE bloom_filter(0.01) GRANULARITY 2,
 INDEX ix_subscriber subscriber_ip TYPE bloom_filter(0.01) GRANULARITY 2,
 INDEX ix_remote remote_ip TYPE bloom_filter(0.01) GRANULARITY 2,
 INDEX ix_ports (local_port, remote_port) TYPE minmax GRANULARITY 4
) ENGINE = MergeTree
PARTITION BY toYYYYMMDD(bucket)
ORDER BY (source, direction, bucket, scope, protocol)
TTL bucket + INTERVAL %d DAY DELETE
SETTINGS index_granularity = 8192, non_replicated_deduplication_window = 20000, ttl_only_drop_parts = 1""" % (t, ttl_days),
        "ALTER TABLE %s MODIFY TTL bucket + INTERVAL %d DAY DELETE" % (t, ttl_days),
        """CREATE TABLE IF NOT EXISTS %s.%s (
 source LowCardinality(String),
 bucket_utc DateTime('UTC') CODEC(DoubleDelta, ZSTD(1)),
 src_ip String CODEC(ZSTD(1)),
 dst_ip String CODEC(ZSTD(1)),
 protocol LowCardinality(String),
 dst_port UInt16,
 input_if UInt32,
 output_if UInt32,
 netflow_direction Int16,
 src_prefix LowCardinality(String),
 dst_prefix LowCardinality(String),
 src_asn UInt64,
 dst_asn UInt64,
 src_asn_name LowCardinality(String),
 dst_asn_name LowCardinality(String),
 src_country LowCardinality(String),
 dst_country LowCardinality(String),
 src_latitude Nullable(Float64),
 src_longitude Nullable(Float64),
 dst_latitude Nullable(Float64),
 dst_longitude Nullable(Float64),
 total_packets Float64 CODEC(ZSTD(1)),
 total_bytes Float64 CODEC(ZSTD(1)),
 flow_records UInt64 CODEC(ZSTD(1)),
 INDEX ix_src src_ip TYPE bloom_filter(0.01) GRANULARITY 2,
 INDEX ix_dst dst_ip TYPE bloom_filter(0.01) GRANULARITY 2
) ENGINE = MergeTree
PARTITION BY toYYYYMMDD(bucket_utc)
ORDER BY (source, bucket_utc, protocol)
TTL bucket_utc + INTERVAL %d DAY DELETE
SETTINGS index_granularity = 8192, non_replicated_deduplication_window = 20000, ttl_only_drop_parts = 1"""
        % (database, PAIRS_TABLE, ttl_days),
        "ALTER TABLE %s.%s MODIFY TTL bucket_utc + INTERVAL %d DAY DELETE" % (database, PAIRS_TABLE, ttl_days),
        "CREATE TABLE IF NOT EXISTS %s.orby_sync_state (name String, value String, updated_at DateTime('UTC')) "
        "ENGINE = ReplacingMergeTree(updated_at) ORDER BY name" % database,
    ] + ["CREATE TABLE IF NOT EXISTS %s.%s (%s) ENGINE = MergeTree ORDER BY %s" % (database, name, cols, key)
         for name, (_, _, cols, key) in DIMENSIONS.items()]


class ClickHouseError(RuntimeError):
    pass


def _tsv(value):
    if value is None:
        return "\\N"
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(value, float):
        return repr(value)
    s = str(value)
    return s.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n")


def encode_rows(rows):
    return "".join("\t".join(_tsv(v) for v in row) + "\n" for row in rows).encode("utf-8")


class Client:
    """Cliente HTTP minimo. Parametros vao como {nome:Tipo} + param_nome (o servidor trata o valor; sem injecao)."""

    def __init__(self, url, user, password, database=DATABASE, timeout=30, opener=None, transport=None):
        self.url = url.rstrip("/")
        self.user, self.password, self.database = user, password, database
        self.timeout = timeout
        self.opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}))   # sempre local
        self.transport = transport        # testes: fn(sql, params, settings, data) -> bytes

    @classmethod
    def from_env(cls, env=None, timeout=30):
        env = os.environ if env is None else env
        url = env.get("ORBYMON_CH_URL", "").strip()
        if not url:
            return None
        if not url.startswith(("http://127.0.0.1", "http://localhost", "http://[::1]", "https://")):
            raise ClickHouseError("ORBYMON_CH_URL deve ser local (http://127.0.0.1:8123) ou https")
        return cls(url, env.get("ORBYMON_CH_USER", "default"), env.get("ORBYMON_CH_PASSWORD", ""),
                   env.get("ORBYMON_CH_DATABASE", DATABASE), timeout=timeout)

    def _send(self, sql, params=None, settings=None, data=None):
        params = {k: (v if isinstance(v, str) else _tsv(v)) for k, v in (params or {}).items()}
        if self.transport:
            return self.transport(sql, params, settings or {}, data)
        q = {"database": self.database} if self.database else {}
        for k, v in (settings or {}).items():
            q[k] = str(v)
        for k, v in params.items():
            q["param_" + k] = v
        if data is None:
            url, body = self.url + "/?" + urllib.parse.urlencode(q), sql.encode("utf-8")
        else:
            q["query"] = sql
            url, body = self.url + "/?" + urllib.parse.urlencode(q), data
        req = urllib.request.Request(url, data=body, method="POST",
                                     headers={"X-ClickHouse-User": self.user, "X-ClickHouse-Key": self.password,
                                              "Content-Type": "text/plain; charset=utf-8"})
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            msg = exc.read().decode("utf-8", "replace").strip()
            raise ClickHouseError("ClickHouse %d: %s" % (exc.code, msg[:300])) from None
        except (urllib.error.URLError, OSError) as exc:
            raise ClickHouseError("ClickHouse inacessivel: %s" % exc) from None

    def query(self, sql, params=None, settings=None):
        """SELECT -> lista de dicts."""
        st = {"output_format_json_quote_64bit_integers": 0}
        st.update(settings or {})
        raw = self._send(sql.rstrip().rstrip(";") + " FORMAT JSON", params, st)
        try:
            return json.loads(raw.decode("utf-8") or "{}").get("data", [])
        except ValueError:
            raise ClickHouseError("resposta inesperada do ClickHouse") from None

    def execute(self, sql, params=None, settings=None):
        self._send(sql, params, settings)

    def insert(self, table, columns, rows, token=None):
        if not rows:
            return 0
        settings = {"insert_deduplication_token": token} if token else {}
        sql = "INSERT INTO %s (%s) FORMAT TabSeparated" % (table, ",".join(columns))
        self._send(sql, None, settings, encode_rows(rows))
        return len(rows)


class Sink:
    """Grava as linhas de cada arquivo do rollup; em falha guarda em spool e reenvia na proxima execucao."""

    def __init__(self, client, spool_dir=SPOOL_DIR, log=None, max_bytes=SPOOL_MAX_BYTES):
        self.client = client
        self.spool = Path(spool_dir)
        self.log = log or (lambda m: print(m, file=sys.stderr, flush=True))
        self.max_bytes = max_bytes
        self.table = "%s.%s" % (client.database, TABLE)

    @classmethod
    def from_env(cls, env=None, **kw):
        try:
            client = Client.from_env(env, timeout=60)
        except ClickHouseError as exc:
            print("AVISO ClickHouse desligado: %s" % exc, file=sys.stderr, flush=True)
            return None
        return cls(client, **kw) if client else None

    @staticmethod
    def token(source, name, size, mtime_ns):
        return "%s:%s:%d:%d" % (source, name, size, mtime_ns)

    def write(self, token, rows, table=None, columns=COLUMNS):
        table = table or self.table
        try:
            self.client.insert(table, columns, rows, token)
            return True
        except Exception as exc:
            self._to_spool(token, rows, table, columns)
            self.log("AVISO ClickHouse: %s; lote guardado no spool" % str(exc)[:200])
            return False

    def write_pairs(self, token, rows):
        """Pares de IP por minuto (pipeline ip-huawei) para os dashboards Huawei/CGNAT/Visao geral."""
        return self.write("pairs:" + token, rows, "%s.%s" % (self.client.database, PAIRS_TABLE), PAIRS_COLUMNS)

    def _to_spool(self, token, rows, table=None, columns=COLUMNS):
        try:
            self.spool.mkdir(parents=True, exist_ok=True)
            name = re.sub(r"[^A-Za-z0-9_.-]+", "_", token)[:200] + ".tsv.gz"
            tmp = self.spool / (".tmp-" + name)
            head = "#%s\t%s\t%s\n" % (token, table or self.table, ",".join(columns))
            with gzip.open(tmp, "wb") as fh:
                fh.write(head.encode("utf-8") + encode_rows(rows))
            tmp.replace(self.spool / name)
            self._trim()
        except OSError as exc:
            self.log("ERRO spool ClickHouse: %s (lote perdido no ClickHouse; MariaDB intacto)" % exc)

    def _trim(self):
        files = sorted(self.spool.glob("*.tsv.gz"), key=lambda p: p.stat().st_mtime)
        total = sum(p.stat().st_size for p in files)
        while files and total > self.max_bytes:
            old = files.pop(0)
            total -= old.stat().st_size
            old.unlink()
            self.log("AVISO spool ClickHouse cheio: descartado %s" % old.name)

    def flush_spool(self, max_files=30):
        """Reenvia lotes guardados (mais antigos primeiro). Para no primeiro erro (servidor ainda fora)."""
        if not self.spool.is_dir():
            return 0
        sent = 0
        for path in sorted(self.spool.glob("*.tsv.gz"), key=lambda p: p.stat().st_mtime)[:max_files]:
            try:
                with gzip.open(path, "rb") as fh:
                    head = fh.readline().decode("utf-8").strip()
                    data = fh.read()
                parts = head[1:].split("\t") if head.startswith("#") else [""]
                token = parts[0] or None
                table, cols = (parts[1], parts[2]) if len(parts) == 3 else (self.table, ",".join(COLUMNS))
                if not re.match(r"^[A-Za-z_][\w]*\.[A-Za-z_]\w*$", table) or not re.match(r"^[\w,]+$", cols):
                    raise ValueError("cabecalho invalido")
                sql = "INSERT INTO %s (%s) FORMAT TabSeparated" % (table, cols)
                self.client._send(sql, None, {"insert_deduplication_token": token} if token else {}, data)
            except ClickHouseError as exc:
                self.log("AVISO ClickHouse ainda indisponivel: %s" % str(exc)[:200])
                break
            except (OSError, EOFError, ValueError) as exc:
                self.log("AVISO spool ClickHouse ilegivel, descartado %s: %s" % (path.name, exc))
            path.unlink(missing_ok=True)
            sent += 1
        return sent

    def pending(self):
        return len(list(self.spool.glob("*.tsv.gz"))) if self.spool.is_dir() else 0


def sync_dimensions(client, cur, log=None):
    """Copia as tabelas pequenas do MariaDB (interfaces, paises, blocos) quando mudam. Retorna as copiadas."""
    import hashlib
    done = []
    state = {r["name"]: r["value"] for r in client.query(
        "SELECT name, argMax(value, updated_at) AS value FROM %s.orby_sync_state GROUP BY name" % client.database)}
    for name, (sql, cols, _, _) in DIMENSIONS.items():
        try:
            cur.execute(sql)
            rows = [tuple("" if v is None else v for v in r) for r in cur.fetchall()]
        except Exception as exc:                     # tabela ainda nao criada no MariaDB
            if log:
                log("AVISO %s: %s" % (name, str(exc)[:120]))
            continue
        digest = hashlib.sha256(encode_rows(sorted(rows))).hexdigest()
        if state.get(name) == digest:
            continue
        table = "%s.%s" % (client.database, name)
        client.execute("TRUNCATE TABLE %s" % table)
        client.insert(table, cols, rows)
        client.insert("%s.orby_sync_state" % client.database, ("name", "value", "updated_at"),
                      [(name, digest, datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0))])
        done.append(name)
    return done


def status(client):
    rows = client.query("SELECT count() AS linhas, min(bucket) AS desde, max(bucket) AS ate FROM %s.%s"
                        % (client.database, TABLE))
    out = dict(rows[0]) if rows else {}
    try:
        pr = client.query("SELECT count() AS linhas, min(bucket_utc) AS desde, max(bucket_utc) AS ate FROM %s.%s"
                          % (client.database, PAIRS_TABLE))
        out["pares_ip"] = pr[0] if pr else {}
    except ClickHouseError:
        pass
    try:
        size = client.query("SELECT sum(bytes_on_disk) AS disco, sum(data_uncompressed_bytes) AS bruto "
                            "FROM system.parts WHERE active AND database={db:String}", {"db": client.database})
        out.update(size[0] if size else {})
    except ClickHouseError:
        pass                                     # usuario sem leitura de system.*: so as linhas
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="OrbyFlow: banco ClickHouse de fluxos")
    ap.add_argument("--init", action="store_true", help="cria o banco/tabela e ajusta a retencao")
    ap.add_argument("--ttl-days", type=int, default=30)
    ap.add_argument("--status", action="store_true")
    a = ap.parse_args(argv)
    try:
        client = Client.from_env(timeout=120)
        if client is None:
            raise ClickHouseError("ORBYMON_CH_URL nao definido")
        if a.init:
            client.database = ""                 # o banco ainda pode nao existir (DDL usa nomes completos)
            for sql in schema(a.ttl_days):
                # mudar a retencao nao reescreve o que ja esta gravado (vale para as partes novas e na limpeza)
                client.execute(sql, settings={"materialize_ttl_after_modify": 0} if "MODIFY TTL" in sql else None)
            client.database = os.environ.get("ORBYMON_CH_DATABASE", DATABASE)
            print("ClickHouse pronto: %s.%s, retencao %d dia(s)" % (client.database, TABLE, a.ttl_days))
        if a.status or not a.init:
            print(json.dumps(status(client), ensure_ascii=False, default=str))
        return 0
    except (ClickHouseError, ValueError) as exc:
        print("FALHA ClickHouse: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
