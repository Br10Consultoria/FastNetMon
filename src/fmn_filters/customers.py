"""Clientes: cadastro com prefixos dedicados e identificacao do assinante (login por IP e horario).

Fonte das sessoes (qualquer ERP), em /etc/orbymon/radius.env (editavel no painel, lido como dados):
  http          API HTTP/JSON do ERP (recomendado): URL/corpo com {ip}, {quando}, {data}, {quando_iso}, {epoch},
                {desde}, {desde_data}, {desde_iso} (= 31 dias antes, para pegar sessoes longas);
                cabecalho de autenticacao; caminhos dos campos de login, inicio, fim e MAC na resposta
  radacct_mysql radacct do FreeRADIUS em MySQL/MariaDB (username, framedipaddress, acctstarttime, ...)
  radacct_pg    radacct do FreeRADIUS em PostgreSQL
  sql_mysql/pg  SELECT proprio com {ip} e {quando}, colunas: login, inicio, fim[, mac[, nas]]
Sempre somente leitura; falha da fonte nunca bloqueia um aviso.
Quem usa: avisos do Telegram (detector, alarmes por filtro), pagina Investigar e pagina Clientes.
"""
from __future__ import annotations

from datetime import timezone
from ipaddress import ip_address, ip_network
import re
from zoneinfo import ZoneInfo

RADIUS_KEYS = ("RADIUS_MODE", "RADIUS_TZ",
               "RADIUS_HTTP_URL", "RADIUS_HTTP_METHOD", "RADIUS_HTTP_BODY_B64", "RADIUS_HTTP_HEADERS_B64",
               "RADIUS_HTTP_PUBLIC_HEADERS_B64", "RADIUS_HTTP_LIST", "RADIUS_HTTP_LOGIN", "RADIUS_HTTP_START", "RADIUS_HTTP_STOP", "RADIUS_HTTP_MAC",
               "RADIUS_HTTP_NAME", "RADIUS_HTTP_CONTRACT", "RADIUS_HTTP_INSECURE",
               "RADIUS_DB_HOST", "RADIUS_DB_PORT", "RADIUS_DB_NAME", "RADIUS_DB_USER", "RADIUS_DB_PASSWORD",
               "RADIUS_TABLE", "RADIUS_SQL_B64")
NAME_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.:_-]{1,253}$")


class CustomerError(ValueError):
    pass


# ------------------------------------------------------------------ cadastro
def parse_prefixes(text):
    out = []
    for token in re.split(r"[\s,;]+", text or ""):
        if not token:
            continue
        try:
            net = ip_network(token, strict=False)
        except ValueError:
            raise CustomerError("prefixo inválido: %s" % token[:60])
        if net.prefixlen < (16 if net.version == 4 else 32):
            raise CustomerError("prefixo amplo demais para um cliente: %s" % net)
        out.append(str(net))
    if len(out) > 200:
        raise CustomerError("no máximo 200 prefixos por cliente")
    return sorted(set(out), key=lambda n: (ip_network(n).version, ip_network(n)))


def validate_customer(name, code="", prefixes="", contact="", note=""):
    name = " ".join((name or "").split())
    if not 2 <= len(name) <= 120:
        raise CustomerError("nome entre 2 e 120 caracteres")
    code, contact, note = (" ".join((x or "").split()) for x in (code, contact, note))
    if len(code) > 40 or len(contact) > 200 or len(note) > 300:
        raise CustomerError("código, contato ou observação longos demais")
    nets = parse_prefixes(prefixes)
    if not nets:
        raise CustomerError("informe ao menos um IP ou prefixo do cliente")
    return {"name": name, "code": code, "prefixes": nets, "contact": contact, "note": note}


class CustomerIndex:
    """Busca o cliente de um IP (prefixo mais especifico vence)."""

    def __init__(self, rows=()):
        self.items = {4: [], 6: []}
        for cid, name, code, cidr in rows:
            try:
                net = ip_network(cidr, strict=False)
            except ValueError:
                continue
            self.items[net.version].append((int(net.network_address), int(net.broadcast_address), net.prefixlen,
                                            {"id": cid, "name": name, "code": code, "cidr": str(net)}))
        for v in self.items:
            self.items[v].sort(key=lambda x: (x[0], -x[2]))

    def __len__(self):
        return len(self.items[4]) + len(self.items[6])

    def lookup(self, ip):
        """Poucas centenas de prefixos e poucas consultas por execucao: busca linear basta."""
        try:
            a = ip_address(ip)
        except ValueError:
            return None
        n, best = int(a), None
        for s, e, plen, info in self.items[a.version]:
            if s > n:
                break
            if n <= e and (best is None or plen > best[0]):
                best = (plen, info)
        return best[1] if best else None


def load_index(cur):
    try:
        cur.execute("SELECT c.id,c.name,c.code,p.cidr FROM orby_customers c JOIN orby_customer_prefixes p "
                    "ON p.customer_id=c.id")
        return CustomerIndex(cur.fetchall())
    except Exception as exc:
        if "orby_customer" in str(exc):
            return CustomerIndex()
        raise


# ------------------------------------------------------------------ fonte de sessoes (login por IP e horario)
class RadiusError(RuntimeError):
    pass


MODES = {
    "http": "API HTTP/JSON do ERP (recomendado)",
    "radacct_mysql": "radacct do FreeRADIUS em MySQL/MariaDB",
    "radacct_pg": "radacct do FreeRADIUS em PostgreSQL",
    "sql_mysql": "consulta SQL própria (MySQL/MariaDB)",
    "sql_pg": "consulta SQL própria (PostgreSQL)",
}
SECRET_KEYS = ("RADIUS_DB_PASSWORD", "RADIUS_HTTP_HEADERS_B64")
PLACEHOLDERS = ("ip", "quando_iso", "quando", "data", "epoch", "desde_iso", "desde_data", "desde")
SESSION_LOOKBACK_DAYS = 31

def b64e(text):
    import base64
    return base64.b64encode((text or "").encode("utf-8")).decode("ascii")


def b64d(text):
    import base64
    try:
        return base64.b64decode((text or "").encode("ascii"), validate=True).decode("utf-8")
    except Exception:
        return ""


# Modelos prontos: preenchem o formulario; o operador informa o endereco do ERP e o token.
#   {base} = endereco do ERP (https://erp.exemplo.com.br), sem barra no fim
PRESETS = {
    "orbycore": {
        "nome": "OrbyCore",
        "ajuda": "Crie um ServiceToken no OrbyCore com a permissão network.view (e, se quiser, ACL só para o IP do "
                 "OrbyFlow). Cabeçalho: Authorization: ServiceToken orby_...",
        "header_hint": "Authorization: ServiceToken orby_...",
        "values": {"RADIUS_MODE": "http", "RADIUS_HTTP_METHOD": "GET",
                   "RADIUS_HTTP_URL": "{base}/api/v1/network/radius/accounting/?assigned_ip={ip}&from={desde_iso}"
                                      "&to={quando_iso}&limit=20",
                   "RADIUS_HTTP_LIST": "", "RADIUS_HTTP_LOGIN": "username", "RADIUS_HTTP_START": "started_at",
                   "RADIUS_HTTP_STOP": "ended_at", "RADIUS_HTTP_MAC": "mac_address",
                   "RADIUS_HTTP_NAME": "customer_name", "RADIUS_HTTP_CONTRACT": "contract_number"},
    },
    "ixc": {
        "nome": "IXC Provedor",
        "ajuda": "No IXC, gere o token de API do usuário (Configurações > Usuários > token) com permissão de leitura "
                 "nas conexões Radius. Cabeçalho: Authorization: Basic <base64 de ID_USUARIO:TOKEN>. Confira com "
                 "Testar: os nomes da tabela e dos campos podem variar com a versão do IXC.",
        "header_hint": "Authorization: Basic <base64 de ID_USUARIO:TOKEN>",
        "values": {"RADIUS_MODE": "http", "RADIUS_HTTP_METHOD": "POST",
                   "RADIUS_HTTP_URL": "{base}/webservice/v1/radacct",
                   "RADIUS_HTTP_PUBLIC_HEADERS_B64": b64e("ixcsoft: listar"),
                   "RADIUS_HTTP_BODY_B64": b64e(
                       '{"qtype": "radacct.framedipaddress", "query": "{ip}", "oper": "=", "page": "1", "rp": "20", '
                       '"sortname": "radacct.acctstarttime", "sortorder": "desc", '
                       '"grid_param": "[{\\"TB\\": \\"radacct.acctstarttime\\", \\"OP\\": \\"<=\\", '
                       '\\"P\\": \\"{quando}\\"}]"}'),
                   "RADIUS_HTTP_LIST": "registros", "RADIUS_HTTP_LOGIN": "username",
                   "RADIUS_HTTP_START": "acctstarttime", "RADIUS_HTTP_STOP": "acctstoptime",
                   "RADIUS_HTTP_MAC": "callingstationid"},
    },
}


def apply_preset(name, base):
    p = PRESETS.get(name)
    if not p:
        raise CustomerError("modelo desconhecido")
    base = (base or "").strip().rstrip("/")
    if not re.match(r"^https?://[A-Za-z0-9.:\[\]_-]+(/[^\s'\\?#]*)?$", base):
        raise CustomerError("informe o endereço do ERP (ex.: https://erp.exemplo.com.br)")
    out = dict(p["values"])
    out.setdefault("RADIUS_HTTP_PUBLIC_HEADERS_B64", "")
    out.setdefault("RADIUS_HTTP_BODY_B64", "")
    out["RADIUS_HTTP_URL"] = out["RADIUS_HTTP_URL"].replace("{base}", base)
    return out
TABLE_RE = re.compile(r"^[A-Za-z0-9_]{1,64}(\.[A-Za-z0-9_]{1,64})?$")
FIELD_RE = re.compile(r"^[A-Za-z0-9_.\-]{0,120}$")
HEADER_RE = re.compile(r"^[A-Za-z0-9-]{1,64}:[^\r\n]{0,2000}$")


def _mode(env):
    mode = (env.get("RADIUS_MODE") or "").strip()
    if not mode and (env.get("RADIUS_DB_HOST") or "").strip():
        mode = "radacct_mysql"                         # configuracao anterior (so radacct MySQL)
    return mode


def validate_radius(env):
    """Normaliza a configuracao gravada pelo painel. Segredos vazios = manter (tratado no painel)."""
    out = {k: (env.get(k) or "").strip() for k in RADIUS_KEYS}
    out["RADIUS_MODE"] = _mode(out)
    if not out["RADIUS_MODE"]:
        return dict.fromkeys(RADIUS_KEYS, "")              # desativado
    if out["RADIUS_MODE"] not in MODES:
        raise CustomerError("modo de identificação inválido")
    out["RADIUS_TZ"] = out["RADIUS_TZ"] or "America/Sao_Paulo"
    try:
        ZoneInfo(out["RADIUS_TZ"])
    except Exception:
        raise CustomerError("fuso inválido")
    if out["RADIUS_MODE"] == "http":
        url = out["RADIUS_HTTP_URL"]
        if not re.match(r"^https?://[^\s'\\]{3,1000}$", url) or "{ip}" not in url + b64d(out["RADIUS_HTTP_BODY_B64"]):
            raise CustomerError("URL da API: http(s)://... com {ip} na URL ou no corpo")
        out["RADIUS_HTTP_METHOD"] = (out["RADIUS_HTTP_METHOD"] or "GET").upper()
        if out["RADIUS_HTTP_METHOD"] not in ("GET", "POST"):
            raise CustomerError("método GET ou POST")
        for line in (b64d(out["RADIUS_HTTP_HEADERS_B64"]) + "\n" + b64d(out["RADIUS_HTTP_PUBLIC_HEADERS_B64"])).splitlines():
            if line.strip() and not HEADER_RE.match(line.strip()):
                raise CustomerError("cabeçalho inválido (use Nome: valor, um por linha)")
        body = b64d(out["RADIUS_HTTP_BODY_B64"])
        if len(body) > 4000:
            raise CustomerError("corpo longo demais")
        out["RADIUS_HTTP_LOGIN"] = out["RADIUS_HTTP_LOGIN"] or "login"
        for key in ("RADIUS_HTTP_LIST", "RADIUS_HTTP_LOGIN", "RADIUS_HTTP_START", "RADIUS_HTTP_STOP",
                    "RADIUS_HTTP_MAC", "RADIUS_HTTP_NAME", "RADIUS_HTTP_CONTRACT"):
            if not FIELD_RE.match(out[key]):
                raise CustomerError("caminho de campo inválido: %s" % out[key][:60])
        out["RADIUS_HTTP_INSECURE"] = "1" if out["RADIUS_HTTP_INSECURE"] in ("1", "on", "true") else ""
        for key in ("RADIUS_DB_HOST", "RADIUS_DB_PORT", "RADIUS_DB_NAME", "RADIUS_DB_USER", "RADIUS_DB_PASSWORD",
                    "RADIUS_TABLE", "RADIUS_SQL_B64"):
            out[key] = ""
        return out
    if not HOST_RE.match(out["RADIUS_DB_HOST"]):
        raise CustomerError("servidor do banco inválido")
    pg = out["RADIUS_MODE"].endswith("_pg")
    port = out["RADIUS_DB_PORT"] or ("5432" if pg else "3306")
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise CustomerError("porta inválida")
    out["RADIUS_DB_PORT"] = port
    for key in ("RADIUS_DB_NAME", "RADIUS_DB_USER"):
        if not NAME_RE.match(out[key]):
            raise CustomerError("%s: letras, números e _" % key.replace("RADIUS_DB_", "").lower())
    if out["RADIUS_MODE"].startswith("radacct"):
        out["RADIUS_TABLE"] = out["RADIUS_TABLE"] or "radacct"
        if not TABLE_RE.match(out["RADIUS_TABLE"]):
            raise CustomerError("tabela: letras, números e _ (pode ter esquema.tabela)")
        out["RADIUS_SQL_B64"] = ""
    else:
        sql = b64d(out["RADIUS_SQL_B64"]).strip().rstrip(";").strip()
        if not re.match(r"(?is)^(select|with)\b", sql) or ";" in sql or "{ip}" not in sql or len(sql) > 4000:
            raise CustomerError("SQL: um único SELECT com {ip} (e {quando}) e sem ';'")
        out["RADIUS_SQL_B64"] = b64e(sql)
        out["RADIUS_TABLE"] = ""
    for key in ("RADIUS_HTTP_URL", "RADIUS_HTTP_METHOD", "RADIUS_HTTP_BODY_B64", "RADIUS_HTTP_HEADERS_B64",
                "RADIUS_HTTP_PUBLIC_HEADERS_B64",
                "RADIUS_HTTP_LIST", "RADIUS_HTTP_LOGIN", "RADIUS_HTTP_START", "RADIUS_HTTP_STOP", "RADIUS_HTTP_MAC",
                "RADIUS_HTTP_NAME", "RADIUS_HTTP_CONTRACT", "RADIUS_HTTP_INSECURE"):
        out[key] = ""
    return out


def parse_when(value, tz):
    """Data/hora vinda do ERP -> UTC ingenuo. Aceita datetime, epoch, ISO (com ou sem fuso) e dd/mm/aaaa hh:mm."""
    from datetime import datetime as dt
    if value is None or value == "":
        return None
    if isinstance(value, dt):
        aware = value if value.tzinfo else value.replace(tzinfo=tz)
        return aware.astimezone(timezone.utc).replace(tzinfo=None)
    text = str(value).strip()
    if not text or text.startswith("0000-00-00"):
        return None
    if re.fullmatch(r"\d{9,13}(\.\d+)?", text):
        n = float(text)
        n = n / 1000 if n > 1e11 else n
        return dt.fromtimestamp(n, timezone.utc).replace(tzinfo=None)
    try:
        got = dt.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        got = None
        for fmt in ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y"):
            try:
                got = dt.strptime(text, fmt)
                break
            except ValueError:
                continue
        if got is None:
            return None
    return parse_when(got, tz)


def _path(obj, path):
    if not path:
        return obj
    for part in path.split("."):
        if isinstance(obj, list):
            if not part.isdigit() or int(part) >= len(obj):
                return None
            obj = obj[int(part)]
        elif isinstance(obj, dict):
            obj = obj.get(part)
        else:
            return None
    return obj


class Radius:
    """Sessoes por IP e horario, de uma fonte configuravel (API do ERP, radacct ou SQL propria)."""

    def __init__(self, env, connect=None, opener=None):
        self.env = {k: (env.get(k) or "").strip() for k in RADIUS_KEYS}
        self.mode = _mode(self.env)
        self.enabled = self.mode in MODES
        self._connect, self._opener = connect, opener
        self._db = None
        self._cache = {}
        self.failed = False
        self.last_raw = ""                             # resposta crua da ultima consulta HTTP (botao Testar)
        if self.enabled:
            self.cfg = validate_radius(dict(self.env, RADIUS_MODE=self.mode))
            self.tz = ZoneInfo(self.cfg["RADIUS_TZ"])

    # ---------- banco
    def _conn(self):
        if self._db is None:
            pg = self.mode.endswith("_pg")
            connect = self._connect
            try:
                if connect is None and pg:
                    try:
                        import pg8000.dbapi as pgdb
                    except ImportError:
                        raise RadiusError("driver PostgreSQL ausente: rode sudo bash scripts/setup-customers.sh")
                    connect = lambda **kw: pgdb.connect(host=kw["host"], port=kw["port"], user=kw["user"],
                                                        password=kw["password"], database=kw["database"], timeout=5)
                elif connect is None:
                    import pymysql
                    connect = lambda **kw: pymysql.connect(connect_timeout=3, read_timeout=5, charset="utf8mb4", **kw)
                self._db = connect(host=self.cfg["RADIUS_DB_HOST"], port=int(self.cfg["RADIUS_DB_PORT"]),
                                   user=self.cfg["RADIUS_DB_USER"], password=self.env["RADIUS_DB_PASSWORD"],
                                   database=self.cfg["RADIUS_DB_NAME"])
            except RadiusError:
                self.failed = True
                raise
            except Exception as exc:
                self.failed = True
                raise RadiusError("banco de sessões inacessível: %s" % type(exc).__name__)
        return self._db

    def _sql(self):
        if self.mode.startswith("radacct"):
            return ("SELECT username,acctstarttime,acctstoptime,callingstationid,nasipaddress FROM %s "
                    "WHERE framedipaddress=%%s AND acctstarttime<=%%s AND (acctstoptime IS NULL OR "
                    "acctstoptime>=%%s) ORDER BY acctstarttime DESC LIMIT 5" % self.cfg["RADIUS_TABLE"], ("ip", "q", "q"))
        sql = b64d(self.cfg["RADIUS_SQL_B64"]).replace("%", "%%")
        order = [m.group(1) for m in re.finditer(r"\{(ip|quando)\}", sql)]
        return re.sub(r"\{(ip|quando)\}", "%s", sql), tuple("ip" if o == "ip" else "q" for o in order)

    def _from_db(self, ip, local):
        sql, order = self._sql()
        db = self._conn()
        cur = db.cursor()
        try:
            if self.mode.endswith("_pg"):
                cur.execute("SET TRANSACTION READ ONLY")
            cur.execute(sql, tuple(ip if o == "ip" else local for o in order))
            rows = cur.fetchmany(5) if hasattr(cur, "fetchmany") else cur.fetchall()[:5]
        finally:
            try:
                db.rollback()                          # nunca grava nada
            except Exception:
                pass
        out = []
        for r in rows:
            r = list(r) + [None] * 5
            out.append({"login": str(r[0] or ""), "inicio": parse_when(r[1], self.tz), "fim": parse_when(r[2], self.tz),
                        "mac": str(r[3] or ""), "nas": str(r[4] or "")})
        return out

    # ---------- API HTTP
    def _from_http(self, ip, when_utc, local):
        import json
        import ssl
        import urllib.parse
        import urllib.request
        from datetime import timedelta
        since_utc = when_utc - timedelta(days=SESSION_LOOKBACK_DAYS)          # sessoes longas comecam antes
        since_local = local - timedelta(days=SESSION_LOOKBACK_DAYS)
        values = {"ip": ip, "quando": local.strftime("%Y-%m-%d %H:%M:%S"), "data": local.strftime("%Y-%m-%d"),
                  "quando_iso": when_utc.replace(tzinfo=timezone.utc).isoformat(),
                  "epoch": str(int(when_utc.replace(tzinfo=timezone.utc).timestamp())),
                  "desde": since_local.strftime("%Y-%m-%d %H:%M:%S"), "desde_data": since_local.strftime("%Y-%m-%d"),
                  "desde_iso": since_utc.replace(tzinfo=timezone.utc).isoformat()}
        fill = lambda text, enc: re.sub(r"\{(" + "|".join(PLACEHOLDERS) + r")\}", lambda m: enc(values[m.group(1)]), text)
        url = fill(self.cfg["RADIUS_HTTP_URL"], lambda v: urllib.parse.quote(v, safe=""))
        body = b64d(self.cfg["RADIUS_HTTP_BODY_B64"])
        data = fill(body, lambda v: json.dumps(v)[1:-1]).encode("utf-8") if body else None
        req = urllib.request.Request(url, data=data,                    # IXC aceita corpo ate em GET
                                     method=self.cfg["RADIUS_HTTP_METHOD"],
                                     headers={"User-Agent": "OrbyFlow/1.0", "Accept": "application/json"})
        if data is not None:
            req.add_header("Content-Type", "application/json")
        for line in (b64d(self.cfg["RADIUS_HTTP_PUBLIC_HEADERS_B64"]) + "\n" +
                     b64d(self.env["RADIUS_HTTP_HEADERS_B64"])).splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                req.add_header(k.strip(), v.strip())
        opener = self._opener
        if opener is None:
            ctx = ssl.create_default_context()
            if self.cfg["RADIUS_HTTP_INSECURE"]:
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            opener = lambda r, timeout: urllib.request.urlopen(r, timeout=timeout, context=ctx)
        with opener(req, timeout=8) as resp:
            raw = resp.read(4 * 1024 * 1024).decode("utf-8", "replace")
        self.last_raw = raw[:4000]
        try:
            doc = json.loads(raw)
        except ValueError:
            raise RadiusError("a API não respondeu JSON")
        items = _path(doc, self.cfg["RADIUS_HTTP_LIST"])
        items = items if isinstance(items, list) else ([items] if isinstance(items, dict) else [])
        out = []
        for it in items:
            login = _path(it, self.cfg["RADIUS_HTTP_LOGIN"])
            if login in (None, ""):
                continue
            start = parse_when(_path(it, self.cfg["RADIUS_HTTP_START"]), self.tz) if self.cfg["RADIUS_HTTP_START"] else None
            stop = parse_when(_path(it, self.cfg["RADIUS_HTTP_STOP"]), self.tz) if self.cfg["RADIUS_HTTP_STOP"] else None
            if start and start > when_utc or stop and stop < when_utc:
                continue                                # sessao fora do horario pedido
            opt = lambda key: str(_path(it, self.cfg[key]) or "") if self.cfg[key] else ""
            out.append({"login": str(login), "inicio": start, "fim": stop, "mac": opt("RADIUS_HTTP_MAC"), "nas": "",
                        "cliente": opt("RADIUS_HTTP_NAME"), "contrato": opt("RADIUS_HTTP_CONTRACT")})
        out.sort(key=lambda x: x["inicio"] or when_utc.replace(year=1), reverse=True)
        return out[:5]

    def sessions(self, ip, when_utc, limit=3):
        """Sessoes que tinham o IP no horario (UTC ingenuo). Mais recente primeiro; horarios devolvidos em UTC."""
        if not self.enabled or self.failed:
            return []
        key = (ip, when_utc.replace(second=0, microsecond=0))
        if key in self._cache:
            return self._cache[key][:limit]
        local = when_utc.replace(tzinfo=timezone.utc).astimezone(self.tz).replace(tzinfo=None)
        try:
            out = self._from_http(ip, when_utc, local) if self.mode == "http" else self._from_db(ip, local)
        except RadiusError:
            self.failed = True
            raise
        except Exception as exc:
            self.failed = True
            raise RadiusError("consulta de sessões falhou: %s" % (str(exc)[:160] or type(exc).__name__))
        self._cache[key] = out
        return out[:limit]

    def close(self):
        if self._db is not None:
            try:
                self._db.close()
            except Exception:
                pass
            self._db = None


class Identifier:
    """identify(ip, quando) -> texto curto ('login joao123 · cliente Padaria X') ou ''. Nunca levanta erro."""

    def __init__(self, radius=None, index=None):
        self.radius, self.index = radius, index

    def __call__(self, ip, when=None):
        parts = []
        if self.index is not None and ip:
            c = self.index.lookup(ip)
            if c:
                parts.append("cliente %s%s" % (c["name"], " (%s)" % c["code"] if c["code"] else ""))
        if self.radius is not None and self.radius.enabled and ip and when is not None:
            try:
                s = self.radius.sessions(ip, when, limit=1)
            except RadiusError:
                s = []
            if s:
                x = s[0]
                parts.append("login %s%s" % (x["login"], " · MAC %s" % x["mac"] if x["mac"] else ""))
                if x.get("cliente"):
                    parts.append("%s%s" % (x["cliente"], " (contrato %s)" % x["contrato"] if x.get("contrato") else ""))
        return " · ".join(parts)


def build_identifier(db=None, radius_env_path=None):
    """Identificador para os avisos: clientes do banco + RADIUS (se configurado)."""
    from pathlib import Path
    radius = index = None
    if radius_env_path:
        from .admin.config_store import read_env
        try:
            env = read_env(Path(radius_env_path))
        except OSError:
            env = {}
        try:
            radius = Radius(env)
        except CustomerError:
            radius = None
    if db is not None:
        try:
            index = load_index(db.cursor())
        except Exception:
            index = None
    if (radius is None or not radius.enabled) and not index:
        return None
    return Identifier(radius, index)
