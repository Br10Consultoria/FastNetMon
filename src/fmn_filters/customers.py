"""Clientes: cadastro de clientes com prefixos dedicados e consulta ao RADIUS (login PPPoE por IP e horario).

RADIUS: tabela de contabilidade padrao do FreeRADIUS (radacct) em MySQL/MariaDB, somente leitura. Usado por
IXC, MK-Auth, SGP e outros. Configuracao em /etc/orbymon/radius.env (editavel no painel, lido como dados):
    RADIUS_DB_HOST, RADIUS_DB_PORT, RADIUS_DB_NAME, RADIUS_DB_USER, RADIUS_DB_PASSWORD,
    RADIUS_TABLE (padrao radacct), RADIUS_TZ (fuso das datas gravadas no radacct; padrao America/Sao_Paulo)
Colunas usadas: username, framedipaddress, acctstarttime, acctstoptime, callingstationid, nasipaddress.

Quem usa: avisos do Telegram (detector, alarmes por filtro), pagina Investigar e pagina Clientes.
"""
from __future__ import annotations

from datetime import timezone
from ipaddress import ip_address, ip_network
import re
from zoneinfo import ZoneInfo

RADIUS_KEYS = ("RADIUS_DB_HOST", "RADIUS_DB_PORT", "RADIUS_DB_NAME", "RADIUS_DB_USER", "RADIUS_DB_PASSWORD",
               "RADIUS_TABLE", "RADIUS_TZ")
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


# ------------------------------------------------------------------ RADIUS
class RadiusError(RuntimeError):
    pass


def validate_radius(env):
    """Normaliza a configuracao (para gravar pelo painel). Senha vazia = manter a atual (tratado no painel)."""
    out = {k: (env.get(k) or "").strip() for k in RADIUS_KEYS}
    if not out["RADIUS_DB_HOST"]:
        return dict.fromkeys(RADIUS_KEYS, "")              # desativado
    if not HOST_RE.match(out["RADIUS_DB_HOST"]):
        raise CustomerError("servidor do RADIUS inválido")
    port = out["RADIUS_DB_PORT"] or "3306"
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise CustomerError("porta inválida")
    out["RADIUS_DB_PORT"] = port
    out["RADIUS_TABLE"] = out["RADIUS_TABLE"] or "radacct"
    for key in ("RADIUS_DB_NAME", "RADIUS_DB_USER", "RADIUS_TABLE"):
        if not NAME_RE.match(out[key]):
            raise CustomerError("%s: letras, números e _" % key.replace("RADIUS_", "").lower())
    out["RADIUS_TZ"] = out["RADIUS_TZ"] or "America/Sao_Paulo"
    try:
        ZoneInfo(out["RADIUS_TZ"])
    except Exception:
        raise CustomerError("fuso inválido")
    return out


class Radius:
    def __init__(self, env, connect=None):
        self.env = {k: (env.get(k) or "").strip() for k in RADIUS_KEYS}
        self.enabled = bool(self.env["RADIUS_DB_HOST"] and self.env["RADIUS_DB_USER"])
        self._connect = connect
        self._db = None
        self._cache = {}
        self.failed = False
        if self.enabled:
            v = validate_radius(self.env)
            self.table, self.tz = v["RADIUS_TABLE"], ZoneInfo(v["RADIUS_TZ"])

    def _conn(self):
        if self._db is None:
            connect = self._connect
            if connect is None:
                import pymysql
                connect = pymysql.connect
            try:
                self._db = connect(host=self.env["RADIUS_DB_HOST"], port=int(self.env["RADIUS_DB_PORT"] or 3306),
                                   user=self.env["RADIUS_DB_USER"], password=self.env["RADIUS_DB_PASSWORD"],
                                   database=self.env["RADIUS_DB_NAME"], connect_timeout=3, read_timeout=5,
                                   charset="utf8mb4")
            except Exception as exc:
                self.failed = True
                raise RadiusError("RADIUS inacessível: %s" % type(exc).__name__)
        return self._db

    def sessions(self, ip, when_utc, limit=3):
        """Sessoes que tinham o IP no horario (UTC ingenuo). Mais recente primeiro; horarios devolvidos em UTC."""
        if not self.enabled or self.failed:
            return []
        key = (ip, when_utc.replace(second=0, microsecond=0))
        if key in self._cache:
            return self._cache[key]
        local = when_utc.replace(tzinfo=timezone.utc).astimezone(self.tz).replace(tzinfo=None)
        try:
            cur = self._conn().cursor()
            cur.execute("SELECT username,acctstarttime,acctstoptime,callingstationid,nasipaddress FROM `%s` "
                        "WHERE framedipaddress=%%s AND acctstarttime<=%%s AND (acctstoptime IS NULL OR "
                        "acctstoptime>=%%s) ORDER BY acctstarttime DESC LIMIT %d" % (self.table, int(limit)),
                        (ip, local, local))
            rows = cur.fetchall()
        except RadiusError:
            raise
        except Exception as exc:
            self.failed = True
            raise RadiusError("consulta ao RADIUS falhou: %s" % str(exc)[:160])
        to_utc = lambda t: t.replace(tzinfo=self.tz).astimezone(timezone.utc).replace(tzinfo=None) if t else None
        out = [{"login": r[0], "inicio": to_utc(r[1]), "fim": to_utc(r[2]), "mac": r[3] or "", "nas": r[4] or ""}
               for r in rows]
        self._cache[key] = out
        return out

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
                parts.append("login %s%s" % (s[0]["login"], " · MAC %s" % s[0]["mac"] if s[0]["mac"] else ""))
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
