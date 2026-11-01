"""Excecoes da deteccao: IPs/redes ou ASNs inteiros que nao devem contar (ou que tem limite proprio).

- lado remoto (internet), acao ignorar: trafego de/para esses IPs nao entra nas regras
  (ex.: QUIC/UDP 443 de Google/Meta/CDNs chegando aos clientes);
- lado local (nossa rede), acao ignorar: o IP local sai da avaliacao (ex.: DNS recursivo proprio);
- lado local, acao multiplicar: o IP tem limite x fator (servidor de cliente com trafego alto normal).

Cada excecao pode valer para um sentido (recebido/originado) e para uma regra so. ASNs viram a lista de
prefixos anunciados (RIPEstat), renovada uma vez por dia:
    python -m fmn_filters.exceptions --sync
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
import json
import sys
import urllib.request

KINDS = ("cidr", "asn")
SIDES = ("remote", "local")
DIRECTIONS = ("in", "out", "any")
ACTIONS = ("ignore", "multiply")
PRESETS = (("Google", 15169), ("Meta (Facebook, WhatsApp, Instagram)", 32934), ("Cloudflare", 13335),
           ("Akamai", 20940), ("Netflix", 2906), ("Amazon", 16509), ("Microsoft", 8075), ("Apple", 714))
RIPESTAT = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%d&sourceapp=orbymon"
MAX_PREFIXES = 50000
RESYNC = timedelta(hours=20)


class ExceptionError(ValueError):
    pass


def validate(kind, value, side, direction="any", rule_name="", action="ignore", factor=1.0, note="", days=None):
    """Normaliza uma excecao vinda do painel. days: validade em dias (None = sem prazo)."""
    if kind not in KINDS or side not in SIDES or direction not in DIRECTIONS or action not in ACTIONS:
        raise ExceptionError("tipo, lado, sentido ou ação inválidos")
    value = (value or "").strip()
    if kind == "cidr":
        try:
            net = ip_network(value, strict=False)
        except ValueError:
            raise ExceptionError("IP ou rede inválida: %s" % value[:60])
        if net.prefixlen < (8 if net.version == 4 else 19):
            raise ExceptionError("rede ampla demais (mínimo /8 em IPv4 e /19 em IPv6)")
        value = str(net)
    else:
        try:
            asn = int(value.upper().removeprefix("AS"))
        except ValueError:
            raise ExceptionError("ASN deve ser número (ex.: 15169 ou AS15169)")
        if not 1 <= asn <= 4294967295:
            raise ExceptionError("ASN fora da faixa")
        if side != "remote":
            raise ExceptionError("ASN só vale do lado remoto (internet)")
        value = str(asn)
    try:
        factor = float(factor or 1)
    except (TypeError, ValueError):
        raise ExceptionError("multiplicador deve ser número")
    if action == "multiply":
        if side != "local":
            raise ExceptionError("multiplicador vale só para IPs da nossa rede (lado local)")
        if not 1.5 <= factor <= 1000:
            raise ExceptionError("multiplicador entre 1,5 e 1000")
    else:
        factor = 1.0
    rule_name = (rule_name or "").strip()
    note = " ".join((note or "").split())
    if len(rule_name) > 100 or len(note) > 200:
        raise ExceptionError("regra ou observação longas demais")
    if days not in (None, ""):
        try:
            days = int(days)
        except (TypeError, ValueError):
            raise ExceptionError("validade em dias deve ser número")
        if not 1 <= days <= 365:
            raise ExceptionError("validade entre 1 e 365 dias")
    else:
        days = None
    return {"kind": kind, "value": value, "side": side, "direction": direction, "rule_name": rule_name,
            "action": action, "factor": factor, "note": note, "days": days}


def describe(e):
    what = ("AS%s" % e["value"]) if e["kind"] == "asn" else e["value"]
    side = {"remote": "remoto", "local": "local"}[e["side"]]
    act = "ignorar" if e["action"] == "ignore" else "limite x%g" % e["factor"]
    dirs = {"in": "recebido", "out": "originado", "any": "ambos"}[e["direction"]]
    return "%s (%s, %s, %s%s)" % (what, side, dirs, act, ", regra " + e["rule_name"] if e["rule_name"] else "")


# ------------------------------------------------------------------ busca rapida
def _merge(ranges):
    out = []
    for a, b in sorted(ranges):
        if out and a <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return [x[0] for x in out], [x[1] for x in out]


class Matcher:
    """Excecoes agrupadas por condicao (lado, sentido, regra, acao, fator), com faixas ordenadas por familia."""

    def __init__(self, entries=()):
        groups = {}
        for e in entries:
            key = (e["side"], e["direction"], e["rule_name"], e["action"], float(e["factor"]))
            g = groups.setdefault(key, {4: [], 6: []})
            for cidr in e["cidrs"]:
                try:
                    net = ip_network(cidr, strict=False)
                except ValueError:
                    continue
                g[net.version].append((int(net.network_address), int(net.broadcast_address)))
        self.groups = [(key, {v: _merge(r) for v, r in fam.items()}) for key, fam in groups.items()]
        self._cache = {}

    def __bool__(self):
        return bool(self.groups)

    def _hits(self, ip):
        """Indices dos grupos que contem o IP (com cache: os mesmos IPs se repetem muito)."""
        if not ip:
            return ()
        got = self._cache.get(ip)
        if got is None:
            try:
                a = ip_address(ip)
            except ValueError:
                got = ()
            else:
                n, out = int(a), []
                for i, (_, fams) in enumerate(self.groups):
                    starts, ends = fams[a.version]
                    j = bisect_right(starts, n) - 1
                    if j >= 0 and n <= ends[j]:
                        out.append(i)
                got = tuple(out)
            if len(self._cache) > 500000:
                self._cache.clear()
            self._cache[ip] = got
        return got

    def _applies(self, i, side, action, rule_name, direction):
        s, d, r, a, _ = self.groups[i][0]
        return s == side and a == action and d in ("any", direction) and r in ("", rule_name)

    def ignore_row(self, rule_name, direction, local_ips, remote_ip):
        if not self.groups:
            return False
        if any(self._applies(i, "remote", "ignore", rule_name, direction) for i in self._hits(remote_ip)):
            return True
        return any(self._applies(i, "local", "ignore", rule_name, direction)
                   for ip in local_ips for i in self._hits(ip))

    def multiplier(self, rule_name, direction, entity):
        best = 1.0
        for i in self._hits(entity):
            if self._applies(i, "local", "multiply", rule_name, direction):
                best = max(best, self.groups[i][0][4])
        return best


def load(cur, now=None):
    """Matcher com as excecoes vigentes. Sem as tabelas (etapa nao instalada), devolve um Matcher vazio."""
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    try:
        cur.execute("SELECT id,kind,value,side,direction,rule_name,action,factor FROM orby_exceptions "
                    "WHERE expires_at IS NULL OR expires_at>%s", (now,))
        rows = cur.fetchall()
        asn_ids = [r[0] for r in rows if r[1] == "asn"]
        prefixes = {}
        if asn_ids:
            cur.execute("SELECT exception_id,cidr FROM orby_exception_prefixes WHERE exception_id IN (%s)"
                        % ",".join(["%s"] * len(asn_ids)), tuple(asn_ids))
            for eid, cidr in cur.fetchall():
                prefixes.setdefault(eid, []).append(cidr)
    except Exception as exc:
        if "orby_exception" in str(exc):
            return Matcher()
        raise
    entries = [{"side": r[3], "direction": r[4], "rule_name": r[5], "action": r[6], "factor": r[7],
                "cidrs": prefixes.get(r[0], []) if r[1] == "asn" else [r[2]]} for r in rows]
    return Matcher(entries)


# ------------------------------------------------------------------ ASN -> prefixos
def fetch_asn(asn, opener=urllib.request.urlopen, timeout=30):
    req = urllib.request.Request(RIPESTAT % int(asn), headers={"User-Agent": "OrbyMon-exceptions/1.0"})
    with opener(req, timeout=timeout) as resp:
        data = json.loads(resp.read(32 * 1024 * 1024).decode("utf-8"))
    out = set()
    for item in (data.get("data") or {}).get("prefixes") or []:
        try:
            net = ip_network(item.get("prefix", ""), strict=False)
        except ValueError:
            continue
        if net.prefixlen >= (8 if net.version == 4 else 19):
            out.add(str(net))
    if not out:
        raise ExceptionError("AS%d sem prefixos anunciados no RIPEstat" % int(asn))
    if len(out) > MAX_PREFIXES:
        raise ExceptionError("AS%d anuncia %d prefixos (máximo %d)" % (int(asn), len(out), MAX_PREFIXES))
    return sorted(out)


def sync(db, opener=urllib.request.urlopen, now=None, only_id=None, force=False, log=print):
    """Atualiza os prefixos das excecoes por ASN. Mantem a lista anterior se a consulta falhar."""
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    cur = db.cursor()
    cur.execute("SELECT id,value,synced_at FROM orby_exceptions WHERE kind='asn'" +
                (" AND id=%s" % int(only_id) if only_id else ""))
    done = 0
    for eid, asn, synced in cur.fetchall():
        if not force and not only_id and synced and now - synced < RESYNC:
            continue
        try:
            cidrs = fetch_asn(int(asn), opener)
        except Exception as exc:
            msg = str(exc)[:250]
            cur.execute("UPDATE orby_exceptions SET sync_error=%s WHERE id=%s", (msg, eid))
            db.commit()
            log("AS%s: falha (%s); mantida a lista anterior" % (asn, msg))
            continue
        cur.execute("DELETE FROM orby_exception_prefixes WHERE exception_id=%s", (eid,))
        for i in range(0, len(cidrs), 1000):
            chunk = cidrs[i:i + 1000]
            cur.execute("INSERT INTO orby_exception_prefixes (exception_id,cidr) VALUES " +
                        ",".join(["(%s,%s)"] * len(chunk)), tuple(x for c in chunk for x in (eid, c)))
        cur.execute("UPDATE orby_exceptions SET prefixes=%s,synced_at=%s,sync_error='' WHERE id=%s",
                    (len(cidrs), now, eid))
        db.commit()
        done += 1
        log("AS%s: %d prefixos" % (asn, len(cidrs)))
    cur.execute("DELETE FROM orby_exception_prefixes WHERE exception_id NOT IN (SELECT id FROM orby_exceptions)")
    cur.execute("DELETE FROM orby_exceptions WHERE expires_at IS NOT NULL AND expires_at<%s - INTERVAL 30 DAY",
                (now,))
    db.commit()
    return done


def main(argv=None):
    ap = argparse.ArgumentParser(description="OrbyMon: excecoes da deteccao (prefixos de ASN)")
    ap.add_argument("--sync", action="store_true", help="atualiza os prefixos dos ASNs de excecao")
    ap.add_argument("--force", action="store_true", help="atualiza mesmo os sincronizados ha pouco")
    args = ap.parse_args(argv)
    from .mysql_sink import connection_from_env
    try:
        db = connection_from_env()
        try:
            n = sync(db, force=args.force) if args.sync else 0
            print("excecoes: %d ASN(s) atualizados" % n)
        finally:
            db.close()
        return 0
    except Exception as exc:
        print("FALHA excecoes: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
