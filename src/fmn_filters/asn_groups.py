"""Grupos de ASN/CDN ("favoritos"): junta ASNs e blocos IP sob um nome (Google, Meta, Netflix, cache da CDN...).

orby_asn_groups (editada no painel) -> orby_asn_group_members (asn -> grupo) e orby_net_prefixes kind='group'
(blocos IPv4 -> grupo). O bloco ganha do ASN: um cache do Google dentro da rede do transito aparece como Google.
Os dashboards leem essas tabelas (e as copias no ClickHouse).
Uso: python -m fmn_filters.asn_groups   (credenciais ORBYMON_DB_*)
"""
from __future__ import annotations

from ipaddress import ip_network
import re
import sys

MAX_MEMBERS = 2000
TOKEN = re.compile(r"[\s,;]+")


def parse_members(text):
    """'AS15169 36040, 8.8.8.0/24' -> ([15169, 36040], ['8.8.8.0/24']). ValueError no primeiro item invalido."""
    asns, cidrs = [], []
    for tok in TOKEN.split((text or "").strip()):
        if not tok:
            continue
        t = tok.upper()
        if t.startswith("AS"):
            t = t[2:]
        if t.isdigit():
            n = int(t)
            if not 1 <= n <= 4294967295 or n in (23456,) or 64512 <= n <= 65535 or 4200000000 <= n:
                raise ValueError("ASN inválido ou privado: %s" % tok)
            if n not in asns:
                asns.append(n)
            continue
        try:
            net = ip_network(tok, strict=False)
        except ValueError:
            raise ValueError("item inválido (use ASN ou bloco IP): %s" % tok[:60]) from None
        if (net.version == 4 and net.prefixlen < 8) or (net.version == 6 and net.prefixlen < 16):
            raise ValueError("bloco grande demais: %s" % tok)
        if str(net) not in cidrs:
            cidrs.append(str(net))
    if len(asns) + len(cidrs) > MAX_MEMBERS:
        raise ValueError("no máximo %d itens por grupo" % MAX_MEMBERS)
    return asns, cidrs


def build(groups):
    """[(nome, membros)] em ordem de prioridade -> (linhas asn, linhas de bloco, avisos)."""
    asn_rows, prefix_rows, notes, seen = [], [], [], {}
    for name, members in groups:
        try:
            asns, cidrs = parse_members(members)
        except ValueError as exc:
            notes.append("%s: %s" % (name, exc))
            continue
        for a in asns:
            if a in seen:
                notes.append("AS%d está em '%s' e '%s': vale o primeiro" % (a, seen[a], name))
                continue
            seen[a] = name
            asn_rows.append((a, name[:64]))
        for c in cidrs:
            net = ip_network(c)
            if net.version == 4:            # INET_ATON nos dashboards: blocos somente IPv4
                prefix_rows.append(("group", str(net), name[:64], int(net.network_address), int(net.broadcast_address)))
    return asn_rows, prefix_rows, notes


def sync(db):
    cur = db.cursor()
    cur.execute("SELECT name,members FROM orby_asn_groups ORDER BY sort,name")
    asn_rows, prefix_rows, notes = build([(r[0], r[1]) for r in cur.fetchall()])
    cur.execute("DELETE FROM orby_asn_group_members")
    if asn_rows:
        cur.executemany("INSERT INTO orby_asn_group_members (asn,name) VALUES (%s,%s)", asn_rows)
    cur.execute("DELETE FROM orby_net_prefixes WHERE kind='group'")
    if prefix_rows:
        cur.executemany("INSERT INTO orby_net_prefixes (kind,cidr,name,v_start,v_end) VALUES (%s,%s,%s,%s,%s)",
                        prefix_rows)
    db.commit()
    return len(asn_rows), len(prefix_rows), notes


def main(argv=None):
    try:
        from .mysql_sink import connection_from_env
        db = connection_from_env()
        try:
            a, p, notes = sync(db)
        finally:
            db.close()
        print("grupos de ASN: %d ASN(s), %d bloco(s)" % (a, p))
        for n in notes:
            print("  aviso: " + n)
        return 0
    except Exception as exc:
        print("FALHA grupos de ASN: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
