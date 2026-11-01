"""Sincroniza orby_net_prefixes (usada pelos dashboards) com os blocos da configuracao.

kinds: protected (blocos IPv4 publicos), pool (pools CGNAT, com nome), private (rede pre-NAT), infra.
Uso: python -m fmn_filters.net_prefixes --config /etc/orbymon/bidir.json   (credenciais ORBYMON_DB_*)
"""
from __future__ import annotations

import argparse
from ipaddress import ip_network
import sys


def rows(cfg, profile):
    meta = profile.get("cgnat_pool_metadata", {})
    groups = [("protected", c, "") for c in profile["protected_cidrs"]]
    groups += [("pool", c, meta.get(c, {}).get("name", c)) for c in profile["cgnat_pools"]]
    groups += [("private", c, "") for c in profile.get("inside_private_cidrs", [])]
    groups += [("infra", c, "") for c in cfg.get("extra_infrastructure_cidrs", [])]
    out = []
    for kind, cidr, name in groups:
        net = ip_network(cidr, strict=False)
        if net.version == 4:          # INET_ATON nos dashboards: somente IPv4
            out.append((kind, str(net), name[:64], int(net.network_address), int(net.broadcast_address)))
    return out


def sync(db, cfg, profile):
    data = rows(cfg, profile)
    cur = db.cursor()
    cur.execute("DELETE FROM orby_net_prefixes")
    if data:
        cur.executemany("INSERT INTO orby_net_prefixes (kind,cidr,name,v_start,v_end) VALUES (%s,%s,%s,%s,%s)", data)
    db.commit()
    return len(data)


def main(argv=None):
    ap = argparse.ArgumentParser(description="OrbyMon: blocos do provedor para os dashboards")
    ap.add_argument("--config", default="/etc/orbymon/bidir.json")
    args = ap.parse_args(argv)
    try:
        from .bidir_config import load_profile, read_config
        from .mysql_sink import connection_from_env
        cfg = read_config(args.config)
        db = connection_from_env()
        try:
            print("orby_net_prefixes: %d bloco(s)" % sync(db, cfg, load_profile(cfg)))
        finally:
            db.close()
        return 0
    except Exception as exc:
        print("FALHA: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
