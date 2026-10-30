"""CGNAT-aware baseline report for the existing Huawei NetFlow IP rollups.

READ ONLY: Never guesses subscriber identity, NAT mappings, interface direction,
or which public ranges are shared. Does not change detector thresholds.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
import json
import math
from pathlib import Path
import sys

from .mysql_sink import connection_from_env

DEFAULT_CONFIG = "/etc/orbymon/cgnat-profiles.json"
ROLE_NAMES = ("cgnat_pools", "dedicated_public_cidrs", "infrastructure_public_cidrs")


def validate_config(raw):
    expected = {"protected_cidrs", "cgnat_pools", "dedicated_public_cidrs",
                "infrastructure_public_cidrs", "lookback_hours", "settle_minutes",
                "min_samples", "max_rows"}
    if not isinstance(raw, dict) or set(raw) != expected:
        raise ValueError("Configuracao CGNAT com campos faltantes ou desconhecidos")
    for field in ("protected_cidrs",) + ROLE_NAMES:
        if not isinstance(raw[field], list):
            raise ValueError(field + " deve ser lista CIDR")
        for cidr in raw[field]:
            if not isinstance(cidr, str):
                raise ValueError("CIDR deve ser texto")
            net = ip_network(cidr, strict=True)
            if net.version != 4 or not net.is_global:
                raise ValueError("Apenas prefixos publicos IPv4; CGNAT 100.64/10 nao e pool publico")
    if not raw["protected_cidrs"]:
        raise ValueError("protected_cidrs obrigatorio")
    protected = [ip_network(s) for s in raw["protected_cidrs"]]
    if any(a.overlaps(b) for n, a in enumerate(protected) for b in protected[n+1:]):
        raise ValueError("protected_cidrs nao pode ter sobreposicao")
    tagged = [(role, ip_network(s)) for role in ROLE_NAMES for s in raw[role]]
    for role, net in tagged:
        if not any(net.subnet_of(p) for p in protected):
            raise ValueError(role + " nao pertence a protected_cidrs: " + str(net))
    for i, (role1, n1) in enumerate(tagged):
        for role2, n2 in tagged[i+1:]:
            if n1.overlaps(n2):
                raise ValueError("subfaixas classificadas se sobrepoem: "
                                 + role1 + " e " + role2)
    for key, lo, hi in (("lookback_hours",1,72), ("settle_minutes",2,20),
                        ("min_samples",2,60), ("max_rows",1000,200000)):
        if type(raw[key]) is not int or not lo <= raw[key] <= hi:
            raise ValueError(key + " fora dos limites")
    return raw


def classify(ip, cfg):
    try:
        addr = ip_address(ip)
    except ValueError:
        return None
    if not any(addr in ip_network(n) for n in cfg["protected_cidrs"]):
        return None
    for role in ROLE_NAMES:
        if any(addr in ip_network(n) for n in cfg[role]):
            return {
                "cgnat_pools":"cgnat_compartilhado",
                "dedicated_public_cidrs":"ip_dedicado",
                "infrastructure_public_cidrs":"infraestrutura",
            }[role]
    return "uso_nao_classificado"


def selection_query(cfg, begin, end):
    ranges = [(int(ip_network(s).network_address),
               int(ip_network(s).broadcast_address)) for s in cfg["protected_cidrs"]]
    parts = []
    vals = ["huawei", begin, end]
    for col in ("src_ip", "dst_ip"):
        for lo, hi in ranges:
            parts.append("(INET_ATON(" + col + ") BETWEEN %s AND %s)")
            vals.extend((lo, hi))
    sql = """SELECT bucket_utc, src_ip, dst_ip, protocol,
input_if, output_if, netflow_direction, total_packets, total_bytes
FROM orby_ip_pairs_minute
WHERE source=%s AND bucket_utc >= %s AND bucket_utc < %s
AND (""" + " OR ".join(parts) + """)
ORDER BY bucket_utc LIMIT %s"""
    vals.append(cfg["max_rows"] + 1)
    return sql, tuple(vals)


def percentile(values, pct):
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[max(0, math.ceil(pct * len(ordered)) - 1)]


def summarize_rows(rows, cfg):
    """Per public IP, observation side, protocol, ifIndex and raw direction.

    A public IP appearing both as src and dst is counted as two observations,
    never aggregated into an 'overall traffic' number.
    """
    samples = defaultdict(lambda: [0., 0., set()])
    for bucket, src, dst, proto, in_if, out_if, direction, packets, nbytes in rows:
        for side, ip, peer in (("IP_NA_ORIGEM",src,dst),
                               ("IP_NO_DESTINO",dst,src)):
            role = classify(ip, cfg)
            if role is None:
                continue
            if not isinstance(bucket, datetime):
                raise ValueError("bucket_utc nao e datetime")
            key = (ip,role,side,str(proto),int(in_if),int(out_if),int(direction),bucket)
            sample = samples[key]
            sample[0] += float(packets)
            sample[1] += float(nbytes)
            sample[2].add(peer)
    grouped = defaultdict(list)
    for (ip,role,side,proto,in_if,out_if,direction,bucket), data in samples.items():
        group=(ip,role,side,proto,in_if,out_if,direction)
        grouped[group].append((data[0]/60, data[1]*8/60000000, len(data[2])))
    result = []
    for (ip,role,side,proto,in_if,out_if,direction), points in grouped.items():
        mbps=[v[1] for v in points]
        pps=[v[0] for v in points]
        result.append({
            "ip_publico":ip,
            "perfil":role,
            "observacao":side,
            "protocolo":proto,
            "ifIndex_entrada":in_if,
            "ifIndex_saida":out_if,
            "direcao_netflow":direction,
            "minutos_com_dados":len(points),
            "baseline_confiavel":len(points)>=cfg["min_samples"],
            "mbps_p95_observado":round(percentile(mbps,.95),2),
            "mbps_pico_observado":round(max(mbps),2),
            "pps_p95_observado":round(percentile(pps,.95),2),
            "pps_pico_observado":round(max(pps),2),
            "maior_numero_ips_remotos_observados":max(v[2] for v in points),
        })
    return sorted(result,key=lambda x:x["mbps_pico_observado"],reverse=True)


def run(cfg, *, limit=20, now=None):
    cfg=validate_config(cfg)
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now precisa de timezone")
    end=now.astimezone(timezone.utc).replace(tzinfo=None,second=0,microsecond=0)
    end-=timedelta(minutes=cfg["settle_minutes"])
    begin=end-timedelta(hours=cfg["lookback_hours"])
    sql, params=selection_query(cfg,begin,end)
    db=connection_from_env()
    try:
        with db.cursor() as cur:
            cur.execute(sql,params)
            data=cur.fetchall()
    finally:
        db.close()
    if len(data)>cfg["max_rows"]:
        raise RuntimeError("Janela excede max_rows. Reduza lookback_hours; relatorio parcial recusado.")
    results=summarize_rows(data,cfg)
    return {
        "source":"huawei","inicio_utc":begin.isoformat(),
        "fim_exclusivo_utc":end.isoformat(),"registros_consultados":len(data),
        "grupos_observados":len(results),"subfaixas_cgnat_declaradas":len(cfg["cgnat_pools"]),
        "aviso":"IP publico CGNAT nao identifica assinante; direction e ifIndex sao campos brutos.",
        "ranking":results[:limit],
    }


def main(argv=None):
    ap=argparse.ArgumentParser(description="OrbyMon CGNAT: diagnostico read-only")
    ap.add_argument("--config",default=DEFAULT_CONFIG)
    ap.add_argument("--top",type=int,default=20)
    ap.add_argument("--validate",action="store_true")
    args=ap.parse_args(argv)
    try:
        cfg=validate_config(json.loads(Path(args.config).read_text(encoding="utf-8")))
        if not 1<=args.top<=100:
            raise ValueError("--top deve estar entre 1 e 100")
        if args.validate:
            print("CGNAT OK: %d blocos protegidos, %d faixas compartilhadas declaradas" %
                  (len(cfg["protected_cidrs"]),len(cfg["cgnat_pools"])))
            return 0
        print(json.dumps(run(cfg,limit=args.top),ensure_ascii=False,indent=2,default=str))
        return 0
    except Exception as exc:
        print("ERRO CGNAT: " + str(exc),file=sys.stderr)
        return 1


if __name__=="__main__":
    raise SystemExit(main())
