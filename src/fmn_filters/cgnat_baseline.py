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
    optional = {"inside_private_cidrs", "cgnat_pool_metadata"}
    if not isinstance(raw, dict) or not expected.issubset(raw) or set(raw) - expected - optional:
        raise ValueError("Configuracao CGNAT com campos faltantes ou desconhecidos")
    raw.setdefault("inside_private_cidrs", [])
    raw.setdefault("cgnat_pool_metadata", {})
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
    internal = raw["inside_private_cidrs"]
    if not isinstance(internal, list):
        raise ValueError("inside_private_cidrs deve ser lista")
    shared_space = ip_network("100.64.0.0/10")
    private_nets = []
    for cidr in internal:
        net = ip_network(cidr, strict=True)
        if net.version != 4 or not net.subnet_of(shared_space):
            raise ValueError("inside_private_cidrs exige subfaixas do CGNAT 100.64.0.0/10")
        if any(net.overlaps(old) for old in private_nets):
            raise ValueError("inside_private_cidrs sobrepostos")
        private_nets.append(net)
    metadata = raw["cgnat_pool_metadata"]
    if not isinstance(metadata, dict) or set(metadata) - set(raw["cgnat_pools"]):
        raise ValueError("cgnat_pool_metadata contem pool ausente da lista")
    for cidr, entry in metadata.items():
        if not isinstance(entry, dict) or set(entry) != {"name", "max_users_per_ip"}:
            raise ValueError("metadata de pool invalida")
        if not isinstance(entry["name"], str) or not entry["name"].strip() or len(entry["name"]) > 64:
            raise ValueError("name de pool invalido")
        cap = entry["max_users_per_ip"]
        if type(cap) is not int or not 1 <= cap <= 65535:
            raise ValueError("max_users_per_ip invalido")
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


def pool_for_ip(ip, cfg):
    """Identifica pool publico declarado. Nunca deduz cliente/assinante."""
    try:
        addr = ip_address(ip)
    except ValueError:
        return None
    for cidr in cfg["cgnat_pools"]:
        if addr in ip_network(cidr):
            item = cfg.get("cgnat_pool_metadata", {}).get(cidr, {})
            return {"cidr": cidr, "name": item.get("name", cidr),
                    "max_users_per_ip": item.get("max_users_per_ip")}
    return None


def pool_baseline(rows, cfg):
    """P95 do pool por minuto e pela face observada; sem unir ingress/egress."""
    groups = defaultdict(lambda: [0.0, 0.0, set()])
    for bucket, src, dst, proto, in_if, out_if, direction, packets, nbytes in rows:
        for side, public, remote in (("IP_NA_ORIGEM", src, dst),
                                     ("IP_NO_DESTINO", dst, src)):
            pool = pool_for_ip(public, cfg)
            if pool is None:
                continue
            key = (pool["cidr"], pool["name"], side, str(proto),
                   int(in_if), int(out_if), int(direction), bucket)
            sample = groups[key]
            sample[0] += float(packets)
            sample[1] += float(nbytes)
            sample[2].add(public)
    grouped = defaultdict(list)
    for (cidr, name, side, proto, iif, oif, direction, bucket), (packets, nbytes, ips) in groups.items():
        grouped[(cidr, name, side, proto, iif, oif, direction)].append(
            (packets / 60, nbytes * 8 / 60000000, len(ips)))
    result = []
    for (cidr, name, side, proto, iif, oif, direction), samples in grouped.items():
        caps = cfg.get("cgnat_pool_metadata", {}).get(cidr, {})
        result.append({
            "pool": name, "cidr": cidr, "observacao": side,
            "protocolo": proto, "ifIndex_entrada": iif, "ifIndex_saida": oif,
            "direcao_netflow": direction, "minutos_com_dados": len(samples),
            "baseline_confiavel": len(samples) >= cfg["min_samples"],
            "mbps_p95_observado": round(percentile([s[1] for s in samples], .95), 2),
            "mbps_pico_observado": round(max(s[1] for s in samples), 2),
            "pps_p95_observado": round(percentile([s[0] for s in samples], .95), 2),
            "pps_pico_observado": round(max(s[0] for s in samples), 2),
            "max_ips_publicos_observados_no_minuto": max(s[2] for s in samples),
            "limite_configurado_usuarios_por_ip": caps.get("max_users_per_ip"),
        })
    return sorted(result, key=lambda r: r["mbps_pico_observado"], reverse=True)


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
            "pool_cgnat": pool_for_ip(ip, cfg),
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
    pools=pool_baseline(data,cfg)
    capacity=[]
    for cidr in cfg["cgnat_pools"]:
        net=ip_network(cidr)
        item=cfg.get("cgnat_pool_metadata", {}).get(cidr,{})
        cap=item.get("max_users_per_ip")
        capacity.append({
            "pool": item.get("name",cidr), "cidr":cidr,
            "enderecos_cidr": net.num_addresses,
            "max_users_per_ip_configurado":cap,
            "capacidade_teorica_atribuicoes":net.num_addresses * cap if cap is not None else None,
        })
    return {
        "source":"huawei","inicio_utc":begin.isoformat(),
        "fim_exclusivo_utc":end.isoformat(),"registros_consultados":len(data),
        "grupos_observados":len(results),"subfaixas_cgnat_declaradas":len(cfg["cgnat_pools"]),
        "rede_interna_cgnat_declarada":cfg["inside_private_cidrs"],
        "pools_cgnat":capacity,
        "baseline_por_pool":pools[:limit],
        "aviso":"Max-users-per-ip e apenas limite configurado, nao usuarios ativos. IP publico nao identifica assinante; roles src/dst nao determinam lado do NAT.",
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
