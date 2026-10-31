"""Auditoria read-only do enquadramento dos eventos A10 CGNAT.

Nao registra NAT no MariaDB; nao imprime IP ou porta de assinante.
"""
from __future__ import annotations
import argparse
from collections import Counter, deque
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
import sys

from .a10_syslog_inspect import LOG, KINDS, candidate_mappings, tail_bytes

# Boundary is detectable even when A10 messages are concatenated in one rawmsg.
HEADER=re.compile(
    r"<(?P<priority>\d{1,3})>1[ ]+"
    r"(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))(?=\s)",re.I)
NAT=KINDS[:2]


def audit(path=LOG,*,last=1000,max_bytes=64000000,max_line_bytes=262144):
    if not (1<=last<=10000 and 4096<=max_bytes<=100000000
            and 65536<=max_line_bytes<=1048576):
        raise ValueError("limites invalidos")
    if not path.exists():
        return {"status":"sem_mensagens","arquivo":str(path)}
    lines=deque(tail_bytes(path,max_bytes,max_line_bytes=max_line_bytes),maxlen=last)
    stats=Counter()
    event_counts=Counter()
    first=None
    newest=None
    sizes=[]
    json_line_bytes=[]
    clock_deltas=[]
    for line in lines:
        if line is None:
            stats["linhas_descartadas_por_limite_de_leitura"]+=1
            stats["linhas_maiores_64KiB"]+=1
            continue
        line_size=len(line.encode("utf-8",errors="replace"))
        json_line_bytes.append(line_size)
        if line_size>65536:
            stats["linhas_maiores_64KiB"]+=1
        try:
            rec=json.loads(line)
            if not isinstance(rec,dict) or not isinstance(rec.get("raw"),str):
                raise ValueError("raw invalido")
            ipaddress.IPv4Address(rec["source_ip"])
        except (ValueError,TypeError,KeyError,json.JSONDecodeError):
            stats["linhas_invalidas"]+=1
            continue
        raw=rec["raw"]
        stats["linhas_validas"]+=1
        sizes.append(len(raw.encode("utf-8",errors="replace")))
        try:
            collector_time=datetime.fromisoformat(
                str(rec["received_at"]).replace("Z","+00:00"))
            if collector_time.tzinfo is None:
                collector_time=None
        except (KeyError,TypeError,ValueError):
            collector_time=None
        starts=list(HEADER.finditer(raw))
        stats["cabecalhos_rfc5424"]+=len(starts)
        stats["marcadores_nat"]+=sum(len(rx.findall(raw)) for _,rx in NAT)
        if len(starts)>1:
            stats["linhas_com_varios_cabecalhos"]+=1
        if not starts:
            stats["linhas_sem_cabecalho"]+=1
            continue
        if raw[:starts[0].start()].strip():
            stats["fragmentos_antes_do_cabecalho"]+=1
        for i,h in enumerate(starts):
            payload=raw[h.end():(starts[i+1].start() if i+1<len(starts) else len(raw))]
            markers=sum(len(rx.findall(payload)) for _,rx in NAT)
            if markers==0:
                stats["cabecalhos_sem_nat"]+=1
                continue
            if markers!=1:
                stats["cabecalhos_com_multiplos_nat"]+=1
                continue
            mappings=list(candidate_mappings(payload))
            if len(mappings)!=1:
                stats["eventos_sem_mapeamento_completo"]+=1
                continue
            if payload.count("LSN:")!=1:
                stats["corpos_ambiguos"]+=1
                continue
            try:
                ts=datetime.fromisoformat(h.group("time").replace("Z","+00:00"))
                if ts.tzinfo is None or not 0<=int(h.group("priority"))<=191:
                    raise ValueError("header")
            except ValueError:
                stats["data_header_invalida"]+=1
                continue
            if first is None or ts<first: first=ts
            if newest is None or ts>newest: newest=ts
            if collector_time is not None:
                clock_deltas.append(
                    (collector_time.astimezone(timezone.utc)
                     - ts.astimezone(timezone.utc)).total_seconds())
            event_counts[mappings[0]["event"]]+=1
    confirmed=sum(event_counts.values())
    total=stats["marcadores_nat"]
    sizes.sort()
    clock_deltas.sort()
    def nearest(values,pct):
        if not values: return None
        import math
        return values[max(0,math.ceil(len(values)*pct)-1)]
    return {
      "status":"ok","linhas_consideradas":len(lines),
      "linhas_validas":stats["linhas_validas"],
      "linhas_invalidas":stats["linhas_invalidas"],
      "linhas_maiores_64KiB":stats["linhas_maiores_64KiB"],
      "linhas_descartadas_por_limite_de_leitura":stats["linhas_descartadas_por_limite_de_leitura"],
      "limite_linha_ndjson_bytes":max_line_bytes,
      "janela_leitura_bytes":max_bytes,
      "linha_ndjson_bytes_max":max(json_line_bytes) if json_line_bytes else None,
      "marcadores_nat":total,
      "rawmsg_bytes_p05":nearest(sizes,.05),
      "rawmsg_bytes_p50":nearest(sizes,.50),
      "rawmsg_bytes_p95":nearest(sizes,.95),
      "rawmsg_bytes_max":sizes[-1] if sizes else None,
      "rawmsg_entre_8000_8192_bytes":sum(8000<=n<=8192 for n in sizes),
      "rawmsg_entre_64000_66000_bytes":sum(64000<=n<=66000 for n in sizes),
      "rawmsg_acima_8192_bytes":sum(n>8192 for n in sizes),
      "rawmsg_entre_4000_4096_bytes":sum(4000<=n<=4096 for n in sizes),
      "delta_coletor_menos_a10_segundos_p50":nearest(clock_deltas,.50),
      "delta_coletor_menos_a10_segundos_p95":nearest(clock_deltas,.95),
      "amostras_com_horarios_comparaveis":len(clock_deltas),
      "cabecalhos_rfc5424":stats["cabecalhos_rfc5424"],
      "linhas_com_varios_cabecalhos":stats["linhas_com_varios_cabecalhos"],
      "linhas_sem_cabecalho":stats["linhas_sem_cabecalho"],
      "fragmentos_antes_do_cabecalho":stats["fragmentos_antes_do_cabecalho"],
      "eventos_sem_mapeamento_completo":stats["eventos_sem_mapeamento_completo"],
      "corpos_ambiguos":stats["corpos_ambiguos"],
      "cabecalhos_com_multiplos_nat":stats["cabecalhos_com_multiplos_nat"],
      "eventos_com_timestamp_e_mapeamento_candidato":confirmed,
      "percentual_estrutural_reconhecido":round(100*confirmed/total,2) if total else 0,
      "candidatos_por_tipo":dict(event_counts),
      "primeiro_evento":first.isoformat() if first else None,
      "ultimo_evento":newest.isoformat() if newest else None,
      "correlacao_automatica_permitida":False,
      "aviso":"Integridade do stream nao homologada; sem assinantes ou gravacoes no banco."}


def main(argv=None):
    p=argparse.ArgumentParser(description="Diagnostico read-only de Syslog A10")
    p.add_argument("--file",type=Path,default=LOG)
    p.add_argument("--last",type=int,default=1000)
    p.add_argument("--max-bytes",type=int,default=64000000)
    p.add_argument("--max-line-bytes",type=int,default=262144)
    a=p.parse_args(argv)
    try:
        print(json.dumps(audit(a.file,last=a.last,max_bytes=a.max_bytes,
                               max_line_bytes=a.max_line_bytes),
                         indent=2,ensure_ascii=False))
    except (OSError,ValueError) as exc:
        print("Falha A10 auditoria: "+str(exc),file=sys.stderr)
        return 1
    return 0


if __name__=="__main__":
    raise SystemExit(main())
