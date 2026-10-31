"""A10: read-only check whether adjacent rsyslog chunks complete one RFC5424 event.

Only aggregated results are printed; never print subscriber IPs or ports.
This test cannot prove original TCP message boundaries or end-to-end delivery.
"""
from __future__ import annotations
import argparse
from collections import Counter, deque
import json
from pathlib import Path
import sys

from .a10_syslog_audit import HEADER, NAT
from .a10_syslog_inspect import LOG, candidate_mappings, tail_bytes


def bridge_status(before: str, after: str) -> str:
    """Classify a candidate event straddling two consecutive raw chunks."""
    left=list(HEADER.finditer(before))
    right=list(HEADER.finditer(after))
    if not left:
        return "ultimo_bloco_sem_cabecalho"
    if not right:
        return "proximo_bloco_sem_cabecalho"
    prefix=after[:right[0].start()]
    suffix=before[left[-1].start():]
    if not prefix:
        return "proximo_bloco_inicia_com_cabecalho"
    if suffix.rstrip().endswith("]"):
        return "ultimo_evento_ja_terminava_com_colchete"
    combined=suffix+prefix
    if len(list(HEADER.finditer(combined)))!=1:
        return "cabecalho_incompleto_ou_ambiguo"
    if not combined.rstrip().endswith("]"):
        return "sem_terminador_apos_juncao"
    markers=sum(len(rx.findall(combined)) for _,rx in NAT)
    if markers!=1 or combined.count("LSN:")!=1:
        return "sem_evento_nat_unico"
    if len(list(candidate_mappings(combined)))!=1:
        return "sem_mapeamento_nat_completo"
    return "candidato_nat_recuperado_na_juncao"


def probe(path=LOG, *, last=200, max_bytes=64000000):
    if not 2<=last<=10000 or not 4096<=max_bytes<=100000000:
        raise ValueError("limites invalidos")
    if not path.is_file():
        return {"status":"sem_mensagens"}
    lines=deque(tail_bytes(path,max_bytes,max_line_bytes=262144),maxlen=last)
    statuses=Counter()
    chunks=[]
    for line in lines:
        if line is None:
            statuses["linha_grande_descartada"]+=1
            chunks.append(None)
            continue
        try:
            rec=json.loads(line)
            if not isinstance(rec,dict) or not isinstance(rec.get("raw"),str):
                raise ValueError("raw invalido")
            source=rec.get("source_ip")
            if not isinstance(source,str):
                raise ValueError("source invalido")
        except (ValueError,TypeError,json.JSONDecodeError):
            statuses["linha_invalida"]+=1
            chunks.append(None)
            continue
        chunks.append((rec["raw"],source))
    examined=0
    for prev,nxt in zip(chunks,chunks[1:]):
        if prev is None or nxt is None:
            statuses["pares_sem_continuidade_por_linha_invalida"]+=1
            continue
        if prev[1]!=nxt[1]:
            statuses["pares_com_origem_diferente"]+=1
            continue
        examined+=1
        statuses[bridge_status(prev[0],nxt[0])]+=1
    return {
        "status":"ok",
        "blocos_considerados":len(chunks),
        "pares_adjacentes_analisados":examined,
        "candidatos_nat_recuperados_entre_blocos":
            statuses["candidato_nat_recuperado_na_juncao"],
        "classificacao_das_juncoes":dict(statuses),
        "correlacao_automatica_permitida":False,
        "aviso":"Juncoes plausiveis nao comprovam entrega integral, ordem TCP ou integridade historica; nenhuma traducao foi gravada."
    }


def main(argv=None):
    p=argparse.ArgumentParser(description="A10: verificar continuidade entre chunks 64k (read-only)")
    p.add_argument("--file",type=Path,default=LOG)
    p.add_argument("--last",type=int,default=200)
    p.add_argument("--max-bytes",type=int,default=64000000)
    a=p.parse_args(argv)
    try:
        print(json.dumps(probe(a.file,last=a.last,max_bytes=a.max_bytes),
                         indent=2,ensure_ascii=False))
        return 0
    except (OSError,ValueError) as exc:
        print("Falha A10 continuidade: "+str(exc),file=sys.stderr)
        return 1

if __name__=="__main__":
    raise SystemExit(main())
