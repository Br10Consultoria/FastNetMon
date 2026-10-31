"""Diagnostico read-only de fronteiras RFC5424 dentro dos blocos A10.

Nao imprime conteudo bruto, IPs nem portas de assinantes.
Os blocos gravados pelo rsyslog sao evidencia parcial, nao captura TCP.
"""
from __future__ import annotations
import argparse
from collections import Counter, deque
import json
from pathlib import Path
import re
import sys
from .a10_syslog_audit import HEADER
from .a10_syslog_inspect import LOG, tail_bytes

OCTET_PREFIX = re.compile(r"(?<![0-9])([0-9]{1,8}) $")

def classify_preceding(raw: str, start: int) -> str:
    if start == 0:
        return "inicio_do_bloco"
    prefix = raw[max(0,start-14):start]
    if OCTET_PREFIX.search(prefix):
        return "prefixo_comprimento_candidato"
    prev = raw[start-1]
    return {
        "]": "colado_apos_fechamento_colchete",
        "\n": "delimitador_LF_visivel",
        "\r": "delimitador_CR_visivel",
        "\x00": "delimitador_NUL_visivel",
        " ": "espaco_antes_cabecalho"
    }.get(prev,"sem_delimitador_visivel_ou_outro")

def probe(path=LOG, *, last=200, max_bytes=64000000, max_line_bytes=262144):
    if not 1<=last<=10000 or not 4096<=max_bytes<=100000000:
        raise ValueError("limites de leitura invalidos")
    if not 65536<=max_line_bytes<=1048576:
        raise ValueError("limite max_line_bytes invalido")
    if not path.is_file():
        return {"status":"sem_mensagens"}
    lines=deque(tail_bytes(path,max_bytes,max_line_bytes=max_line_bytes),maxlen=last)
    stats=Counter()
    boundaries=Counter()
    lengths=[]
    for line in lines:
        if line is None:
            stats["linhas_descartadas_por_tamanho"]+=1
            continue
        try:
            item=json.loads(line)
            raw=item["raw"]
            if not isinstance(raw,str):
                raise ValueError("raw nao textual")
        except (json.JSONDecodeError,KeyError,ValueError,TypeError):
            stats["linhas_invalidas"]+=1
            continue
        stats["linhas_validas"]+=1
        lengths.append(len(raw.encode("utf-8",errors="replace")))
        headers=list(HEADER.finditer(raw))
        stats["cabecalhos_rfc5424"]+=len(headers)
        if not headers:
            stats["linhas_sem_cabecalho"]+=1
            continue
        if headers[0].start()==0:
            stats["primeiro_cabecalho_no_inicio"]+=1
        else:
            stats["fragmentos_antes_do_primeiro_cabecalho"]+=1
        if len(headers)>1:
            stats["linhas_com_multiplos_cabecalhos"]+=1
        for h in headers[1:]:
            boundaries[classify_preceding(raw,h.start())]+=1
        if not raw.rstrip().endswith("]"):
            stats["blocos_sem_terminacao_colchete"]+=1
    count=sum(boundaries.values())
    most=boundaries.most_common(1)
    return {
        "status":"ok",
        "linhas_consideradas":len(lines),
        "linhas_validas":stats["linhas_validas"],
        "linhas_invalidas":stats["linhas_invalidas"],
        "linhas_descartadas_por_tamanho":stats["linhas_descartadas_por_tamanho"],
        "rawmsg_bytes_min":min(lengths) if lengths else None,
        "rawmsg_bytes_max":max(lengths) if lengths else None,
        "rawmsg_exatamente_8096_ou_65536":sum(n in (8096,65536) for n in lengths),
        "cabecalhos_rfc5424":stats["cabecalhos_rfc5424"],
        "fronteiras_internas_analisadas":count,
        "tipos_de_fronteira":dict(boundaries),
        "tipo_predominante":most[0][0] if most else None,
        "primeiro_cabecalho_no_inicio":stats["primeiro_cabecalho_no_inicio"],
        "fragmentos_antes_do_primeiro_cabecalho":stats["fragmentos_antes_do_primeiro_cabecalho"],
        "blocos_sem_terminacao_colchete":stats["blocos_sem_terminacao_colchete"],
        "limite_correlacao_liberado":False,
        "observacao":"Somente blocos salvos pelo rsyslog. Resultado nao prova framing original TCP nem homologa eventos NAT."
    }

def main(argv=None):
    ap=argparse.ArgumentParser(description="A10: inspecionar fronteiras sem revelar dados NAT")
    ap.add_argument("--file",type=Path,default=LOG)
    ap.add_argument("--last",type=int,default=200)
    ap.add_argument("--max-bytes",type=int,default=64000000)
    args=ap.parse_args(argv)
    try:
        print(json.dumps(probe(args.file,last=args.last,max_bytes=args.max_bytes),
                         indent=2,ensure_ascii=False))
    except (OSError,ValueError) as exc:
        print("Erro de framing A10: "+str(exc),file=sys.stderr)
        return 1
    return 0

if __name__=="__main__":
    raise SystemExit(main())
