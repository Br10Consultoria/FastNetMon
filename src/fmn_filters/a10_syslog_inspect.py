"""Preview A10 raw syslog: classify markers, count candidate maps, redact IPs.

Does not create subscriber correlations or persist mappings in the database.
"""
from __future__ import annotations
import argparse
from collections import Counter, deque
import ipaddress
import json
from pathlib import Path
import re
import sys

LOG = Path("/var/log/orbymon/a10/a10-current.ndjson")
IP = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
KINDS = (
    ("port_allocation",re.compile(r"LSN:PortAllocation",re.I)),
    ("port_freed",re.compile(r"LSN:PortFreed",re.I)),
    ("session_created",re.compile(r"SessionCreated",re.I)),
    ("session_deleted",re.compile(r"SessionDeleted",re.I)),
    ("port_batch",re.compile(r"Port[- ]?Batch|PortBlock",re.I)),
)
MAPPING = re.compile(
    r"LSN:Port(?:Allocation|Freed):(TCP|UDP)\s+\["
    r"((?:\d{1,3}\.){3}\d{1,3})\s+(\d{1,5})\s+"
    r"((?:\d{1,3}\.){3}\d{1,3})\s+(\d{1,5})\s+-\s+-\]")
INSIDE = ipaddress.ip_network("100.64.64.0/19")
POOLS = tuple(map(ipaddress.ip_network, (
    "45.238.170.64/26", "45.238.170.128/26",
    "45.238.171.64/26", "45.238.171.128/26")))


def classify(text):
    return next((name for name,pattern in KINDS if pattern.search(text)), "unrecognized")


def candidate_mapping(text):
    """Only a sample published A10 single-port format. Not a verified log."""
    m=MAPPING.search(text)
    if not m:
        return None
    proto, inside, inside_port, public, public_port=m.groups()
    try:
        inside=ipaddress.ip_address(inside)
        public=ipaddress.ip_address(public)
        inside_port=int(inside_port)
        public_port=int(public_port)
    except ValueError:
        return None
    if not (inside in INSIDE and any(public in pool for pool in POOLS)
            and 1<=inside_port<=65535 and 1<=public_port<=65535):
        return None
    return {"protocol":proto.lower(),"inside_ip":str(inside),
            "inside_port":inside_port,"public_ip":str(public),
            "public_port":public_port,"status":"unverified_candidate"}


def tail_bytes(path, max_bytes):
    with path.open("rb") as stream:
        stream.seek(0,2)
        size=stream.tell()
        if size>max_bytes:
            stream.seek(size-max_bytes)
            stream.readline()
        else:
            stream.seek(0)
        for line in stream:
            yield None if len(line)>65536 else line.decode("utf-8",errors="replace")


def inspect(path=LOG, last=200, max_bytes=8000000, examples=3):
    if not (1<=last<=10000 and 4096<=max_bytes<=100000000 and 0<=examples<=10):
        raise ValueError("limites de inspecao invalidos")
    if not path.exists():
        return {"status":"sem_mensagens","arquivo":str(path),"categorias":{}}
    records=deque(tail_bytes(path,max_bytes),maxlen=last)
    categories=Counter()
    source_ips=Counter()
    raw_examples=[]
    malformed=0
    candidates=0
    for line in records:
        try:
            if line is None:
                raise ValueError("linha muito grande")
            item=json.loads(line)
            raw=item["raw"]
            source=item["source_ip"]
            ipaddress.IPv4Address(source)
            if not isinstance(raw,str):
                raise ValueError("raw nao textual")
        except (ValueError,TypeError,KeyError,json.JSONDecodeError):
            malformed+=1
            continue
        source_ips[source]+=1
        categories[classify(raw)]+=1
        candidates+=int(candidate_mapping(raw) is not None)
        if len(raw_examples)<examples:
            raw_examples.append(IP.sub("[IP]",raw)[:240])
    return {"status":"ok","linhas_consideradas":len(records),
            "tipos_identificados":dict(categories),"origens_recebidas":dict(source_ips),
            "candidatos_mapeamento_formato_publicado":candidates,
            "linhas_invalidas":malformed,"exemplos_com_ips_ocultos":raw_examples,
            "observacao":"Candidatos nao sao mapeamentos homologados, nem associacoes PPPoE."}


def main(argv=None):
    ap=argparse.ArgumentParser(description="OrbyMon inspecao inicial syslog A10")
    ap.add_argument("--file",type=Path,default=LOG)
    ap.add_argument("--last",type=int,default=200)
    ap.add_argument("--samples",type=int,default=3)
    args=ap.parse_args(argv)
    try:
        print(json.dumps(inspect(args.file,last=args.last,examples=args.samples),
                         ensure_ascii=False,indent=2))
    except (OSError,ValueError) as exc:
        print("Falha A10 inspect: " + str(exc),file=sys.stderr)
        return 1
    return 0


if __name__=="__main__":
    raise SystemExit(main())
