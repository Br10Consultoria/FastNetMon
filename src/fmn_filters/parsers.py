from __future__ import annotations
import json
import re
from typing import Iterator, TextIO
from .models import Event, timestamp, positive_number


def _first(obj: dict, *keys: str, default=None):
    for key in keys:
        if key in obj and obj[key] not in ('', None):
            return obj[key]
    return default


def _flags(raw: object) -> str:
    if raw is None:
        return ''
    if isinstance(raw, int):
        names = [(0x01, 'F'), (0x02, 'S'), (0x04, 'R'), (0x08, 'P'), (0x10, 'A'), (0x20, 'U'), (0x40, 'E'), (0x80, 'C')]
        return ''.join(letter for bit, letter in names if raw & bit)
    value = str(raw).upper()
    if re.fullmatch(r'0X[0-9A-F]+', value):
        return _flags(int(value, 16))
    return value.replace('.', '')


def parse_record(raw: dict, assume_utc: bool = False) -> Event | None:
    if not isinstance(raw, dict):
        raise ValueError('registro não é objeto JSON')
    if str(raw.get('type', '')).upper() == 'EVENT' and 'kind' not in raw:
        # nfdump also exports NAT and other non-flow events.
        return None
    kind = str(raw.get('kind', 'flow')).lower()
    src_ip = _first(raw, 'src_ip', 'src4_addr', 'src6_addr', 'srcip')
    dst_ip = _first(raw, 'dst_ip', 'dst4_addr', 'dst6_addr', 'dstip')
    start = timestamp(_first(raw, 'start', 'first', 'timestamp', 'time'), assume_utc)
    end = timestamp(_first(raw, 'end', 'last', 'timestamp', 'time', default=start), assume_utc)
    proto_raw = _first(raw, 'protocol', 'proto', default='tcp' if kind == 'http' else '')
    proto_aliases = {'6': 'tcp', '17': 'udp', '1': 'icmp', '58': 'icmpv6', '50': 'esp'}
    proto = proto_aliases.get(str(proto_raw).lower(), str(proto_raw).lower())
    if kind == 'http' and proto != 'tcp':
        raise ValueError('evento HTTP deve ser TCP')
    packets = positive_number(_first(raw, 'packets', 'in_packets', 'pkt', default=1 if kind == 'http' else 0), 'packets')
    total_bytes = positive_number(_first(raw, 'bytes', 'in_bytes', 'byt', default=0), 'bytes')
    return Event(
        kind=kind, start=start, end=end, src_ip=str(src_ip), dst_ip=str(dst_ip),
        src_port=int(_first(raw, 'src_port', 'srcport', default=0)),
        dst_port=int(_first(raw, 'dst_port', 'dstport', default=443 if kind == 'http' else 0)),
        protocol=proto, packets=packets, bytes=total_bytes,
        tcp_flags=_flags(_first(raw, 'tcp_flags', 'flags')),
        method=str(_first(raw, 'method', default='')).upper(),
        path=str(_first(raw, 'path', 'uri', default='')),
        status=int(_first(raw, 'status', default=0)),
        src_asn=int(_first(raw, 'src_asn', 'src_as', default=0)),
        dst_asn=int(_first(raw, 'dst_asn', 'dst_as', default=0)),
        src_asn_name=str(_first(raw, 'src_asn_name', default='')),
        dst_asn_name=str(_first(raw, 'dst_asn_name', default='')),
        src_country=str(_first(raw, 'src_country', default='')).upper(),
        dst_country=str(_first(raw, 'dst_country', default='')).upper(),
        src_latitude=float(raw['src_latitude']) if raw.get('src_latitude') is not None else None,
        src_longitude=float(raw['src_longitude']) if raw.get('src_longitude') is not None else None,
        dst_latitude=float(raw['dst_latitude']) if raw.get('dst_latitude') is not None else None,
        dst_longitude=float(raw['dst_longitude']) if raw.get('dst_longitude') is not None else None,
        input_if=int(_first(raw, 'input_if', 'in_if', 'input_snmp', default=0)),
        output_if=int(_first(raw, 'output_if', 'out_if', 'output_snmp', default=0)),
        ttl=int(_first(raw, 'ttl', default=-1)),
        icmp_type=int(_first(raw, 'icmp_type', default=-1)),
        icmp_code=int(_first(raw, 'icmp_code', default=-1)),
        next_hop=str(_first(raw, 'next_hop', 'next_ip', default='')),
        bgp_next_hop=str(_first(raw, 'bgp_next_hop', 'bgpnext_ip', default='')),
        src_nat_ip=str(_first(raw, 'src_nat_ip', default='')),
        dst_nat_ip=str(_first(raw, 'dst_nat_ip', default='')),
        src_nat_port=int(_first(raw, 'src_nat_port', default=-1)),
        dst_nat_port=int(_first(raw, 'dst_nat_port', default=-1)),
    )


def stream_records(stream: TextIO, fmt: str) -> Iterator[dict]:
    if fmt == 'json':
        data = json.load(stream)
        if not isinstance(data, list):
            raise ValueError('formato json exige uma lista de registros (nfdump -o json)')
        for value in data:
            yield value
    elif fmt == 'ndjson':
        for number, line in enumerate(stream, 1):
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f'linha NDJSON {number}: {exc}') from exc
    else:
        raise ValueError('formato não suportado')
