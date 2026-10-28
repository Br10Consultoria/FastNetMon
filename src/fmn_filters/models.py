from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
import math


def timestamp(value: object, assume_utc: bool = False) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        result = float(value)
    elif isinstance(value, str):
        try:
            result = float(value)
        except ValueError:
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
            if dt.tzinfo is None:
                if not assume_utc:
                    raise ValueError(f'timestamp sem timezone: {value!r}; use --assume-utc e TZ=UTC')
                dt = dt.replace(tzinfo=timezone.utc)
            result = dt.timestamp()
    else:
        raise ValueError('timestamp ausente/inválido')
    if not math.isfinite(result) or result < 0:
        raise ValueError('timestamp inválido')
    return result


def positive_number(value: object, field: str, allow_zero: bool = True) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f'{field} inválido') from exc
    if isinstance(value, bool) or not math.isfinite(result) or result < 0 or (not allow_zero and result == 0):
        raise ValueError(f'{field} inválido')
    return result


@dataclass(frozen=True)
class Event:
    kind: str
    start: float
    end: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packets: float
    bytes: float
    tcp_flags: str = ''
    method: str = ''
    path: str = ''
    status: int = 0
    src_asn: int = 0
    dst_asn: int = 0
    src_asn_name: str = ''
    dst_asn_name: str = ''
    src_country: str = ''
    dst_country: str = ''
    src_latitude: float | None = None
    src_longitude: float | None = None
    dst_latitude: float | None = None
    dst_longitude: float | None = None
    input_if: int = 0
    output_if: int = 0
    ttl: int = -1
    icmp_type: int = -1
    icmp_code: int = -1
    next_hop: str = ''
    bgp_next_hop: str = ''
    src_nat_ip: str = ''
    dst_nat_ip: str = ''
    src_nat_port: int = -1
    dst_nat_port: int = -1

    def __post_init__(self):
        if self.kind not in ('flow', 'http'):
            raise ValueError('tipo de evento desconhecido')
        for addr in (self.src_ip, self.dst_ip):
            ip_address(addr)
        for port in (self.src_port, self.dst_port):
            if not 0 <= port <= 65535:
                raise ValueError('porta inválida')
        if self.end < self.start:
            raise ValueError('fim do fluxo anterior ao início')
        if self.end - self.start > 86400:
            raise ValueError('duração de fluxo anômala')
        positive_number(self.packets, 'packets')
        positive_number(self.bytes, 'bytes')
