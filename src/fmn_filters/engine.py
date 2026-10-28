from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
import math
from typing import Any

from .models import Event

MATCH_KEYS = {'src_cidrs', 'dst_cidrs', 'exclude_src_cidrs', 'exclude_dst_cidrs',
              'src_ports', 'dst_ports', 'protocols', 'tcp_flags_all', 'tcp_flags_any',
              'path_suffix', 'methods', 'statuses', 'all_of', 'any_of',
              'src_asns', 'dst_asns', 'src_countries', 'dst_countries', 'input_interfaces', 'output_interfaces',
              'not', 'tcp_flags_none', 'ttl_min', 'ttl_max', 'bytes_min', 'bytes_max',
              'packets_min', 'packets_max', 'duration_ms_min', 'duration_ms_max',
              'icmp_types', 'icmp_codes', 'src_nat_ips', 'dst_nat_ips',
              'src_nat_ports', 'dst_nat_ports', 'next_hops', 'bgp_next_hops'}
GROUP_KEYS = {'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'src_asn', 'dst_asn', 'src_country', 'dst_country', 'input_if', 'output_if'}
THRESHOLDS = {'min_pps', 'min_mbps', 'min_flows_per_sec', 'min_unique_sources', 'min_rps'}


def validate_match(match: dict):
    if not isinstance(match, dict):
        raise ValueError('match precisa ser objeto')
    unknown = match.keys() - MATCH_KEYS
    if unknown:
        raise ValueError(f'campo de filtro desconhecido: {sorted(unknown)}')
    for key in ('src_cidrs', 'dst_cidrs', 'exclude_src_cidrs', 'exclude_dst_cidrs'):
        if key in match:
            if not isinstance(match[key], list) or not match[key]:
                raise ValueError(f'{key} deve ser lista não vazia')
            for cidr in match[key]:
                ip_network(cidr, strict=False)
    for key in ('src_ports', 'dst_ports', 'src_asns', 'dst_asns', 'input_interfaces', 'output_interfaces', 'icmp_types', 'icmp_codes', 'src_nat_ports', 'dst_nat_ports'):
        if key in match:
            if not isinstance(match[key], list) or not match[key]:
                raise ValueError(f'{key} deve ser lista não vazia')
            for p in match[key]:
                if not isinstance(p, int) or isinstance(p, bool) or p < 0 or p > (65535 if key in ('src_ports', 'dst_ports') else 4294967295):
                    raise ValueError(f'{key} com porta inválida')
    for key in ('protocols', 'methods', 'statuses', 'src_countries', 'dst_countries'):
        if key in match and (not isinstance(match[key], list) or not match[key]):
            raise ValueError(f'{key} deve ser lista não vazia')
    for key in ('tcp_flags_all', 'tcp_flags_any', 'tcp_flags_none', 'path_suffix'):
        if key in match and (not isinstance(match[key], str) or not match[key]):
            raise ValueError(f'{key} deve ser string não vazia')
    for key in ('ttl_min', 'ttl_max', 'bytes_min', 'bytes_max', 'packets_min', 'packets_max', 'duration_ms_min', 'duration_ms_max'):
        if key in match and (not isinstance(match[key], (int,float)) or isinstance(match[key], bool) or not math.isfinite(match[key]) or match[key] < 0):
            raise ValueError(f'{key} deve ser numérico, não negativo e finito')
    for key in ('src_nat_ips', 'dst_nat_ips', 'next_hops', 'bgp_next_hops'):
        if key in match:
            if not isinstance(match[key], list) or not match[key]:
                raise ValueError(f'{key} precisa de lista de IPs')
            for ip in match[key]:
                ip_address(ip)
    if 'not' in match:
        validate_match(match['not'])
    for key in ('all_of', 'any_of'):
        if key in match:
            if not isinstance(match[key], list) or not match[key]:
                raise ValueError(f'{key} deve ser lista não vazia')
            for part in match[key]:
                validate_match(part)


def matches(event: Event, match: dict) -> bool:
    for key, field_name in (('src_cidrs', 'src_ip'), ('dst_cidrs', 'dst_ip')):
        if key in match and not any(ip_address(getattr(event, field_name)) in ip_network(v, strict=False) for v in match[key]):
            return False
    for key, field_name in (('exclude_src_cidrs', 'src_ip'), ('exclude_dst_cidrs', 'dst_ip')):
        if key in match and any(ip_address(getattr(event, field_name)) in ip_network(v, strict=False) for v in match[key]):
            return False
    for key, field_name in (('src_ports', 'src_port'), ('dst_ports', 'dst_port'),
                            ('src_asns', 'src_asn'), ('dst_asns', 'dst_asn'),
                            ('src_countries', 'src_country'), ('dst_countries', 'dst_country'),
                            ('input_interfaces', 'input_if'), ('output_interfaces', 'output_if'),
                            ('icmp_types','icmp_type'), ('icmp_codes','icmp_code'),
                            ('src_nat_ports','src_nat_port'), ('dst_nat_ports','dst_nat_port'),
                            ('protocols', 'protocol'), ('methods', 'method'), ('statuses', 'status')):
        if key in match:
            allowed = match[key]
            if key == 'protocols':
                allowed = [str(v).lower() for v in allowed]
            if key in ('src_countries', 'dst_countries'):
                allowed = [str(v).upper() for v in allowed]
            if key == 'methods':
                allowed = [str(v).upper() for v in allowed]
            if getattr(event, field_name) not in allowed:
                return False
    for key,attr in (('src_nat_ips','src_nat_ip'),('dst_nat_ips','dst_nat_ip'),
                     ('next_hops','next_hop'),('bgp_next_hops','bgp_next_hop')):
        if key in match and getattr(event, attr) not in match[key]:
            return False
    for prefix, value in (('ttl',event.ttl),('bytes',event.bytes),('packets',event.packets),
                          ('duration_ms',(event.end-event.start)*1000)):
        if f'{prefix}_min' in match and value < match[f'{prefix}_min']:
            return False
        if f'{prefix}_max' in match and value > match[f'{prefix}_max']:
            return False
    if 'tcp_flags_none' in match and any(c in event.tcp_flags for c in match['tcp_flags_none'].upper()):
        return False
    if 'not' in match:
        # Unknown enrichment cannot prove country/ASN exclusion.
        negated = match['not']
        for k, value in (('src_countries', event.src_country), ('dst_countries', event.dst_country),
                         ('src_asns', event.src_asn), ('dst_asns', event.dst_asn)):
            if k in negated and (value == '' or value == 0):
                return False
        if matches(event, negated):
            return False
    if 'tcp_flags_all' in match and not all(c in event.tcp_flags for c in match['tcp_flags_all'].upper()):
        return False
    if 'tcp_flags_any' in match and not any(c in event.tcp_flags for c in match['tcp_flags_any'].upper()):
        return False
    if 'path_suffix' in match and not event.path.split('?', 1)[0].lower().endswith(match['path_suffix'].lower()):
        return False
    if 'all_of' in match and not all(matches(event, child) for child in match['all_of']):
        return False
    if 'any_of' in match and not any(matches(event, child) for child in match['any_of']):
        return False
    return True


@dataclass(frozen=True)
class Rule:
    name: str
    kind: str
    match: dict
    group_by: tuple[str, ...]
    window_seconds: int
    cooldown_seconds: int
    thresholds: dict[str, float]
    severity: str = 'warning'

    @classmethod
    def from_dict(cls, raw: dict) -> 'Rule':
        expected = {'name', 'kind', 'match', 'group_by', 'window_seconds',
                    'cooldown_seconds', 'thresholds', 'severity'}
        extra = raw.keys() - expected
        if extra:
            raise ValueError(f'chaves desconhecidas: {sorted(extra)}')
        for key in ('name', 'kind', 'match', 'group_by', 'window_seconds', 'thresholds'):
            if key not in raw:
                raise ValueError(f'regra sem {key}')
        validate_match(raw['match'])
        if not isinstance(raw['name'], str) or not raw['name'].strip():
            raise ValueError('nome da regra inválido')
        if raw['kind'] not in ('flow', 'http'):
            raise ValueError('kind deve ser flow ou http')
        group_by = raw['group_by']
        if not isinstance(group_by, list) or not group_by or any(k not in GROUP_KEYS for k in group_by):
            raise ValueError('group_by inválido')
        if len(set(group_by)) != len(group_by):
            raise ValueError('group_by duplicado')
        window = raw['window_seconds']
        cooldown = raw.get('cooldown_seconds', 60)
        if type(window) is not int or not 1 <= window <= 3600:
            raise ValueError('window_seconds deve estar entre 1 e 3600')
        if type(cooldown) is not int or not 0 <= cooldown <= 86400:
            raise ValueError('cooldown_seconds inválido')
        thresholds = raw['thresholds']
        if not isinstance(thresholds, dict) or not thresholds or thresholds.keys() - THRESHOLDS:
            raise ValueError('thresholds desconhecidos/vazios')
        if raw['kind'] == 'http' and any(k in thresholds for k in ('min_flows_per_sec', 'min_pps', 'min_mbps')):
            raise ValueError('regra HTTP só pode usar min_rps/min_unique_sources')
        if raw['kind'] == 'flow' and 'min_rps' in thresholds:
            raise ValueError('regra flow não pode usar min_rps')
        for k, v in thresholds.items():
            if not isinstance(v, (int, float)) or isinstance(v, bool) or not math.isfinite(v) or v <= 0:
                raise ValueError(f'{k} deve ser positivo e finito')
        return cls(raw['name'], raw['kind'], raw['match'], tuple(group_by), window,
                   cooldown, dict(thresholds), raw.get('severity', 'warning'))


@dataclass
class Bucket:
    packets: float = 0.
    bytes: float = 0.
    flows: float = 0.
    requests: float = 0.
    sources: set[str] = field(default_factory=set)


class Detector:
    """Streaming, approximate time-window evaluator. No changes to network state."""

    def __init__(self, rules: list[Rule], max_groups: int = 100000):
        if len(set(r.name for r in rules)) != len(rules):
            raise ValueError('nomes de regras duplicados')
        self.rules = rules
        self.buckets: dict[tuple, dict[int, Bucket]] = {}
        self.last_alert: dict[tuple, float] = {}
        self.high_watermark: dict[tuple, int] = {}
        self.max_groups = max_groups
        self.seen = 0

    def _add_flow(self, buckets: dict[int, Bucket], event: Event, window: int, current: int):
        # Distribute exporter totals evenly across the flow duration (rate estimate, NOT per-packet truth).
        duration = event.end - event.start
        if duration == 0:
            segments = [(math.floor(event.end), 1.)]
        else:
            segments = []
            first = max(math.floor(event.start), current - window + 1)
            last = min(math.ceil(event.end) - 1, current)
            for second in range(first, last + 1):
                overlap = max(0., min(event.end, second + 1) - max(event.start, second))
                if overlap > 0:
                    segments.append((second, overlap / duration))
        for second, factor in segments:
            b = buckets.setdefault(second, Bucket())
            b.packets += event.packets * factor
            b.bytes += event.bytes * factor
            b.flows += factor
            if len(b.sources) < 10000:
                b.sources.add(event.src_ip)

    def process(self, event: Event) -> list[dict[str, Any]]:
        results = []
        self.seen += 1
        for rule in self.rules:
            if rule.kind != event.kind or not matches(event, rule.match):
                continue
            group = {k: getattr(event, k) for k in rule.group_by}
            key = (rule.name, tuple(group.items()))
            current = math.ceil(event.end) - 1 if event.end > event.start else math.floor(event.end)
            watermark = max(current, self.high_watermark.get(key, current))
            self.high_watermark[key] = watermark
            if current < watermark - rule.window_seconds + 1:
                continue  # Out-of-order record too old to matter.
            if key not in self.buckets and len(self.buckets) >= self.max_groups:
                raise RuntimeError('limite de grupos atingido; reduzir cardinalidade ou aumentar capacidade')
            buckets = self.buckets.setdefault(key, {})
            start_bucket = watermark - rule.window_seconds + 1
            for second in list(buckets):
                if second < start_bucket:
                    del buckets[second]
            if event.kind == 'flow':
                self._add_flow(buckets, event, rule.window_seconds, watermark)
            else:
                b = buckets.setdefault(current, Bucket())
                b.requests += 1
                if len(b.sources) < 10000:
                    b.sources.add(event.src_ip)
            active = [v for second, v in buckets.items() if start_bucket <= second <= watermark]
            total_packets = sum(b.packets for b in active)
            total_bytes = sum(b.bytes for b in active)
            source_ips = set()
            for b in active:
                source_ips.update(b.sources)
            metrics = {
                'pps': round(total_packets / rule.window_seconds, 2),
                'mbps': round(8 * total_bytes / (rule.window_seconds * 1e6), 4),
                'flows_per_sec': round(sum(b.flows for b in active) / rule.window_seconds, 2),
                'unique_sources': len(source_ips),
                'rps': round(sum(b.requests for b in active) / rule.window_seconds, 2),
            }
            metrics_map = {'min_pps': 'pps', 'min_mbps': 'mbps', 'min_flows_per_sec': 'flows_per_sec',
                           'min_unique_sources': 'unique_sources', 'min_rps': 'rps'}
            if not all(metrics[metrics_map[k]] >= val for k, val in rule.thresholds.items()):
                continue
            last = self.last_alert.get(key)
            if last is not None and watermark - last < rule.cooldown_seconds:
                continue
            self.last_alert[key] = watermark
            # Attribution is only safe if grouping includes the dimension (multi-source
            # destination alerts MUST NOT claim a single ASN or source IP).
            context = {name: getattr(event, name) for name in
                       ('src_asn', 'src_asn_name', 'src_country', 'src_latitude', 'src_longitude',
                        'dst_asn', 'dst_asn_name', 'dst_country')
                       if (name.startswith('src_') and ('src_asn' in rule.group_by or 'src_ip' in rule.group_by)
                           or name.startswith('dst_') and ('dst_asn' in rule.group_by or 'dst_ip' in rule.group_by))}
            if 'src_ip' not in rule.group_by:
                context.pop('src_latitude', None)
                context.pop('src_longitude', None)
            # Even grouped-by-ASN data may span countries: country attribution
            # requires explicit src_country grouping or single source IP.
            if 'src_country' not in rule.group_by and 'src_ip' not in rule.group_by:
                context.pop('src_country', None)
            results.append({'context': context, 'rule': rule.name, 'kind': rule.kind, 'severity': rule.severity,
                            'group': group, 'time_unix': event.end, 'window_seconds': rule.window_seconds,
                            'metrics_estimated': metrics, 'sample_sources': sorted(source_ips)[:10],
                            'action': 'alert_only'})
        # Cheap global sweep to avoid leaks for old/inactive groups.
        if self.seen % 1000 == 0:
            latest = math.floor(event.end)
            for key in list(self.buckets):
                if self.high_watermark[key] < latest - 3600:
                    del self.buckets[key]
                    self.high_watermark.pop(key, None)
                    self.last_alert.pop(key, None)
        return results
