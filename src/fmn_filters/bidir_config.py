"""Configuracao compartilhada da deteccao bidirecional (receptor NAT, rollup e detector)."""
from __future__ import annotations

import json
import math
from ipaddress import ip_network
from pathlib import Path

from .cgnat_baseline import validate_config as validate_profile
from .scopes import ScopeMap

DEFAULT_CONFIG = "/etc/orbymon/bidir.json"
LIMIT_SCOPES = ("dedicated", "cgnat_pool", "cgnat_private", "cgnat_subscriber")
SEVERITIES = frozenset({"warning", "high", "critical"})
PROTOCOLS = frozenset({"tcp", "udp", "icmp", "icmpv6", "esp", "gre"})
SPLIT_FIELDS = frozenset({"protocol", "local_port", "remote_port"})
LIMIT_KEYS = frozenset({"min_pps", "min_mbps", "min_remote_ips", "min_syn_ratio",
                        "min_zero_port_ratio"})
CONFIG_KEYS = frozenset({
    "enabled", "source", "cgnat_profile_path", "extra_infrastructure_cidrs",
    "nat_socket", "observation_ifindexes", "keep_ports", "counter_multiplier",
    "settle_minutes", "cooldown_minutes", "max_query_rows", "retention_days",
    "rules", "nat_rules"})
OPTIONAL_CONFIG_KEYS = frozenset({"ipv6_protected_cidrs"})
RULE_KEYS = frozenset({"name", "enabled", "severity", "direction", "protocols",
                       "local_ports", "remote_ports", "split_by",
                       "consecutive_minutes", "limits"})
NAT_RULE_KEYS = frozenset({"name", "enabled", "severity", "min_allocs_per_min",
                           "min_active_ports", "consecutive_minutes"})


def _int_list(value, name, low=0, high=4294967295):
    if not isinstance(value, list) or any(type(v) is not int or not low <= v <= high for v in value):
        raise ValueError(name + " deve ser lista de inteiros")
    return value


def _positive(value, name):
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
        raise ValueError(name + " deve ser positivo e finito")


def _validate_rule(rule, names):
    if not isinstance(rule, dict) or set(rule) - RULE_KEYS or not {
            "name", "enabled", "severity", "direction", "protocols", "limits"} <= set(rule):
        raise ValueError("regra com campos faltantes ou desconhecidos")
    name = rule["name"]
    if not isinstance(name, str) or not 1 <= len(name) <= 95 or name in names:
        raise ValueError("nome de regra invalido, extenso ou duplicado")
    names.add(name)
    if type(rule["enabled"]) is not bool:
        raise ValueError("enabled precisa ser booleano")
    if rule["severity"] not in SEVERITIES:
        raise ValueError("severity invalida")
    if rule["direction"] not in ("in", "out"):
        raise ValueError("direction deve ser in ou out")
    protos = rule["protocols"]
    if not isinstance(protos, list) or not protos or any(p not in PROTOCOLS for p in protos):
        raise ValueError("protocols: lista nao vazia de " + ",".join(sorted(PROTOCOLS)))
    for key in ("local_ports", "remote_ports"):
        if key in rule:
            if not _int_list(rule[key], key, 1, 65535):
                raise ValueError(key + " nao pode ser vazia")
    rule.setdefault("split_by", ["protocol"])
    split = rule["split_by"]
    if not isinstance(split, list) or not split or set(split) - SPLIT_FIELDS or len(set(split)) != len(split):
        raise ValueError("split_by invalido")
    rule.setdefault("consecutive_minutes", 2)
    if type(rule["consecutive_minutes"]) is not int or not 1 <= rule["consecutive_minutes"] <= 5:
        raise ValueError("consecutive_minutes deve estar entre 1 e 5")
    limits = rule["limits"]
    if not isinstance(limits, dict) or not limits or set(limits) - set(LIMIT_SCOPES):
        raise ValueError("limits precisa de ao menos um escopo: " + ",".join(LIMIT_SCOPES))
    for scope, item in limits.items():
        if not isinstance(item, dict) or not item or set(item) - LIMIT_KEYS:
            raise ValueError("limites de " + scope + " invalidos")
        if "min_pps" not in item and "min_mbps" not in item:
            raise ValueError("limites de " + scope + " precisam de min_pps ou min_mbps")
        for key, value in item.items():
            _positive(value, key)
        for ratio in ("min_syn_ratio", "min_zero_port_ratio"):
            if ratio in item and not item[ratio] <= 1:
                raise ValueError(ratio + " deve ser <= 1")
        if "min_remote_ips" in item and type(item["min_remote_ips"]) is not int:
            raise ValueError("min_remote_ips deve ser inteiro")


def _validate_nat_rule(rule, names):
    if not isinstance(rule, dict) or set(rule) - NAT_RULE_KEYS or not {
            "name", "enabled", "severity"} <= set(rule):
        raise ValueError("nat_rule com campos faltantes ou desconhecidos")
    if not isinstance(rule["name"], str) or not 1 <= len(rule["name"]) <= 95 or rule["name"] in names:
        raise ValueError("nome de nat_rule invalido ou duplicado")
    names.add(rule["name"])
    if type(rule["enabled"]) is not bool or rule["severity"] not in SEVERITIES:
        raise ValueError("nat_rule enabled/severity invalidos")
    if "min_allocs_per_min" not in rule and "min_active_ports" not in rule:
        raise ValueError("nat_rule precisa de min_allocs_per_min ou min_active_ports")
    for key in ("min_allocs_per_min", "min_active_ports"):
        if key in rule:
            _positive(rule[key], key)
    rule.setdefault("consecutive_minutes", 2)
    if type(rule["consecutive_minutes"]) is not int or not 1 <= rule["consecutive_minutes"] <= 5:
        raise ValueError("consecutive_minutes deve estar entre 1 e 5")


def validate_config(obj):
    if (not isinstance(obj, dict) or not CONFIG_KEYS <= set(obj)
            or set(obj) - CONFIG_KEYS - OPTIONAL_CONFIG_KEYS):
        raise ValueError("configuracao F4 com campos faltantes ou desconhecidos: esperado "
                         + ",".join(sorted(CONFIG_KEYS)) + " (opcional: "
                         + ",".join(sorted(OPTIONAL_CONFIG_KEYS)) + ")")
    obj.setdefault("ipv6_protected_cidrs", [])
    v6 = obj["ipv6_protected_cidrs"]
    if not isinstance(v6, list):
        raise ValueError("ipv6_protected_cidrs deve ser lista")
    for cidr in v6:
        net = ip_network(cidr, strict=True)
        if net.version != 6 or not net.is_global:
            raise ValueError("ipv6_protected_cidrs aceita apenas prefixos IPv6 publicos: " + str(cidr))
    if type(obj["enabled"]) is not bool or obj["source"] != "huawei":
        raise ValueError("enabled booleano e source huawei obrigatorios")
    for key in ("cgnat_profile_path", "nat_socket"):
        if not isinstance(obj[key], str) or not obj[key].startswith("/"):
            raise ValueError(key + " deve ser caminho absoluto")
    extras = obj["extra_infrastructure_cidrs"]
    if not isinstance(extras, list):
        raise ValueError("extra_infrastructure_cidrs deve ser lista")
    for cidr in extras:
        ip_network(cidr, strict=False)
    obs = obj["observation_ifindexes"]
    if not isinstance(obs, dict) or set(obs) != {"in", "out"}:
        raise ValueError("observation_ifindexes precisa de in e out")
    _int_list(obs["in"], "observation_ifindexes.in")
    _int_list(obs["out"], "observation_ifindexes.out")
    ports = obj["keep_ports"]
    if not isinstance(ports, dict) or set(ports) != {"below", "extra"}:
        raise ValueError("keep_ports precisa de below e extra")
    if type(ports["below"]) is not int or not 0 <= ports["below"] <= 65536:
        raise ValueError("keep_ports.below invalido")
    _int_list(ports["extra"], "keep_ports.extra", 1, 65535)
    _positive(obj["counter_multiplier"], "counter_multiplier")
    for key, low, high in (("settle_minutes", 1, 20), ("cooldown_minutes", 1, 1440),
                           ("max_query_rows", 1000, 2000000), ("retention_days", 1, 3650)):
        if type(obj[key]) is not int or not low <= obj[key] <= high:
            raise ValueError(key + " fora dos limites")
    names = set()
    rules = obj["rules"]
    if not isinstance(rules, list) or not rules:
        raise ValueError("rules deve ter pelo menos uma regra")
    for rule in rules:
        _validate_rule(rule, names)
    nat_rules = obj["nat_rules"]
    if not isinstance(nat_rules, list):
        raise ValueError("nat_rules deve ser lista")
    for rule in nat_rules:
        _validate_nat_rule(rule, names)
    return obj


def read_config(path=DEFAULT_CONFIG):
    return validate_config(json.loads(Path(path).read_text(encoding="utf-8")))


def load_profile(cfg):
    return validate_profile(json.loads(Path(cfg["cgnat_profile_path"]).read_text(encoding="utf-8")))


def build_scopes(cfg, profile=None):
    profile = profile if profile is not None else load_profile(cfg)
    return ScopeMap(validate_profile(profile), cfg["extra_infrastructure_cidrs"],
                    cfg.get("ipv6_protected_cidrs", []))


def keep_port_set(cfg):
    """Portas de servico preservadas no rollup; as demais (efemeras) viram 0."""
    keep = cfg["keep_ports"]
    return frozenset(range(1, keep["below"])) | frozenset(keep["extra"])
