"""Classificacao de enderecos em escopos: CGNAT (privado/pool), dedicado, infra, externo.

Usada pelo receptor NAT do A10, pelo rollup de fluxos e pelo detector bidirecional.
Nao deduz assinante: apenas diz a que "lado" da rede o endereco pertence.
"""
from __future__ import annotations

from functools import lru_cache
from ipaddress import ip_address, ip_network

SCOPE_PRIVATE = "cgnat_private"    # IP interno do CGNAT (100.64.x), visto antes do NAT
SCOPE_POOL = "cgnat_pool"          # IP publico compartilhado de pool CGNAT, visto depois do NAT
SCOPE_DEDICATED = "dedicated"      # IP publico dedicado de cliente
SCOPE_INFRA = "infra"              # roteador, coletor, servidores proprios
SCOPE_EXTERNAL = "external"        # qualquer outro (internet)

LOCAL_SCOPES = frozenset({SCOPE_PRIVATE, SCOPE_POOL, SCOPE_DEDICATED, SCOPE_INFRA})


class ScopeMap:
    """Resolve um IP para (escopo, nome_do_pool, max_users_por_ip).

    O perfil e o mesmo validado por cgnat_baseline.validate_config. Prefixos
    protegidos nao listados em nenhum papel contam como ``dedicated``.
    """

    def __init__(self, profile: dict, extra_infrastructure=()):
        meta = profile.get("cgnat_pool_metadata", {})
        self._private = [ip_network(c) for c in profile.get("inside_private_cidrs", [])]
        self._pools = [(ip_network(c), meta.get(c, {}).get("name", c),
                        int(meta.get(c, {}).get("max_users_per_ip") or 0))
                       for c in profile["cgnat_pools"]]
        self._infra = [ip_network(c, strict=False) for c in
                       list(profile.get("infrastructure_public_cidrs", [])) + list(extra_infrastructure)]
        self._dedicated = [ip_network(c) for c in profile.get("dedicated_public_cidrs", [])]
        self._protected = [ip_network(c) for c in profile["protected_cidrs"]]
        self.classify = lru_cache(maxsize=262144)(self._classify)

    def _classify(self, ip: str) -> tuple:
        external = (SCOPE_EXTERNAL, "", 0)
        try:
            addr = ip_address(ip)
        except ValueError:
            return external
        if addr.version != 4:
            # IPv6 de assinantes ainda nao e classificado: nunca presumir escopo.
            return external
        if any(addr in n for n in self._private):
            return (SCOPE_PRIVATE, "", 0)
        if any(addr in n for n in self._infra):
            return (SCOPE_INFRA, "", 0)
        for net, name, users in self._pools:
            if addr in net:
                return (SCOPE_POOL, name, users)
        if any(addr in n for n in self._dedicated) or any(addr in n for n in self._protected):
            return (SCOPE_DEDICATED, "", 0)
        return external

    def scope(self, ip: str) -> str:
        return self.classify(ip)[0]

    def is_local(self, ip: str) -> bool:
        return self.classify(ip)[0] in LOCAL_SCOPES
