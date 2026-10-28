# OrbyMon — filtros combinados (referência RR Flow)

O documento fornecido pelo usuário **Filtros Manuais – RR Flow.pdf** contém grupos de IP, portas, redes, ASN, geolocalização, protocolos, flags, ICMP, TTL, bytes, pacotes, duração, interfaces, NAT e next-hop. **Esta implementação usa um formato JSON próprio; não aceita diretamente a DSL textual do RR Flow.**

## Campos disponíveis

- `src_cidrs`, `dst_cidrs`, `exclude_src_cidrs`, `exclude_dst_cidrs`: listas de CIDR IPv4/IPv6.
- `src_ports`, `dst_ports`: listas de portas.
- `protocols`: `tcp`, `udp`, `icmp`, `icmpv6`, `gre`, `esp` etc. (se exporter fornecer).
- `src_asns`, `dst_asns`: listas de ASN numéricos.
- `src_countries`, `dst_countries`: países ISO-3166 alfa-2 (`BR`, `US`, `CN`, ...).
- `input_interfaces`, `output_interfaces`: índices de interface exportados.
- `tcp_flags_all`, `tcp_flags_any`, `tcp_flags_none`: flags canônicas (`S` SYN, `A` ACK, ...).
- `icmp_types`, `icmp_codes`: listas de códigos inteiros.
- `ttl_min`, `ttl_max`, `bytes_min`, `bytes_max`, `packets_min`, `packets_max`, `duration_ms_min`, `duration_ms_max`: limites **por registro de fluxo**, não limites agregados.
- `src_nat_ips`, `dst_nat_ips`, `src_nat_ports`, `dst_nat_ports`, `next_hops`, `bgp_next_hops`: igualdade exata sobre campos normalizados presentes nos exports.
- `path_suffix`, `methods`, `statuses`: regras HTTP baseadas em logs; não obtidas de NetFlow.
- `all_of` (AND), `any_of` (OR), `not` (negação): operadores combináveis e aninhados.

Os limites de **taxa agregada** vão no campo `thresholds` (`min_pps`, `min_mbps`, `min_flows_per_sec`, `min_unique_sources`, `min_rps`), com `group_by` e `window_seconds`.

## Exemplo

```json
{
  "name": "SYN-PURO",
  "kind": "flow",
  "match": {
    "protocols": ["tcp"], "tcp_flags_all": "S", "tcp_flags_none": "A",
    "dst_cidrs": ["198.51.100.0/24"], "dst_ports": [80, 443],
    "not": {"src_countries": ["BR"]}
  },
  "group_by": ["src_ip", "dst_ip", "dst_port"],
  "window_seconds": 10,
  "thresholds": {"min_pps": 20000}
}
```

## Observações importantes

- ASN e país podem estar ausentes, incorretos ou desatualizados. **Desconhecido não deve ser interpretado como país diferente de BR** para bloquear tráfego. Não crie políticas de mitigação automática baseadas apenas em geolocalização.
- País, ASN e coordenadas devem vir de exportadores ou de bases **MaxMind GeoLite2-ASN/City**; endereço IP não identifica a localização física de uma pessoa. A fonte e data da base devem ser exibidas na UI futura.
- ASN de origem pode se referir à rede anunciadora do IP e **não comprova identidade do atacante**; UDP pode ser falsificado.
- `tcp_flags_*` em NetFlow são flags agregadas; usar `S AND NOT A` é uma aproximação, não análise pacote a pacote.
- `TTL`, NAT, next-hop, interfaces, ICMP precisam estar presentes no formato exportado e podem exigir templates específicos por roteador.
- Filtros `src_asns` e `src_countries` permitem valor `0`/`''` apenas se explicitamente configurados; um valor ausente pode reduzir cobertura.
- Os limiares exemplificativos **não estão calibrados** para operadoras reais.

Ver `rules/orbymon-advanced.json` para exemplos mais completos.
