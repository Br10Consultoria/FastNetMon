# Arquitetura v0.1

## Fluxo de dados

```
Roteadores/Exportadores --NetFlow v9 / IPFIX--> nfcapd (UDP 2056)
                                               |
                                               v
                                       nfcapd.* rotacionado
                                               |
                                               v
                                         nfdump -o json
                                               |
                                               v
                                  FastNetMon Combined Filters
                                  - regras AND/OR aninhadas
                                  - agrupamento por tupla
                                  - janelas e limiares
                                  - cooldown
                                               |
                                               v
                                          Alertas JSON

Roteadores -- NetFlow/IPFIX/sFlow --> FastNetMon Community (sensor independente)
Nginx/Apache/WAF -- logs HTTP JSON --> Combined Filters (tipo http)
```

## Interpretação

Cada evento tem origem, destino, portas, protocolo, contadores, timestamps e, opcionalmente, flags TCP. Eventos HTTP acrescentam method, path e status. As regras são aplicadas à fonte definida em kind: flow ou http. **Não existe ainda correlação entre fontes em uma mesma regra**.

As taxas PPS/Mbps são estimadas pela distribuição uniforme dos contadores durante a duração do fluxo. Latência de exportação, tempo de rotação, amostragem e possíveis registros duplicados alteram métricas. Na POC, a contagem de fontes distintas é limitada e o processo mantém buckets na memória. Não se trata de detecção sub-segundo.

## Restrições e cuidados

- IP de origem de UDP pode ser falsificado; porta 53 e volume não comprovam DNS amplification ou autoria.
- Flags TCP de um registro agregado não equivalem à inspeção de cada pacote.
- Detecção PHP precisa dos logs do serviço que termina HTTPS; nunca confie em X-Forwarded-For indiscriminadamente.
- Para operadores com múltiplas OLTs/BNGs/links, considere de-duplicação de fluxos espelhados/exportados.
- Modele allowlists de servidores críticos e não faça mitigação automática sem homologação de upstream, auditoria e rollback.
- Não exponha portas de exportação UDP para a Internet; aceite apenas IPs explicitamente autorizados.

## Estratégia de validação

1. Rodar somente alertas e criar baseline por cliente/serviço (idealmente semanas de tráfego real).
2. Comparar contadores com roteadores e FastNetMon Community.
3. Medir atraso, perdas e falsos positivos.
4. Homologar reação supervisionada antes de anunciar FlowSpec ou RTBH.
