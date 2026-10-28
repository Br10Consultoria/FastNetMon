# Roadmap — FastNetMon Combined Filters

## Fase 0: POC v0.1.0

- [x] Regras AND/OR com CIDR, IP, portas, protocolos, TCP flags e exclusões
- [x] Janelas PPS, Mbps, fluxos/s, requisições/s e fontes únicas
- [x] Ingestão NDJSON e nfdump JSON
- [x] HTTP/PHP baseado em logs (não é inspeção de payload criptografado)
- [x] Watcher de arquivos rotacionados e checkpoint SQLite
- [x] Alertas JSON em modo somente leitura e 15 testes unitários

## Fase 1: coleta e compatibilidade

- [ ] Validar NetFlow v9 e IPFIX reais de MikroTik, Huawei, Cisco e Juniper
- [ ] Adicionar ingestão de sFlow/IPFIX em streaming com limites de recursos
- [ ] Tratar amostragem, duplicações, timestamps fora de ordem e atrasos
- [ ] Testar desempenho em cenários reais de 1/10/40/100Gbps
- [ ] Usar serviço systemd sem root, healthchecks, persistência e retenção
- [ ] Reduzir consumo de memória no parsing nfdump
- [ ] Separar SYN de SYN-ACK, confirmar limites reais de coleta

## Fase 2: regras multioperadora

- [ ] Políticas por cliente, hostgroup, ASN, IP/prefixo e exceções
- [ ] Correlação NetFlow + HTTP/WAF
- [ ] DNS L7 baseado em logs/sondas (QNAME, QTYPE, NXDOMAIN, RCODE)
- [ ] Baseline adaptativo por hora, porta e prefixo
- [ ] IDs persistentes de incidentes, deduplicação e trilha de auditoria

## Fase 3: operação

- [ ] API autenticada e dashboard
- [ ] Prometheus, Zabbix, Grafana, Telegram e webhook
- [ ] Replays seguros de telemetria para testes

## Fase 4: mitigação assistida

- [ ] Integrar FlowSpec/RTBH com GoBGP/controlador independente
- [ ] Aprovação humana, allowlist, RBAC, TTL, rollback e auditoria
- [ ] Homologar upstream e medir impacto em tráfego legítimo

**Nunca acionar mitigação apenas com a POC.** Ataques acima do link contratado precisam de ação do provedor de trânsito / upstream.
