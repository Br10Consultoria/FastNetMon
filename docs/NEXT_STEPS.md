# Próximos passos de implementação e otimização

## P0 — homologação da coleta
- Validar com nfdump os formatos NetFlow v9/IPFIX em Huawei NE8000 e MikroTik.
- Monitorar perdas, amostragem, duplicidade, latência de exportação e timestamps fora de ordem.
- Implementar checkpoints idempotentes no pipeline de métricas e fila com retry/backpressure (o sink inicial não oferece isso).
- Testar consultas e geomap no Grafana real, com credenciais de leitura restritas.

## P1 — escalabilidade e produto
- Regras customizadas com editor visual AND/OR/NOT, importação/validação e auditoria.
- Multiempresa/multiprovedor com isolamento de tenants e RBAC.
- Perfil de cliente: prefixos IPv4/IPv6, ASN próprio, limites PPS/Mbps, horários, serviços e allowlist.
- Baselines dinâmicos por grupo, protocolo, hora do dia e percentis.
- Alertas parametrizados com severidade, estado (novo/confirmado/resolvido), incidentes correlacionados e supressão.
- Otimizar ingestão streaming sem carregar todo JSON nfdump na memória, workers multiprocesso, filas e chunking.
- Separar banco de time-series (ex. ClickHouse, VictoriaMetrics/Prometheus), MySQL para catálogo e alertas, com retenção e downsampling.

## P2 — identificação e visualização
- ASN name via GeoLite2-ASN; país/cidade/coordenadas aproximadas via GeoLite2-City; rotinas de atualização e sinal de base desatualizada.
- Ranking de IPs, ASNs, países, protocolos e portas; mapa-múndi sem geolocalização exata.
- Exibir interfaces, sFlow sampling, direção de tráfego, BGP next-hop e NAT quando disponível.
- Capturar HTTP/PHP via Nginx/Apache/WAF com privacidade e não confiar em cabeçalhos arbitrários de proxy.
- Integrar Grafana e Zabbix, webhooks, notificações e PDF de incidentes.

## P3 — mitigação segura
- API autenticada para recomendar RTBH/FlowSpec com aprovação humana, RBAC, TTL, allowlist, observabilidade e rollback.
- Testar upstream antes de bloquear. Nunca confiar apenas em ASN ou país para classificar atacante.
- Homologar em laboratório com replay e limites estritos de ações em roteadores.
