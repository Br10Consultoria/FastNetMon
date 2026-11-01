# Próximas etapas (OrbyMon → OrbyFlow)

Ordem pensada para deixar **detecção e alarmes certeiros antes da mitigação**.

## Feito
- Detecção bidirecional CGNAT-aware, calibração, Telegram, painel com 2FA.
- Investigação de denúncias (log NAT do A10), reputação (listas, DNSBL, AbuseIPDB).
- Análise avançada com filtros nfdump e filtros salvos; dashboards padronizados a partir do export
  validado em produção (`grafana/exports`) e sem blocos fixos do provedor (`orby_net_prefixes`).
- **Alarmes por filtro** ([ALARMES.md](ALARMES.md)): filtro nfdump + condições fixas ou relativas à média,
  incidente aberto → resfriando → encerrado, histórico por alarme, teste com o tráfego real e Telegram com
  top alvos/origens e assinante CGNAT.

## 2. Base de comportamento (menos falso positivo) — próxima
- Linha de base por IP/pool/porta por hora do dia e dia da semana; limites dinâmicos que substituem a
  calibração diária fixa.
- Lista de exceções (CDNs, DNS próprios, Google/Meta, servidores do provedor) por grupo.
- Exportação NetStream com *active timeout* menor (ex.: 60 s) para detectar em ~1 minuto.

## 3. Clientes
- Cadastro "Meus clientes" (prefixos dedicados, nome) e consulta ao RADIUS/BRAS para transformar
  100.64.x + horário em login PPPoE.
- Relatório por cliente (o que ele originou/recebeu) para enviar junto com a notificação de abuso.

## 4. Ferramentas
- RDAP/whois, busca de AS por nome (base GeoLite2-ASN local), prefixos anunciados por AS (RIPEstat),
  ping/traceroute e diagnóstico DNS a partir do servidor.

## 5. Operação
- Várias fontes (outros roteadores), e-mail e webhook, página de saúde (atraso de coleta, disco,
  serviços), exportar/importar configuração.

## 6. Mitigação (última)
- Blackhole (RTBH) e FlowSpec para o NE8000 a partir dos incidentes, com aprovação manual primeiro,
  whitelist/blacklist, retirada automática ao resolver.

## Renomear para OrbyFlow
1. Nome visível (painel, Grafana, Telegram, documentação).
2. Identificadores internos (`/etc/orbymon`, serviços `orbymon-*`, banco/tabelas, usuários) com
   migração assistida e janela de manutenção.
