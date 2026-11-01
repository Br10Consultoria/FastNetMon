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
- **Linha de base por hora e exceções** ([BASE.md](BASE.md)): limite dinâmico por hora (dias úteis/fim de
  semana, nunca acima do fixo), exceções por IP/rede/ASN com validade, limite próprio por IP, “acima do habitual”
  nos alarmes por filtro. Pendente do lado do roteador: active timeout do NetStream em 1 minuto.

- **Saúde** ([SAUDE.md](SAUDE.md)): coleta, atrasos, disco, serviços e tempo de execução, com aviso no Telegram.

## 3. Clientes — próxima
- Cadastro "Meus clientes" (prefixos dedicados, nome) e consulta ao RADIUS/BRAS para transformar
  100.64.x + horário em login PPPoE.
- Relatório por cliente (o que ele originou/recebeu) para enviar junto com a notificação de abuso.

## 4. Ferramentas
- RDAP/whois, busca de AS por nome (base GeoLite2-ASN local), prefixos anunciados por AS (RIPEstat),
  ping/traceroute e diagnóstico DNS a partir do servidor.

## 5. Operação
- Várias fontes (outros roteadores), e-mail e webhook, exportar/importar configuração.

## 6. Mitigação (última)
- Blackhole (RTBH) e FlowSpec para o NE8000 a partir dos incidentes, com aprovação manual primeiro,
  whitelist/blacklist, retirada automática ao resolver.

## Renomear para OrbyFlow
1. Nome visível (painel, Grafana, Telegram, documentação).
2. Identificadores internos (`/etc/orbymon`, serviços `orbymon-*`, banco/tabelas, usuários) com
   migração assistida e janela de manutenção.
