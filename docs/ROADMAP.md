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
  nos alarmes por filtro. Active timeout do NetStream em 1 minuto aplicado no NE8000.

- **Relatório por cliente/IP** ([CLIENTES.md](CLIENTES.md)): ataques, alarmes, tráfego e listas num período, com texto
  para resposta de abuso.
- **E-mail e webhook** ([AVISOS.md](AVISOS.md)): todos os avisos também por SMTP e webhook.
- **Backup** ([BACKUP.md](BACKUP.md)): diário, cifrado, com cópia externa opcional e restauração assistida.
- **Saúde** ([SAUDE.md](SAUDE.md)): coleta, atrasos, disco, serviços e tempo de execução, com aviso no Telegram.

- **Clientes e RADIUS** ([CLIENTES.md](CLIENTES.md)): clientes com prefixos dedicados e login PPPoE pelo `radacct`
  nos avisos e na investigação.
- **Ferramentas** (página Ferramentas do painel): RDAP com contato de abuso, AS com prefixos anunciados, DNS, ping e
  traceroute a partir do servidor, tudo auditado.


## 4. Ferramentas (restante)
- Busca de AS por nome (base GeoLite2-ASN local).

## 5. Operação
- Várias fontes (outros roteadores).

## 6. Mitigação (última)
- Blackhole (RTBH) e FlowSpec para o NE8000 a partir dos incidentes, com aprovação manual primeiro,
  whitelist/blacklist, retirada automática ao resolver.

## Renomear para OrbyFlow
1. Nome visível (painel, Grafana, Telegram, documentação).
2. Identificadores internos (`/etc/orbymon`, serviços `orbymon-*`, banco/tabelas, usuários) com
   migração assistida e janela de manutenção.
