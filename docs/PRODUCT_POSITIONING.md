# OrbyMon — identidade própria e plano de produto

O OrbyMon é uma plataforma original de **investigação explicável de DDoS para ISPs**, não uma reprodução de um analisador de tráfego genérico. Referências de mercado, incluindo manuais do RR Flow fornecidos pelo solicitante, servem apenas para identificar necessidades e padrões de rede. **Não reutilizar telas, elementos gráficos, textos, workflows exatos, código ou comandos do bot do concorrente.**

## O que manter do padrão de redes

Filtros IP e IPv6/CIDR, ASN, portas, protocolos, direções, TTL, ICMP, TCP flags, NAT e interfaces são capacidades genéricas de fluxo. Usar JSON próprio, configuração validada e critérios de segurança. ASN e GeoIP significam origem **aproximada do prefixo**, não identidade geográfica do atacante; IP de origem UDP pode ser falsificado. Resolver DNS em HTTPS e ataques PHP exige telemetria de logs DNS/HTTP/WAF, não somente NetFlow.

## O que distingue o OrbyMon

- **Central de incidentes:** cada alerta relacionado é agrupado em incidente persistente com histórico, severidade, destino e picos PPS/Mbps/RPS.
- **Evidência e contraevidência:** mostrar quais métricas provocaram o disparo e quais campos estavam ausentes; guardar o registro bruto com retenção controlada.
- **Observabilidade da coleta:** detectar exportador inativo, amostragem, fila em atraso, duplicações e diferenças de contagem.
- **Escopo por ISP:** tenant, prefixos monitorados, limites por serviço e controles de acesso a implementar; não apresentar `--tenant` da POC como RBAC real.
- **Simulação de resposta:** no futuro, propor FlowSpec/RTBH com prévia do impacto, aprovação, expiração e rollback — jamais efetivar com a POC.
- **Integrações em vez de clonar:** usar Grafana para dashboards, Zabbix para SNMP/estado e OrbyCore para inventário autorizado; evitar criar mais um NMS completo.

## O que NÃO copiar do RR Flow

- Não copiar captura de telas, ilustrações, textos, nomes de menus ou disposição de painéis.
- Não reaproveitar código, APIs privadas, identidade visual ou comandos do bot Telegram do concorrente.
- Não reproduzir uma suíte genérica de BGP Looking Glass, scanner de portas, terminal SSH, inventário e CGNAT como núcleo.
- Não chamar filtros da DSL nfdump de "exclusivos" ou tentar replicar fluxos de criação de regras da interface.
- Não anexar os PDFs de referência ao repositório.

## Interface proposta (autoral)

OrbyMon azul/laranja com navegação baseada em tarefas: **Central, Incidentes, Sinais, Políticas, Proteção, Integrações**. Evitar menus, cards, screenshots e tokens visuais do RR Flow. O GitHub permanecerá com o nome `FastNetMon` por compatibilidade; a marca de produto pode ser `OrbyMon`.

## Roadmap por critérios verificáveis

1. **POC atual:** detector combinado, GeoLite2 opcional, MariaDB/Grafana agregados, incidentes persistidos em SQLite, API HTTP local autenticada e testes de replay.
2. **Próximo ciclo:** acoplar pipeline MariaDB/Grafana aos incidentes, sistema de eventos idempotente, métricas de qualidade de coleta, benchmark e homologação NetFlow do NE8000/MikroTik.
3. **Operação ISP:** identidade de usuários, RBAC por tenant, API TLS, dashboard autoral de investigação, notificações Telegram/email/webhook sem comandos de mitigação por bot.
4. **Mitigação supervisionada:** laboratório BGP com controles de escopo/impacto, TTL, dupla aprovação, auditoria e rollback, seguido de avaliação de falsos positivos.

**Estado:** este arquivo é planejamento, e não declaração de funcionalidades já implementadas.
