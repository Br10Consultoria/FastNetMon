# OrbyFlow 🛡️

**OrbyFlow — observabilidade de tráfego e defesa DDoS para provedores** · [BR10 Consultoria](https://github.com/Br10Consultoria) · Estágio: **piloto passivo / laboratório**.

![OrbyFlow](assets/orbymon-logo.svg)

> Antes chamado **OrbyMon**. Os identificadores internos (serviços `orbymon-*`, `/etc/orbymon`, banco `orbymon`, variáveis `ORBYMON_*`) continuam com o nome antigo até a migração planejada em [docs/ROADMAP.md](docs/ROADMAP.md).

> **Pode instalar num Ubuntu 24.04 LTS ou Debian e receber NetFlow/IPFIX do Huawei e MikroTik.** Isso coleta tráfego normal, mesmo sem qualquer ataque. A consulta inicial funciona com `nfdump`; **a ingestao MariaDB e o provisionamento automatico de dashboards Grafana estao disponiveis em piloto, ainda nao homologados para producao.** Mitigação por blackhole (RTBH) disponível, começando em simulação.

## Instalação automática (recomendada)

Num Ubuntu 22.04/24.04 limpo, um comando instala tudo (MariaDB, coletor, Grafana, detecção, painel, reputação,
alarmes, saúde, backup e ClickHouse):

```bash
sudo apt update && sudo apt install -y git
cd /opt && sudo git clone https://github.com/Br10Consultoria/FastNetMon.git orbymon
cd /opt/orbymon && sudo bash scripts/install.sh --public-host IP_DO_SERVIDOR --a10-ip IP_DO_A10
```

Detalhes, opções e o que configurar depois: **[docs/INSTALACAO.md](docs/INSTALACAO.md)**. As seções abaixo
descrevem a instalação manual, etapa por etapa.

## Instalar servidor do zero — começar somente pelo Huawei

**Piloto atual:** [Huawei NE8000 primeiro; MikroTik só após calibração](docs/HUAWEI_PILOT.md). O bootstrap prepara ambas as fontes, mas inicie **apenas** o serviço Huawei no primeiro teste.

## Preparação dos coletores (Huawei + MikroTik)

**[Manual completo, do sistema operacional à recepção do primeiro flow →](docs/INSTALL_PILOT.md)**

```bash
sudo apt update && sudo apt install -y git python3
cd /opt
sudo git clone https://github.com/Br10Consultoria/FastNetMon.git orbymon
cd /opt/orbymon

bash scripts/test-incidents.sh
sudo bash scripts/bootstrap-pilot.sh

# Revise firewall (UDP 2056/2057 somente para IPs reais dos roteadores),
# caminhos de acesso e parametros do serviço antes de iniciar.
sudo systemctl enable --now orbymon-nfcapd@huawei.service
# Nao iniciar o servico MikroTik na fase Huawei
```

O `bootstrap-pilot.sh` instala dependências e prepara dois serviços systemd separados; **não inicia serviços nem altera firewall ou roteadores**. Após configurar a exportação de NetFlow/IPFIX no Huawei/MikroTik:

```bash
sudo tcpdump -ni any -c 15 'udp port 2056 or udp port 2057'
sudo bash scripts/inspect-pilot.sh huawei
## Depois de calibrar a coleta Huawei, testaremos o MikroTik separadamente
```

A inspeção mostra volume normal, top IPs, portas e protocolos, sem depender de alerta. Os coletores são independentes e persistem após reinício, com diretórios separados.

> **Fase 2 (piloto):** [Ingestao idempotente Huawei → MariaDB → Grafana](docs/TRAFFIC_PIPELINE.md). O timer e opcional e nao e iniciado pelo bootstrap.

## Instalar Grafana e importar TODOS os dashboards automaticamente

No Ubuntu com MariaDB OrbyFlow instalado:

```bash
cd /opt/orbymon
sudo bash scripts/setup-grafana.sh --public-host 187.87.201.198
```

O instalador configura HTTPS autofirmado na porta 3000, datasource somente leitura e importa todos dashboards da pasta grafana/dashboards. Veja [procedimento e seguranca](docs/GRAFANA_AUTO.md).

**Fase 2 IPs e interfaces:** [instalacao automatica com dashboard](docs/IP_ANALYTICS.md): `sudo bash scripts/setup-ip-analytics.sh`.

**GeoLite2 (ASN/operadora/país e mapa):** [configuracao com MaxMind e atualização diária](docs/GEOIP_SETUP.md): `sudo bash scripts/setup-geoip.sh` após cadastrar a licença GeoLite2. As bases não vêm incluídas no repositório e o estado do servidor deve ser verificado.

**Ataques (painel) e ClickHouse:** a página **Ataques** do painel reúne os ataques recebidos e originados com filtros combinados e o detalhe origem → destino, portas e IP privado do assinante. Para retenção longa dos fluxos e consultas rápidas, instale o [ClickHouse](docs/CLICKHOUSE.md): `sudo bash scripts/setup-clickhouse.sh`.

**Fase 3 DDoS passiva:** [regras AND/OR/NOT para as redes protegidas, PPS/Mbps e dashboard](docs/DDOS_PASSIVE.md). Instalar com `sudo bash scripts/setup-ddos-passive.sh` apos validar a Fase 2.

**Fase 4 CGNAT:** [diagnostico read-only, IP publico como origem/destino, perfis de pool e baseline p95](docs/CGNAT_BASELINE.md): `sudo bash scripts/setup-cgnat-baseline.sh`.

**Fase 4 bidirecional (ataque recebido e originado, CGNAT-aware):** [receptor NAT do A10, rollup com IP privado do assinante e detector nos dois sentidos](docs/BIDIRECTIONAL.md). Instalar com `sudo bash scripts/setup-bidir.sh` apos o perfil CGNAT. Substitui a F3 para deteccao; mantenha a F3 apenas durante a validacao.

**Painel web de administração:** página própria em HTTPS (porta 8443, separada do Grafana) com usuário, senha e 2FA para configurar provedor, ASNs, blocos, pools CGNAT, bordas, regras, Telegram e retenção: `sudo bash scripts/setup-admin.sh`. Veja [docs/ADMIN.md](docs/ADMIN.md).

**Clientes e RADIUS:** login PPPoE e cliente dedicado nos avisos e na investigação — [docs/CLIENTES.md](docs/CLIENTES.md). **Mitigação (RTBH):** blackhole via BGP com simulação, validação, aprovação manual e travas — [docs/MITIGACAO.md](docs/MITIGACAO.md). **E-mail e webhook:** avisos também por SMTP e webhook (Slack, Discord, Teams, JSON) — [docs/AVISOS.md](docs/AVISOS.md). **Backup:** diário e cifrado, com restauração — [docs/BACKUP.md](docs/BACKUP.md). **Saúde:** coleta, atrasos, disco, serviços e tempo de execução com aviso no Telegram — [docs/SAUDE.md](docs/SAUDE.md). **Linha de base e exceções:** limite dinâmico por hora do dia, exceções por IP/ASN e limite próprio por IP — [docs/BASE.md](docs/BASE.md). **Alarmes por filtro:** filtro nfdump + limite fixo ou % acima da média, incidente com início/resfriamento/fim e Telegram com top alvos e assinante CGNAT — [docs/ALARMES.md](docs/ALARMES.md). **Análise avançada:** filtros nfdump com atalhos da rede (`@dst_rede`, `@src_pools`...), filtros salvos e top IPs/portas/AS/interfaces no painel — [docs/ANALISE.md](docs/ANALISE.md). **Dashboards:** gerados do export validado em produção (`grafana/exports` → `python3 grafana/import_v2.py`). Próximas etapas: [docs/ROADMAP.md](docs/ROADMAP.md).

**Etapa 2 — denúncias de abuso e reputação:** página *Investigar* (denúncia com IP, horário e porta → assinante atrás do CGNAT, pelo log NAT do A10) e monitoramento de hora em hora de listas de bloqueio, DNSBL e AbuseIPDB, com o assinante provável e aviso no Telegram: `sudo bash scripts/setup-reputation.sh`. Veja [docs/REPUTACAO.md](docs/REPUTACAO.md).

**Alertas no Telegram (F4):** início, lembrete e encerramento de cada ataque, com assinante CGNAT e link para o painel: `sudo bash scripts/setup-telegram.sh`. Veja [docs/BIDIRECTIONAL.md](docs/BIDIRECTIONAL.md).

**A10 CGNAT Syslog:** [recepcao TCP/5514 exclusiva, spool bruto e inspecao sem correlacao prematura](docs/A10_SYSLOG.md). Instalar com sudo bash scripts/setup-a10-syslog.sh --a10-source-ip IP_REAL_DO_A10.

**A10 Syslog framing:** [auditoria read-only de mensagens RFC 5424 e integridade antes de correlacao NAT](docs/A10_SYSLOG_AUDIT.md). Use `python3 -m fmn_filters.a10_syslog_audit` com usuario orbymon.

## Componentes e estágio real

| Componente | Estado |
| --- | --- |
| Coleta NetFlow v9/IPFIX em portas separadas | **Piloto disponível**, precisa validar exportadores reais |
| Inspeção de tráfego normal (nfdump) | Disponível |
| Filtros AND/OR/NOT, IP, porta, protocolo, ASN, geolocalização e métricas | Protótipo funcional; regras de exemplo usam IPs de documentação |
| Incidentes SQLite, API local autenticada e replay idempotente | v0.3 laboratório |
| Grafana e MariaDB (SQL, dashboards JSON, GeoLite2 offline) | Pipeline idempotente MariaDB e instalador automatico Grafana disponiveis (piloto) |
| Verificação em links reais 10/40/100G e sampling | Não homologado |
| Deteccao bidirecional CGNAT-aware (F4), log NAT do A10, IP privado do assinante | **Piloto**, testes unitarios; SQL ainda nao exercitado em MariaDB real |
| BGP FlowSpec, RTBH, comandos em roteadores | **Não implementados**; nenhuma ação automática |
| Multiempresa com autorização robusta | Ainda não homologado para produção |

## Manuais

- **[Instalação de piloto Ubuntu/Debian com Huawei e MikroTik](docs/INSTALL_PILOT.md)** — passo a passo de servidor zero, firewall, serviços, exportadores, validação e limitações.
- [Filtros combinados](docs/FILTERS.md) — sintaxe JSON, campos ASN, país, NAT, TTL e TCP/ICMP.
- [Simulação e incidentes](docs/TESTING_INCIDENTS.md) — testes, SQLite e API somente em loopback.
- [Grafana/MariaDB](docs/GRAFANA.md) — formatos e implantação **parcial**, com avisos sobre duplas contagens.
- [Arquitetura](docs/ARCHITECTURE.md), [próximos passos](docs/NEXT_STEPS.md), [roadmap](docs/ROADMAP.md).
- [Posicionamento original](docs/PRODUCT_POSITIONING.md) — inspiração em funcionalidades comuns de observabilidade, sem reproduzir interface RR Flow.

## Limites importantes

O OrbyFlow é um **complemento independente**; não inclui código nem instalador do daemon FastNetMon Community. NetFlow/IPFIX é telemetria de fluxos, não inspeção de todos os pacotes. Ao usar amostragem, as taxas exigem validação. Informações de ASN/GeoIP podem ser aproximadas ou ausentes; o endereço de origem UDP pode ser forjado. URLs PHP não são reveladas por HTTPS/NetFlow sem logs Nginx/Apache/WAF.

O `nfcapd` cria arquivos rotacionados continuamente; **não há retenção automática no bootstrap**. Monitore disco e estabeleça política antes de manter um piloto ativo por dias. Fluxos de dois roteadores podem representar **as mesmas conexões** vistas em pontos diferentes: nunca some sem de-duplicação.

Código original OrbyFlow sob licença MIT. FastNetMon Community é independente (GPL-2.0).
