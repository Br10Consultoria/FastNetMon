# OrbyMon F4 — detecção bidirecional com CGNAT (etapa 1)

Detecta ataques **recebidos** (internet → sua rede) e **originados** (sua rede → internet), separa IP
dedicado de IP de CGNAT e identifica o **IP privado do assinante** (100.64.64.0/19) usando o log NAT do A10.
Somente alertas: nenhuma ação em Huawei, A10, firewall ou BGP.

## Topologia considerada

| Item | Valor |
|---|---|
| Blocos públicos | `187.87.201.0/24` e `45.238.170.0/23` |
| Pools CGNAT (A10) | NAT-POOL-08..11 = `45.238.170.64/26`, `45.238.171.64/26`, `45.238.170.128/26`, `45.238.171.128/26` (32 usuários/IP) |
| Rede privada CGNAT | `100.64.64.0/19` |
| Exportador de fluxos (Huawei) | `187.87.201.193` (classificado como infraestrutura) |
| Servidor OrbyMon (flow) | `187.87.201.198` (infraestrutura) — assumido; confirme se o digitado foi `87.87.201.198` |
| A10 (origem do syslog) | `10.100.10.10` |

IPs públicos dos blocos que não são pool nem infraestrutura contam como **dedicados**. Ajuste
`extra_infrastructure_cidrs` em `/etc/orbymon/bidir.json` para incluir outros equipamentos próprios.

## Arquitetura

```
A10 --syslog TCP 5515--> orbymon-a10-nat  (framing correto, tabela NAT em memória, log TSV compacto)
                              |  socket Unix /run/orbymon/nat.sock (consulta IP público:porta -> IP privado)
                              |  agregados NÃO amostrados por assinante/minuto -> orby_nat_user_minute
Huawei --NetFlow--> nfcapd --> orbymon-flow-rollup-huawei (a cada 30 s)
                              |  direção in/out, escopo, SYN, portas de serviço, IP privado do assinante
                              v
                        orby_flow_minute --> orbymon-bidir-huawei (a cada 1 min) --> orby_attack_events
                                                                                  \-> orby_alerts
```

## O que foi corrigido em relação à F3

| Problema | Correção |
|---|---|
| Ataque dividido em 2 interfaces nunca somava e não alertava | O detector soma o mesmo alvo entre interfaces; as interfaces ficam no detalhe do evento |
| Só detectava tráfego recebido | Regras `direction: out` (flood, SYN/varredura, ICMP, IP usado como refletor) |
| Reflexão/amplificação não detectável (rollup sem porta de origem) | Rollup guarda porta de origem/destino **de serviço** (<1024 e lista `keep_ports`); regra `IN reflexao/amplificacao UDP` |
| IP de pool CGNAT tratado como dedicado | Limites por escopo: `dedicated`, `cgnat_pool`, `cgnat_private`, `cgnat_subscriber` |
| Sem identificação do assinante | Pool + porta → IP privado pelo log NAT; eventos trazem `top_subscribers` |
| Sem SYN flood | Proporção de fluxos "somente SYN" (`min_syn_ratio`) |
| Syslog A10 truncado em 8096 B / eventos fragmentados | Receptor próprio separa pelo cabeçalho `<PRI>1 timestamp` e só aceita evento com `]` fechado |
| Fluxos com origem forjada (bogon) | Não são descartados; contados em `remoto_nao_publico_mantido` |

## Instalação

Pré-requisitos: fases 1 e 2 e o perfil CGNAT (`setup-cgnat-baseline.sh`).

```bash
cd /opt/orbymon && git pull --ff-only origin main
PYTHONPATH=src python3 -m unittest discover -s tests -q
sudo bash scripts/setup-bidir.sh
```

Para diagnosticar um arquivo de 1 hora já rotacionado (mostra período, eventos/s, liberações casadas e por
que mensagens foram ignoradas, sem IP de assinante):

```bash
sudo -u orbymon env PYTHONPATH=/opt/orbymon/src /opt/orbymon/.venv/bin/python -m fmn_filters.a10_nat \
  --config /opt/orbymon/rules/bidir.example.json \
  --replay-rsyslog /var/log/orbymon/a10/a10-current.ndjson-20261031-20.gz
```

O instalador valida a configuração, cria as tabelas, instala as units e, se existir o spool do rsyslog, roda
`a10_nat --replay-rsyslog` mostrando **somente contagens** — é a prova rápida de que o novo framing recupera
os eventos que o rsyslog fragmentou.

### Lado A10 (manual; não aplicado por este projeto)

1. Libere TCP **5515** no firewall do servidor **somente** para `10.100.10.10`.
2. Configure no A10 uma **segunda** destinação de log (porta 5515) mantendo a atual (5514) até validar.
   Confirme a sintaxe da sua versão do ACOS com `?` antes de aplicar.
3. Confirme: `journalctl -u orbymon-a10-nat -n 20 --no-pager` (eventos alocados/liberados, mensagens ignoradas).
4. **NTP no A10** antes de trocar `--time-source received` por `a10`. Enquanto o relógio do A10 não estiver
   sincronizado, o padrão `received` usa o horário de chegada (atraso típico ~1 s).

### Pontos de observação no Huawei (importante para não duplicar)

O mesmo pacote pode ser visto em mais de uma interface (antes e depois do A10). Em `observation_ifindexes`:

- `in`: ifIndex por onde entra tráfego **vindo da internet** (uplinks/trânsito).
- `out`: ifIndex por onde entra tráfego **de assinantes** (lado BNG/A10).

Vazio = sem filtro (aceita tudo; pode haver dupla contagem entre pré e pós-NAT). Se o NetStream do Huawei
enxerga o tráfego **antes** do A10, o IP de origem já é o `100.64.x` (escopo `cgnat_private`) e a identificação
do assinante é direta; se só enxerga depois, a identificação depende do log NAT (`cgnat_subscriber`). Se ambos
existirem, o evento `cgnat_private` prevalece e o `cgnat_subscriber` equivalente é suprimido.

## Regras

Cada regra tem `direction`, `protocols`, filtros opcionais `local_ports`/`remote_ports`, `consecutive_minutes`
(1–5) e `limits` por escopo. Todos os limites informados precisam ser atingidos em **todos** os minutos:

| Limite | Significado |
|---|---|
| `min_pps`, `min_mbps` | taxa do alvo somada entre interfaces |
| `min_remote_ips` | origens distintas (entrada) ou destinos distintos (saída) |
| `min_syn_ratio` | fração dos pacotes vinda de fluxos somente-SYN |

`nat_rules` usam contadores **não amostrados** do A10: alocações de porta por minuto e portas ativas por
assinante (sinal forte de varredura/abuso mesmo com amostragem 1:2048).

**Os limites do exemplo são pontos de partida, não calibrados.** Calibre com tráfego real:

```bash
sudo -u orbymon env $(cat /etc/orbymon/pipeline.env | xargs) python3 -m fmn_filters.attack_report --top-talkers 60
sudo -u orbymon env $(cat /etc/orbymon/pipeline.env | xargs) python3 -m fmn_filters.attack_report --nat-top 60
sudo -u orbymon env $(cat /etc/orbymon/pipeline.env | xargs) python3 -m fmn_filters.bidir_detector --config /etc/orbymon/bidir.json --dry-run
```

## Consultas (base da etapa 2)

```bash
# Quais IPs (públicos e privados CGNAT) originaram ataque nas últimas 24 h
python3 -m fmn_filters.attack_report --hours 24 --direction out
# Histórico de um assinante (IP privado) ou de um IP público
python3 -m fmn_filters.attack_report --hours 168 --ip 100.64.64.7
```

Tabela `orby_attack_events`: direção, escopo, pool, IP público, IP privado do assinante, protocolo, portas
de serviço, pps, Mbps, IPs remotos, razão SYN, interfaces e detalhes (top remotos, top assinantes).

## Limitações — leia antes de confiar nos números

- **Amostragem NetFlow (1:2048)**: abuso pequeno de um único assinante fica invisível no fluxo; as métricas de
  fluxo são **estimativas**. Verifique contra SNMP se o `nfdump` já multiplicou os contadores
  (`counter_multiplier` = 1.0 assume que sim; não multiplique duas vezes).
- **Latência**: rotação de 30 s + rollup + `settle_minutes` + janelas de minuto = detecção em ~3–5 min. Não
  é detecção em segundos; para isso é preciso um detector em tempo real (ex.: FastNetMon Community) ao lado.
- **Memória do receptor**: cada mapeamento ocupa ~450 bytes. O histórico de mapeamentos fechados fica 15 min
  em memória (`--retention-seconds 900`, ~0,6 GB a ~1500 liberações/s). Rollup atrasado mais que isso deixa
  fluxos sem assinante resolvido.
- **Disco**: enquanto rsyslog (5514) e receptor (5515) recebem juntos, o log NAT é gravado duas vezes. O spool
  do rsyslog já usa ~3,5–4 GB/dia compactado. Depois de validar o receptor, desligue a destinação 5514 no A10.
- **Estado NAT em memória**: ao reiniciar, o receptor reconstrói a última janela a partir do log TSV; mapeamentos
  mais antigos ainda abertos (sessões longas) ficam não resolvidos. Fluxos sem mapeamento têm `subscriber_ip`
  vazio e **nunca** são atribuídos por aproximação.
- **Volume do log NAT**: o spool atual cresce ~31 GiB/dia (~3 mil eventos/s, indica log por porta). Avalie
  *port-batch* no A10 para reduzir. O log TSV compacto é compactado diariamente e **não é apagado**; defina
  retenção legal e espaço em disco.
- **IPv6** de assinantes não é classificado (ignorado). Informe se há tráfego IPv6 a proteger.
- Porta de serviço mantida/zerada: portas efêmeras viram 0 no rollup (a resolução NAT usa a porta real antes de zerar).
- Regras `nat_rules` exigem eventos em todos os minutos da janela; assinante parado por um minuto quebra a sequência.
- A camada SQL foi validada por parser MySQL e por testes com cursor simulado, **mas ainda não foi executada
  contra um MariaDB real**; rode primeiro em homologação.
- Não implementado (etapa 2 e seguintes): portal de consulta ao cliente, verificação em listas de reputação
  (blocklists), mitigação (RTBH/FlowSpec), painel Grafana F4.
