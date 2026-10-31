# OrbyMon Fase 3 - deteccao PASSIVA de anomalias DDoS

Sem qualquer comando no Huawei, Mikrotik, firewall, CGNAT, PPPoE,
FlowSpec ou RTBH. Alertas representam sinais de anomalia, nao ataques provados.

## Redes protegidas
- 45.238.170.0/23
- 187.87.201.0/24

As redes fornecidas ja constam do arquivo inicial de regras.
Limites ilustrativos conservadores: calibrar usando o trafego real e SNMP.

## Instalacao automatica

Requer fase 2 ja funcional (orby_ip_pairs_minute com dados):

    cd /opt/orbymon
    git pull --ff-only origin main
    PYTHONPATH=src python3 -m unittest discover -s tests -q
    sudo bash scripts/setup-ddos-passive.sh

Instala tabelas orby_ddos_rule_state e orby_ddos_checks, timer separado
orbymon-ddos-huawei.timer e dashboard Grafana. Reutiliza orby_alerts.
Ao reinstalar, preserva /etc/orbymon/ddos-rules.json ja existente.

## Filtros combinados

Suporta AND/all_of, OR/any_of, NOT/not, src/dst CIDR, origem ASN, pais,
protocolo, porta destino, interfaces entrada/saida e exclusoes.
Exemplo conceitual de AND UDP e (DNS ou NTP) e NOT rede confiavel:

    "match": {
      "all_of": [
        {"protocols": ["udp"]},
        {"any_of": [{"dst_ports": [53]}, {"dst_ports": [123]}]},
        {"not": {"src_cidrs": ["198.51.100.0/24"]}}
      ]
    }

198.51.100.0/24 e apenas rede reservada de documentacao, nao sua rede.
Todas as regras sao limitadas aos dois blocos reais protegidos.

O motor de filtros original suporta outros campos (SYN/ACK, TTL,
ICMP detalhado, NAT, next-hop, HTTP/PHP); a F3 baseada no MariaDB agregado
NAO aceita esses campos ainda: exige NetFlow bruto ou logs L7.

## Operacao

Todos os tres minimos (PPS, Mbps, fontes distintas) devem ser atingidos
em dois minutos consecutivos. Janela e examinada com atraso de quatro
minutos por causa de exportacao NetFlow. ifIndex entrada e saida sao separados,
nao somados; contagens do nfdump ja consideram sampler 1:2048.

    sudo systemctl is-active orbymon-ddos-huawei.timer
    sudo journalctl -u orbymon-ddos-huawei.service -n 30 --no-pager
    sudo mariadb orbymon -e "SELECT * FROM orby_ddos_checks"
    sudo mariadb orbymon -e "SELECT event_time,rule_name,dst_ip,dst_port,pps,mbps,unique_sources FROM orby_alerts WHERE rule_name LIKE 'OrbyMon F3:%' ORDER BY event_time DESC LIMIT 25"

Dashboard: "OrbyMon | Fase 3 - Sinais DDoS passivos", pasta OrbyMon.

Para parar SOMENTE detector:
    sudo systemctl disable --now orbymon-ddos-huawei.timer

## Limitacoes de seguranca e confiabilidade

- Nenhum bloqueio ou alteracao de roteamento.
- Limiares inicialmente NAO calibrados; comparar taxas com SNMP.
- Bucket igual ao minuto final do fluxo, sem redistribuir trafego entre minutos.
- PPS, Mbps e contagem de origens estimados a partir de NetFlow amostrado.
- DDoS curto, volume baixo ou poucas origens podem nao gerar alerta.
- Se volume superar max_query_rows, falha sem produzir resultado parcial.
- Reinicios longos podem perder janelas historicas; catch-up e futuro.
- Ausencia de campos para payload HTTPS, DNS QNAME e TCP flags no rollup.


## Foco DDoS — sem dependencia do Zabbix ou Syslog do A10

Fluxo efetivo: **Huawei NetFlow v9/IPFIX → nfcapd/nfdump →
`orby_ip_pairs_minute` (MariaDB) → `ddos_passive` →
`orby_alerts` → Grafana OrbyMon**.

A entrada A10 RFC5424/TCP 5514 fica **separada**. Os contadores
A10 de alocacao/liberacao de portas CGNAT nao identificam sozinhos
volume por IP de destino, fontes e portas associadas a um ataque.
Podem complementar diagnosticos de carga e funcionamento do CGNAT,
mas **nao sao requisito** para a deteccao DDoS baseada no Huawei.

A fase 3 atual detecta **sinais**, passivamente, principalmente
**inundacoes volumetricas para destinos publicos protegidos**.
Portas 53/123 sao indicios de trafego DNS/NTP, nao prova de
reflexao/amplificacao. HTTP, HTTPS e caminho `*.php` nao
podem ser inspecionados com os rollups de NetFlow por minuto;
para deteccao por URL, usar futuramente logs HTTP do
servidor/WAF que termina o TLS.

### Melhorias de confiabilidade propostas (PR separado, sem deploy)

- Regras negativas como `{"not":{"protocols":["udp"]}}` ou
  `any_of` com ramo sem restricao positiva **nao passam**
  a validacao: evitam cobrir trafego quase arbitrario e
  producao de falsos sinais.
- Janela sem nenhuma linha NetFlow em `orby_ip_pairs_minute`
  passa a registrar `status='sem_dados'` em
  `orby_ddos_checks`, em vez de `passive` como se
  tivesse observado os fluxos. Zero sinal com dados e
  **diferente** de zero sinal porque nao ha dados.
- Dashboard inclui minutos desde ultima amostra Huawei e
  estado da ultima verificacao (0=janela analisada,
  1=sem dados, 2=verificacao atrasada, -1=ausente).
- Regras de bloqueio de trafego **nao** sao implementadas
  nem habilitadas.

### Confirmar prontidao do detector no flow (somente leitura)

Nao executar `scripts/setup-ddos-passive.sh` em producao
antes de homologar a configuracao e a importacao do PR.
Para coletar o estado atual sem modificar servicos:

```bash
systemctl is-active orbymon-ip-huawei.timer orbymon-ddos-huawei.timer
systemctl list-timers --all | grep -E 'orbymon-(ip|ddos)-huawei'
journalctl -u orbymon-ddos-huawei.service -n 15 --no-pager
mariadb orbymon -e "
SELECT COUNT(*) AS pares_ultimos_10m,
       MAX(bucket_utc) AS ultimo_bucket_utc
FROM orby_ip_pairs_minute
WHERE source='huawei'
  AND bucket_utc>=UTC_TIMESTAMP()-INTERVAL 10 MINUTE;
SELECT source,last_checked_at,latest_bucket_utc,status,signals,alerts
FROM orby_ddos_checks;"
```

Estes SQLs apenas consultam **contagens e metadados**,
sem retornar IPs de assinantes nem registros brutos.
Se a tabela `orby_ddos_checks` nao existir, a fase 3
ainda nao foi instalada no host: nao criar automaticamente.

### Baseline obrigatorio antes de alertar como DDoS

Os limites demonstrativos atuais nao foram calibrados.
Medir trafego real por hora, dia, interface e protocolo,
comparar Huawei/SNMP e ajustar `min_pps`, `min_mbps`,
`min_sources` e `input_interfaces` por servico.
Com sampling 1:2048, `nfdump` pode extrapolar
bytes/pacotes, mas **nao extrapola quantidade de flows**:
fontes distintas observadas sao apenas amostra e podem
subestimar uma inundacao distribuida. Portanto nao
tratar `unique_sources` como cardinalidade real.

Referencia para comportamento do sampling no nfdump:
https://github.com/phaag/nfdump#sampling


### Leitura de produção — 31/10/2026, aproximadamente 17h51 BRT

O operador executou consultas read-only no `flow`:

```text
orbymon-ip-huawei.timer = active
orbymon-ddos-huawei.timer = active
orby_ip_pairs_minute (huawei, ultimos 10min) = 213 linhas
ultimo bucket da coleta = 2026-10-31 20:48:00 UTC
orby_ddos_checks: last_checked_at=2026-10-31 20:51:00 UTC
latest_bucket_utc=2026-10-31 20:46:00 UTC
status=passive, signals=0, alerts=0
```

Conclusao limitada: ingestao e detector agendados, registros recentes,
nenhuma regra disparou na janela avaliada. O atraso de cinco minutos
entre verificacao e ultimo minuto avaliado corresponde ao
`settle_minutes=4` + fronteira de janela. As 213 linhas **nao sao**
213 pacotes/conexoes; representam pares agregados por minuto.
`passive` preexistente nao certifica se a janela tinha amostras:
a correcao deste PR registra `sem_dados` quando vazia. Ainda nao
ha evidencia suficiente para dizer que os limites estao calibrados.

### Calibracao opcional somente leitura, sem IP de clientes no output

O novo `sql/ddos_baseline_readonly.sql` contem tres consultas
`SELECT`, trabalhando em 60 minutos encerrados 5 minutos
antes da execucao. O resultado informa cobertura dos buckets
e **picos por destino/minuto** separados por protocolo,
ifIndex e direcao, inclusive DNS/NTP por porta. Os IPs
sao usados apenas para agrupamento **interno** no SQL;
a resposta exibe apenas estatisticas e interfaces.

Para executar diretamente da branch do PR #33 no worktree
**isolado**, sem checkout, merge, alteracao em prod ou
reinicializacao de qualquer processo:

```bash
git -C /opt/orbymon-a10-audit fetch origin fix/ddos-passive-reliability-20261031
set -o pipefail
git -C /opt/orbymon-a10-audit show FETCH_HEAD:sql/ddos_baseline_readonly.sql | mariadb orbymon
```

Se o primeiro comando falhar, nao executar a segunda linha.
As taxas sao estimadas de NetFlow amostrado: picos de PPS,
Mbps e origens podem vir de minutos ou destinos diferentes.
O objetivo imediato e observar cobertura e ordem de grandeza,
**sem alterar automaticamente os limiares atuais**.


### Baseline real: 60/60 minutos, mas nenhuma linha para destinos protegidos

Em 31/10/2026, o operador executou o
`sql/ddos_baseline_readonly.sql` no `flow`:

```text
pares_60min=2103
minutos_com_dados=60
ultimo_bucket_consolidado_utc=2026-10-31 21:00:00
pacotes_estimados_60min=8613888
```

As consultas seguintes (picos por destino público protegido
e por destino DNS/NTP, UDP/53 e 123) **não retornaram linhas**.
Isso mostra que **nenhum destino** na hora analisada
correspondia aos prefixos configurados
`45.238.170.0/23` e `187.87.201.0/24`
na representação `dst_ip` do rollup Huawei.

**Consequencia:** o detector direcionado a esses prefixos pode
estar cego ao tráfego relevante. Zero alertas **nao comprova**
ausência de DDoS. Antes de ajustar limiares, conferir se
os prefixos aparecem em `src_ip`, qual ifIndex/direcao e
quais protocolos chegam. Nao inverter src/dst automaticamente,
pois isso pode disparar falsos alertas em tráfego de saida.

### Diagnostico de sentido e interfaces (sem IPs individuais)

Arquivo em PR #33: `sql/ddos_direction_audit_readonly.sql`.
Ele usa tres consultas **SELECT** no mesmo intervalo de
60 minutos finalizado 5 minutos antes da execucao:
1. Classifica se as redes protegidas aparecem como origem,
   destino, ambas as pontas ou nenhuma.
2. Quando ha prefixo protegido, aponta protocolos,
   ifIndex de entrada/saida e `netflow_direction` bruta.
3. Lista protocolos, interfaces e direcoes de maior
   movimento independentemente das redes protegidas.

Os enderecos `src_ip`/`dst_ip` sao consultados somente
para testes de pertencimento ao prefixo; os resultados
**nao projetam enderecos de clientes**. As taxas sao
medias na janela observada, nao PPS exato do Huawei.

Execucao isolada no `flow`, sem atualizar checkout produtivo:

```bash
git -C /opt/orbymon-a10-audit fetch origin \
  fix/ddos-passive-reliability-20261031 &&
git -C /opt/orbymon-a10-audit show \
  FETCH_HEAD:sql/ddos_direction_audit_readonly.sql | mariadb orbymon
```

Se o `fetch` falhar, **nao** executar o `show` de
`FETCH_HEAD` antigo. Com `set -o pipefail`, erros na
consulta serao sinalizados. Com os tres resultados
definir se o Huawei exporta somente saida, se os
prefixos da configuracao estao errados ou se ha outra
causa de ausencia do tráfego de entrada. Nao modificar
NE8000 nem regras do detector ate confirmar a causa.


### Resultado de 60 minutos sem QUALQUER ponta dos CIDRs protegidos

O operador executou `sql/ddos_direction_audit_readonly.sql` no
`flow` em 31/10/2026 e obteve:

```text
papel_das_redes=nenhuma_ponta_protegida
pares_agregados=2106
minutos_com_dados=60
pacotes_estimados=8603648
megabits_estimados=44890.16
ultimo_bucket_utc=2026-10-31 21:03:00
```

O segundo `SELECT` (interfaces com ponta protegida) **nao
retornou linhas**. O terceiro mostrou interfaces `86`,
`16`, `334` e `0`, protocolos TCP/UDP/ESP/ICMP,
com `netflow_direction` bruta `0` e `1`.
**Nao interpretar** `0/1` como sentido Internet sem
validacao externa, nem `ifIndex 0` como interface fisica.

Conclusao: a ausencia dos CIDRs `45.238.170.0/23` e
`187.87.201.0/24` ocorre **tanto em src_ip como em dst_ip**
durante essa janela. Logo, **inverter origem/destino nao
resolve**. Suspeitas a diferenciar:
- Huawei BNG esta vendo apenas trafego **antes/depois da
  traducao NAT do lado dos assinantes**, enquanto o IP
  publico compartilhado esta no segmento externo do A10;
- prefixos escolhidos nao correspondem aos alvos que
  atravessam o Huawei monitorado;
- exportacao NetFlow amostrada/visibilidade parcial de
  interfaces ou dados IPv6 em vez de IPv4.

**Nao configurar mitigacao, NAT, ou exportacao em producao
apenas a partir deste resultado.** Para uma DDoS contra IPs
publicos do A10, a coleta relevante precisa ser feita
no ponto que enxerga o trafego externo antes do NAT.
A necessidade de outro exportador/link so pode ser
decidida depois de validar topologia e interfaces.

### Identificar faixas reais e se ha CGNAT 100.64/10

Arquivo novo:
`sql/ddos_ip_scope_audit_readonly.sql` — dois SELECTs,
sem enderecos individuais nos resultados:
1. Top 30 prefixos **IPv4 /16** observados nas pontas de
   origem/destino, com numero de pares e minutos;
2. categorias `CGNAT_100.64/10`, `PRIVADO_RFC1918`,
   `IPv6`, `OUTRO_IPv4` agrupadas por `ifIndex` e
   direcao, sem declarar que `OUTRO_IPv4` seja sempre
   publico (inclui enderecos especiais).

Execute **sem atualizar o OrbyMon de producao**:

```bash
set -o pipefail
git -C /opt/orbymon-a10-audit fetch origin \
  fix/ddos-passive-reliability-20261031 &&
git -C /opt/orbymon-a10-audit show \
  FETCH_HEAD:sql/ddos_ip_scope_audit_readonly.sql | mariadb orbymon
```

Se os blocos protegidos nao aparecem nem como origem
nem destino, nao ajustar limiares DDoS para encobrir
falta de cobertura. Mesmo com amostra em 60/60 minutos,
a visibilidade de ataques aos IPs publicos do CGNAT
**ainda nao foi validada**.


### Auditoria real dos enderecos visiveis no Huawei (31/10/2026)

O operador rodou `sql/ddos_ip_scope_audit_readonly.sql`.
Janela UTC ate 21:03, cobertura de 60/60 minutos:

```text
2106 pares agregados; 8.603.648 pacotes estimados; 44.890,16 megabits estimados.
Nenhum CIDR protegido como origem OU destino.
origem 177.85/16 = 946 pares; destino 168.0/16 = 738;
destino 187.87/16 = 543; destino 177.85/16 = 445.
```

Nas categorias de IP, quase todos os pares sao
`OUTRO_IPv4 -> OUTRO_IPv4`. **Nenhum** registro
`CGNAT_100.64/10` foi identificado; somente
dois registros residuais tinham ponta RFC1918.
A hipotese de que a amostra observa principalmente
IPs CGNAT privados fica menos plausivel; isso nao
estabelece propriedade dos prefixos nem cobertura dos
links da Internet. Pode haver fluxos duplos em diferentes
interfaces e direcoes: ainda nao somar as duas pontas
para afirmar vazao de link/ataque.

Para localizar os **/24 realmente observados**, sem
exibir IP de host nem mapear assinante, foi criada
`sql/ddos_public_scope_detail_readonly.sql` (SELECT unico).
A saída limita aos 35 principais agrupamentos por prefixo,
ponta e ifIndex, sem misturar entrada/saida/direcao.

Execute no worktree isolado:

```bash
set -o pipefail
git -C /opt/orbymon-a10-audit fetch origin \
  fix/ddos-passive-reliability-20261031 &&
git -C /opt/orbymon-a10-audit show \
  FETCH_HEAD:sql/ddos_public_scope_detail_readonly.sql | mariadb orbymon
```

Se existir a tabela `orby_interface_names`, a consulta
somente leitura abaixo mostra nomes **verificados** por SNMP
ou operador (nunca supor que 86 seja uma porta especifica):

```bash
mariadb orbymon -e "
SHOW TABLES LIKE 'orby_interface_names';
SELECT if_index,if_name,updated_at FROM orby_interface_names
WHERE source='huawei' AND if_index IN (16,86,334);"
```

Se a tabela nao existir, o segundo `SELECT` falha sem
alterar dados; criar tabela ou popular ifIndex requer
processo separado e consentido. O `ifIndex=0` e ausencia
de index exportado e **nao** uma interface fisica.

Nao editar `/etc/orbymon/ddos-rules.json` ate
validar os /24 realmente roteados/administrados pelo
ISP e seu ponto de observacao (lado Internet vs lado
assinante). O resultado so demonstra presenca do
prefixo **no fluxo observado**, nao titularidade BGP.
