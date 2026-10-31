# Diagnóstico de tráfego real A10 TCP/5514 — 2026-10-31

## Evidência capturada no flow

Captura PCAP clássica `LINUX_SLL2` em `-i any`, 20 segundos,
com filtro `src host 10.100.10.10 and tcp dst port 5514`.
Comandos executados em `/opt/orbymon-a10-audit`, branch
`feat/a10-tcp-framing-audit`, commit `3f0be54`.

**Resultado agregado informado pelo operador:**

| Indicador | Valor |
|---|---:|
| pacotes capturados | 69212 |
| pacotes recebidos pelo filtro | 70032 |
| pacotes descartados pelo kernel | 0 |
| cabeçalhos RFC5424 reconhecidos | 69196 |
| fronteiras coladas após `]` | 69190 |
| conexões TCP observadas | 9 |
| conexões sem SYN na captura | 5 |
| conexões sem FIN na captura | 5 |
| lacunas TCP reportadas pelo analisador | 1 |

Classificação: `concatenacao_sem_delimitador_visivel`.
`captura_tcp_completa_no_intervalo_observado: false`.
`correlacao_automatica_permitida: false`.

**Interpretação conservadora:** as mensagens RFC5424 aparecem efetivamente
coladas no tráfego TCP, antes do `rsyslog`; logo, aumentar
`global(maxMessageSize)` sozinho não criará fronteiras entre eventos.
RFC 6587 prevê comprimento em octetos ou um delimitador (frequentemente LF);
não foi observado separador visível entre as fronteiras coladas.

**Não confundir 0 drops do kernel de captura com 0 perdas fim-a-fim.**
Pacotes recebidos pelo filtro e capturados são métricas distintas do
`tcpdump`; não subtrair 70032 - 69212 para alegar perda. A amostra
de 20s intercepta conexões já abertas: falta de SYN/FIN não demonstra
perda por si só. A lacuna reportada exige avaliação e não prova perda
no A10 ou na rede sem confirmação adicional.

## Sem mudança em produção

- Não alterar NAT pools, portas de logging, `format`, `batched-logging-disable`,
  NTP, Huawei, rsyslog ou serviço ativo.
- Não usar o PCAP como fonte de logs jurídicos e não publicar seu conteúdo.
- Não habilitar parser de NAT, correlação PPPoE/RADIUS ou exclusão do raw.
- Não confundir lote de portas do CGNAT com *framing* do stream Syslog TCP.

## Próxima verificação no A10 (somente leitura)

Recolher **apenas os trechos relevantes** da saída, ocultando credenciais:

```text
show version
show running-config | include logging
show running-config | include cgnv6
show cgnv6 logging statistics
```

Além dos `include`, conferir no running-config o bloco completo de
`cgnv6 template logging ORBY_LOG_TEMPLATE`, o service-group de log e
os servidores/portas para saber a configuração efetivamente aplicada
(`include` sozinho pode omitir comandos recuados como `format`).
Antes de recomendar qualquer alteração de emissor, identificar ACOS.

Medir **diferenças**, não apenas valores acumulados, nos contadores
`Log Packets Dropped` e `TCP Connection Lost`.

## Acompanhamento de armazenamento no flow (somente leitura)

```bash
df -hT /var/log/orbymon/a10
du -sh /var/log/orbymon/a10
systemctl status orbymon-a10-logrotate.timer --no-pager
sudo -u orbymon env PYTHONPATH=/opt/orbymon/src \
  /opt/orbymon/.venv/bin/python -m fmn_filters.a10_syslog_capacity --seconds 15
```

Havia medição anterior de ~31,36 GiB/dia sem compressão, que deve
ser refeita. O disco raiz de ~95 GB não é base suficiente para
reter raw legalmente sem planejamento, compactação e arquivo durável.

## Critério técnico de continuação

1. Verificar com a versão ACOS real se é possível gerar Syslog TCP
   com framing RFC6587 adequado (LF ou octet-counting) sem efeito
   colateral; não supor que a opção exista na CLI.
2. Se ACOS não oferecer framing apropriado, projetar um **receptor
   especializado** de eventos A10 para teste isolado, com reconstrução
   por conexão TCP, validação estrita de cabeçalho/corpo e
   armazenamento raw/offset antes de qualquer evento estruturado.
3. Validar os eventos de alocação e liberação para TCP/UDP,
   reinício/reconexão, gaps, duplicação, backlog, fila e volumes reais.
4. Só depois implementar histórico e correlação com PPPoE/RADIUS,
   com controle de retenção conforme política legal e auditoria.

Fontes:
- https://www.rfc-editor.org/rfc/rfc6587
- https://docs.rsyslog.com/doc/configuration/modules/imtcp.html
- https://documentation.a10networks.com/ACOS-Docs/axapi/703/cgnv6_template_logging.html


## Inventário real do A10 — 31/10/2026, 15:18 (BRT)

Saída somente leitura fornecida pelo operador:

- Hardware: Thunder Series Unified Application Service Gateway **TH1030S**;
- Versão: **ACOS 5.2.1-P11 build 66**, de 30/07/2024;
- Relógio A10: `Oct-31-2026 15:18`, aparentemente compatível com horário do flow, ainda sem prova de offset NTP;
- `cgnv6 server ORBY_SYSLOG 187.87.201.198`;
- `cgnv6 service-group ORBY_SYSLOG tcp`;
- `cgnv6 template logging ORBY_LOG_TEMPLATE`;
- `cgnv6 lsn logging default-template ORBY_LOG_TEMPLATE`;
- `cgnv6 enable-port-batch-v1` ativo;
- `cgnv6 ddos-protection disable` e `cgnv6 ddos-protection logging disable`;
- `show running-config | include` não exibe parâmetros subordinados de template, service-group e server. **Framing e formato interno não estão auditados com essa saída**.

Contadores acumulados mais recentes:
```text
TCP Port Allocated           62276450
TCP Port Freed               62254966
UDP Port Allocated           95469644
UDP Port Freed               95446525
TCP Port Batch Allocated            0
UDP Port Batch Allocated            0
Log Packets Sent            336092243
Log Packets Dropped              2629
TCP Connection Established         15
TCP Connection Lost                30
```

Em comparação com o diagnóstico anteriormente registrado no projeto
(`Log Packets Dropped=1945` e `TCP Connection Lost=15`), os acumulados
cresceram +684 drops e +15 perdas de conexão. Não há timestamps
precisos e comparáveis para transformar isso em taxas. Também não
significa necessariamente perda de tradução NAT para cada pacote.
O A10 enviou 336 milhões de pacotes de log acumulados; esta contagem
não prova entrega/persistência pelo receptor.

### Próxima consulta, ainda sem alterações

No A10 modo `#`:
```text
show running-config | section ORBY_LOG_TEMPLATE
show running-config | section ORBY_SYSLOG
```
Se o filtro `section` não fornecer contexto, consultar o
`show running-config` localmente e copiar só blocos pertinentes;
**não expor credenciais, segredos, comunidade SNMP, chaves, senhas**.
Confirmar `format rfc5424`, serviço, opção `log port-mappings`,
`batched-logging-disable`, e porta do servidor no bloco completo.

A documentação de aXAPI para ACOS 5.2.1-P5 descreve `format`,
`log.port-mappings`, `batched-logging-disable` e `service-group`,
mas não comprova opção CLI que adicione delimitadores a Syslog TCP
neste firmware. No RFC6587, o Syslog sobre TCP precisa de
octet-counting ou delimitador. Não converter o `batch` de portas
NAT (`enable-port-batch-v1`) em hipótese de framing de mensagens;
são mecanismos distintos.

Documentação consultada:
- https://documentation.a10networks.com/ACOS-Docs/axapi/521p5/cgnv6_template_logging.html
- https://www.rfc-editor.org/rfc/rfc6587
- https://documentation.a10networks.com/docs/ACOS/521x/5-2-1-P11/

### Observação de segurança

O login de gerenciamento foi feito por `telnet`, sem cifragem
em trânsito. Planejar migração de gerenciamento para SSH,
sem desabilitar Telnet antes de validar acesso alternativo.


## Template confirmado no equipamento (31/10/2026)

Consulta `show running-config | section ORBY_LOG_TEMPLATE`:

```text
cgnv6 template logging ORBY_LOG_TEMPLATE
  format rfc5424
  service-group ORBY_SYSLOG
cgnv6 lsn logging default-template ORBY_LOG_TEMPLATE
```

**Conclusões:** o formato RFC5424 está explicitamente definido, o
template está ativo como default do LSN e a saída não contém opção
explícita `batched-logging-disable`. Isso não prova se a opção está
atuando por default no patch P11, e o comportamento de batching de
mensagens difere do `cgnv6 enable-port-batch-v1`. O fato de os
eventos aparecerem concatenados no *wire* justifica investigar o
enquadramento de aplicação RFC6587 sem mudar a operação do CGNAT.

A documentação A10 de aXAPI ACOS 5.2.1-P5 descreve o default
`batched-logging-disable=0`; um guia oficial posterior (ACOS 7.0.1)
diz que batching de log não se aplica a `format rfc5424`. Esse
comportamento do P11 ainda **não foi confirmado** no equipamento.
Não recomendar habilitar `batched-logging-disable` em produção para
resolver concatenação de TCP; nem envio TCP unitário garante leitura
unitária pelo receptor.

Próxima consulta **somente leitura**:
```text
show running-config | section ORBY_SYSLOG
```

Depois é possível avançar o diagnóstico no coletor, isolado de
produção, com detecção segura de cabeçalhos RFC5424 e verificação
estrita de completude de eventos; **sem associar assinantes
automaticamente e sem remover logs brutos**.

Fontes:
- https://documentation.a10networks.com/ACOS-Docs/axapi/521p5/cgnv6_template_logging.html
- https://documentation.a10networks.com/ACOS/701x/ACOS_7.0.1/pdf/Traffic_Logging_for_IPv6_Migration.pdf


## Classificação efetiva dos eventos RFC5424 — 31/10/2026

Auditoria realizada no servidor flow com `HEAD=a86f4df` e com a mesma
captura PCAP de 20 segundos. A opção `--audit-nat-candidates`
produziu somente estatísticas:

| Tipo | Quantidade |
|---|---:|
| LSN PortAllocated TCP | 12646 |
| LSN PortFreed TCP | 13113 |
| LSN PortAllocated UDP | 19720 |
| LSN PortFreed UDP | 19798 |
| Outros marcadores LSN classificados como ICMP | 3913 |
| **Total dos eventos delimitados heuristicamente** | **69190** |
| Eventos finais sem cabeçalho seguinte | 6 |

`65277/69190=94,34%` são candidatos NAT TCP/UDP que passam na
validação estrutural dos pools/portas. Todos os `3913` restantes
foram classificados por marcador **ICMP** (`5,66%`). Não houve
eventos indefinidos nos trechos analisados. **Isso não valida
o conteúdo/mapeamento ICMP**.

Revisão de integridade: `conexoes_observadas=9`, `lacunas_tcp=1`,
`conexoes_sem_syn_na_captura=5`,
`conexoes_sem_fin_na_captura=5` e
`captura_tcp_completa_no_intervalo_observado=false`.
`correlacao_automatica_permitida=false`.

**Não interpretar** diferença entre `allocated=32366` e
`freed=32911` como 545 eventos perdidos; sessões podem iniciar
antes e terminar depois da janela. Da mesma forma, 0 pacotes
descartados pelo kernel tcpdump não implica perda zero entre A10,
transporte e persistência de Syslog.

Este resultado encerra a **classificação de marcadores da amostra**,
não a homologação de integridade do logging CGNAT. O próximo passo
é comparar contadores cumulativos do A10 em intervalos definidos,
analisar as lacunas e projetar recepção com framing auditável antes
de registrar traduções históricas.


## Localização anônima da lacuna TCP — captura 20s, revisão 6c2469e

Informações fornecidas pelo servidor flow (sem payload):

| Métrica | Valor |
|---|---:|
| Conexão por índice observacional no PCAP | 3 |
| Segmentos TCP com dados nessa conexão | 13768 |
| Trechos contíguos nessa conexão | 2 |
| Lacunas entre trechos | 1 |
| Bytes ausentes nessa lacuna | **123** |
| SYN observado na conexão | não |
| FIN observado | não |
| RST observado | não |

Todos os nove fluxos observados no PCAP tiveram **0 RST**
(`conexoes_com_rst=0`). Cinco fluxos não apresentaram SYN no
recorte e cinco não apresentaram FIN; isso é esperado em capturas
curtas e não prova resets nem perda no equipamento.

**Interpretação conservadora:** a lacuna de 123 bytes significa que
um intervalo TCP não foi reconstruído com os segmentos disponíveis na
captura, não que exatamente uma alocação NAT foi perdida. Não existe
relação comprovada entre um pacote TCP e um evento Syslog neste fluxo.
O `tcpdump` informou zero drops pelo kernel, mas isso não elimina
outras razões para faltar um segmento no PCAP. A causa não foi
determinada com esta amostra.

### Inspeção de bordas por conexão, sem revelar dados

A branch adicionou `src/fmn_filters/a10_tcp_gap_edges.py` e
`contexto_estrutural_das_lacunas` ao relatório. O teste identifica,
para cada lacuna em segmentos TCP, somente se:

- bytes capturados antes da lacuna terminam com `]` (registro
  aparentemente encerrado);
- bytes capturados após a lacuna começam com cabeçalho RFC5424;
- existe um cabeçalho seguinte e quantos bytes precedem esse
  primeiro cabeçalho (contagem numérica);
- os eventos adjacentes são sempre **não homologados**.

Esses indicadores são heurísticos. Não mostram IPs de assinante,
portas traduzidas, quatro-tuplas TCP ou timestamps das mensagens.

A próxima revisão em produção depende de leituras em dois instantes
do `show cgnv6 logging statistics`, para avaliar o crescimento dos
contadores `Log Packets Dropped` e `TCP Connection Lost`.
Mantemos `correlacao_automatica_permitida=false`,
sem mudar o serviço TCP/5514 nem o CGNAT.


## Alinhamento das bordas da lacuna — 31/10/2026

A última auditoria real do flow (commit `32fb522`) verificou
a lacuna de 123 bytes da conexão TCP #3:

```text
trecho_anterior_termina_colchete: true
trecho_seguinte_inicia_cabecalho_rfc5424: true
trecho_seguinte_tem_cabecalho_rfc5424: true
bytes_antes_do_primeiro_cabecalho_seguinte: 0
eventos_adjacentes_nao_homologados: true
```

É possível que a lacuna contenha um evento inteiro, mas sem
quadro/ACKs de sentido inverso e sem comprovação de entrega pelo
rsyslog, isso é somente uma hipótese. Não afirmar perda efetiva
de um registro NAT ou culpa do A10.

### Prototipagem de replay sem produção

A branch inclui `a10_rfc5424_replay.py` e
`--audit-offline-replay` em `a10_tcp_framing`, para comparar
o reconhecedor existente com um decodificador incremental que
recebe blocos arbitrários, mantém buffer limitado e descarta
trechos finais em cada lacuna. **Nunca persiste traduções NAT,
não muda rsyslog/A10 e não liga associação de assinantes**.

A execução e interpretação ficam em
`docs/A10_TCP_PCAP_PROBE.md`.


## Replay incremental real homologado como prova de conceito offline

A execução fornecida pelo operador no `flow`, com
`HEAD=787b3f9` e `--audit-nat-candidates --audit-offline-replay`,
apresentou equivalência entre os dois algoritmos de
**contagem estrutural de candidatos**, para a mesma amostra
de 20 segundos:

| Evento | Auditoria direta | Replay incremental |
|---|---:|---:|
| PortAllocated TCP | 12646 | 12646 |
| PortFreed TCP | 13113 | 13113 |
| PortAllocated UDP | 19720 | 19720 |
| PortFreed UDP | 19798 | 19798 |
| ICMP (apenas marcador) | 3913 | 3913 |
| **Eventos com fronteira candidata** | **69190** | **69190** |

O replay processou `8385236` bytes e reportou
`replay_trechos_fechados=6`,
`replay_eventos_finais_sem_fronteira_confiavel=6`.
Não houve campo `replay_buffers_acima_do_limite` no relatório,
portanto o contador de estouros registrado é zero nesta execução.

A análise manteve a lacuna TCP de 123 bytes na conexão #3:
**nenhum dado ausente foi preenchido, inferido ou persistido**.

**Status desta etapa: prova de conceito de classificação incremental
offline validada por contagens coincidentes na amostra**. Não é um
receptor TCP real, não garante enquadramento RFC6587, não valida
entrega fim a fim nem integridade/retencão dos logs CGNAT.
Mantenha `correlacao_automatica_permitida=false`.

## Encerramento da fase PCAP e próxima evidência independente

Não solicitar sucessivas reexecuções da mesma captura. Para avançar
à qualificação operacional sem interromper os clientes:

1. Registrar duas leituras de `show cgnv6 logging statistics`
   no A10, com intervalo **realmente cronometrado** de ~60s.
2. Usar `a10_logging_health.py` ou calcular manualmente
   as diferenças dos contadores `Log Packets Dropped`,
   `TCP Connection Lost` e `Log Packets Sent`.
3. Conferir disponibilidade e capacidade do receptor atual,
   espaço em disco e rotacão dos logs brutos.
4. Só então desenhar ingestão durável com comprovacão de
   enquadramento, fila/backpressure, cortes nas reconexões,
   idempotência, reconciliacão e política legal de retenção.

A etapa seguinte **não** deve mudar `cgnv6`,
`batched-logging-disable`, `rsyslog` ativo ou porta TCP/5514
enquanto o receptor alternativo não tiver sido testado de forma
isolada com failover/rollback definido.


## 31/10/2026 — duas leituras de contadores A10 (16:12:46 a 16:13:59, BRT)

O operador enviou duas saídas de `show clock` +
`show cgnv6 logging statistics`. A distância entre os horários
é de **73 segundos**; as consultas de estatísticas ocorreram logo
após os comandos de relógio, portanto as taxas por segundo são
**aproximadas** ao considerar 73s como o intervalo de amostragem.

| Contador | Primeiro | Segundo | Delta |
|---|---:|---:|---:|
| TCP Port Allocated | 64473214 | 64522289 | 49075 |
| TCP Port Freed | 64451447 | 64501236 | 49789 |
| UDP Port Allocated | 98746827 | 98817707 | 70880 |
| UDP Port Freed | 98724267 | 98797250 | 72983 |
| ICMP Resource Allocated | 10655007 | 10662314 | 7307 |
| ICMP Resource Freed | 10654962 | 10662317 | 7355 |
| Log Packets Sent | 347702775 | 347960164 | **257389** |
| Log Packets Dropped | 2629 | 2629 | **0** |
| TCP Connection Established | 15 | 15 | **0** |
| TCP Connection Lost | 30 | 30 | **0** |

- **Soma dos 6 deltas de eventos NAT: 257389**;
- **Delta Log Packets Sent: 257389**;
- Diferença: **0**; os contadores internos do A10 se reconciliam
  exatamente nesta janela.
- Taxa aproximada de `Log Packets Sent`: **3525,88/s**.
- Nenhum novo `Log Packets Dropped` ou
  `TCP Connection Lost` foi contabilizado.

**Interpretação:** existe evidência forte de consistência entre a
contabilização interna dos eventos NAT e do envio de logs do A10
nessa janela. Não significa que cada registro se transformou
em um pacote físico TCP distinto, nem comprova que os eventos
chegaram ao rsyslog, foram persistidos no arquivo NDJSON ou
foram retidos com integridade.

A captura offline anterior permanece com lacuna de 123 bytes
e framing RFC5424 concatenado sem delimitador RFC6587 detectado.
Essa lacuna não foi "resolvida" por esta medição e não podemos
atribuí-la automaticamente a falha do emissor. Também não há
evidência nova de impacto no tráfego de clientes.

A função `a10_logging_health.reconcile_log_sent_with_events`
foi acrescentada para verificar automaticamente essa igualdade
em futuros intervalos, retornando estado inconclusivo se
faltar um contador opcional e recusando taxas em caso de
reinício/wrap. Mantém `integridade_do_logging_comprovada=false`.

### Próximo teste distinto — saúde do receptor flow, sem restart

Executar exclusivamente consultas no servidor flow:
```bash
systemctl is-active rsyslog
sudo ss -lntp '( sport = :5514 )'
sudo systemctl --no-pager --full status rsyslog
df -hT /var/log/orbymon/a10
sudo du -sh /var/log/orbymon/a10
sudo stat -c '%n %s bytes alterado=%y' /var/log/orbymon/a10/a10-current.ndjson
sudo systemctl status orbymon-a10-logrotate.timer --no-pager
```
Esses comandos não revelam mapeamentos NAT, não alteram o
A10 e não reiniciam o rsyslog. O diretório pode conter arquivos
sensíveis: **não compartilhar conteúdo de NDJSON**.


## 31/10/2026, 16:18 BRT — estado do receptor flow

Leitura somente de metadados fornecida pelo operador:

| Verificação | Resultado |
|---|---|
| `systemctl is-active rsyslog` | `active` |
| `ss -lntp '( sport = :5514 )'` | `0.0.0.0:5514 LISTEN`, `rsyslogd`, Recv-Q=0 |
| `df -hT /var/log/orbymon/a10` | ext4 raiz 96G; 16G usados; 76G livres; 18% |
| `du -sh /var/log/orbymon/a10` | 5,7G |
| Arquivo atual `a10-current.ndjson` | 456276719 bytes (~435,1 MiB) |
| Última modificação do arquivo atual | 2026-10-31 16:18:21 -03 |
| `systemctl is-active orbymon-a10-logrotate.timer` | `active` |

**Interpretação:** o daemon do receptor e o socket TCP estavam ativos
e o arquivo registrou modificação recente. Isso não prova chegada
dos 257389 eventos contabilizados pelo A10 no intervalo anterior.

O repositório instala o timer com `OnCalendar=hourly` e a regra
`maxsize 128M` para logrotate. **Este valor é limiar avaliado
somente quando logrotate executa**, não tamanho máximo contínuo
do arquivo. O arquivo atual estar ~435 MiB não demonstra por si
só falha do logrotate. A condição `active` do timer tampouco
comprova que a última execução da unidade `.service` deu certo.

A configuração gerada pelo instalador usa `rotate -1`
(retém arquivos rodados), `compress`, `delaycompress`,
sem remoção automática. Com disco finito, o acervo crescerá até
precisar de capacidade adicional/arquivamento durável.

Medição anterior de ~31,36 GiB/dia raw sugere que os 76 GiB
livres, **sem compressão e se a taxa for constante**, equivalem
a apenas ~2,42 dias. Não é previsão real de esgotamento;
é uma estimativa provisória. É preciso considerar compressão,
outros arquivos e taxa atual medida. Não excluir logs CGNAT.

### Verificações seguintes sem restart nem risco à coleta

No flow:

```bash
systemctl list-timers --all orbymon-a10-logrotate.timer
systemctl show orbymon-a10-logrotate.service \
  -p Result -p ExecMainStatus -p ExecMainStartTimestamp -p ExecMainExitTimestamp
journalctl -u orbymon-a10-logrotate.service --since today --no-pager -n 30
sudo sed -n '1,60p' /etc/logrotate.d/orbymon-a10
sudo env PYTHONPATH=/opt/orbymon-a10-audit/src \
  python3 -m fmn_filters.a10_storage_inventory
sudo env PYTHONPATH=/opt/orbymon/src \
  python3 -m fmn_filters.a10_syslog_capacity --seconds 15
```

`a10_storage_inventory` reporta apenas quantidades/tamanhos de
arquivos ativos/rodados/comprimidos e espaço disponível; não lê
payload, IPs ou portas dos assinantes. Não verifica execuções
systemd. `a10_syslog_capacity` mede crescimento durante 15s,
mas descarta o resultado se o arquivo for rotacionado no período;
é taxa raw sem compressão.

Não alterar periodicidade/limites da rotação nem reiniciar rsyslog
até conferir a execução real e disponibilidade de armazenamento.
Se o disco se aproximar de seu limite, priorizar adicionar
armazenamento ou arquivamento com retenção verificada; não apagar
dados CGNAT por automação improvisada.


## 31/10/2026 16:21–16:22 BRT — diagnóstico concluído da rotação e capacidade

O operador realizou nova leitura no flow, com resultados:

- `systemctl list-timers`: última execução às **16:00:02 -03**,
  próxima às **17:00:00 -03**, timer habilitado e agendado;
- `systemctl show ...`: **Result=success**, `ExecMainStatus=0`,
  execução das 16:00:02 às 16:00:55;
- `journalctl`: rotações das 10h, 11h, 12h, 13h, 14h,
  15h e 16h terminaram com sucesso. As últimas consomem
  aproximadamente 45–55 segundos de tempo de CPU;
- `a10_storage_inventory`: **29 arquivos comprimidos**, total
  **3,594 GiB**; **2 arquivos rotacionados não comprimidos**,
  **1,600 GiB**; arquivo ativo **0,514 GiB**;
  total **5,708 GiB** em 32 arquivos. O diretório está ativo
  (última alteração ocorreu no momento da coleta);
- `df`: disco com **95,407 GiB** no total, **74,981 GiB**
  livres (78,59% livre);
- `a10_syslog_capacity --seconds 15`:
  **6.562.300 bytes em 15,001 s**, `valid=true`,
  taxa bruta projetada **35,2 GiB/dia**, ~**2,13 dias**
  se o restante de disco recebesse somente logs **sem compressão**.

**Resultado:** não existe evidência de falha atual do timer,
do rsyslog ou da rotação. O arquivo ativo com mais de
128 MiB é compatível com a execução **horária**: `maxsize`
é avaliado somente na execução do logrotate; não é um
limite contínuo de tamanho.

**Risco pendente:** `rotate -1` mantém os arquivos sem
remoção, mesmo com `compress` e `delaycompress`.
A previsão de 2,13 dias é **conservadora e não representa o
crescimento líquido real com compressão**. Não é correto
inferir retenção de 30 dias ou taxa de compressão a partir
das categorias de 32 arquivos em um instante isolado.
O fluxo de logs é elevado: acompanhar disco e consumo de
CPU da rotação; não alterar política ou excluir arquivos
sem definir armazenamento/retencão adequada.

### Medir crescimento líquido efetivo incluindo compressão (somente leitura)

A branch adicionou `a10_storage_trend.py` e timestamps em
`a10_storage_inventory.py`. Recomendação: duas leituras
com **pelo menos 1 hora, preferivelmente 2–3 horas**
de diferença para atravessar rotações, salvo-se o histórico
de metadados como JSON em diretório administrativo protegido.

```bash
sudo install -d -m 0700 /root/orbymon-audit
sudo env PYTHONPATH=/opt/orbymon-a10-audit/src \
 python3 -m fmn_filters.a10_storage_inventory \
 > /root/orbymon-audit/antes.json
# Repetir o comando abaixo após pelo menos 2 horas:
sudo env PYTHONPATH=/opt/orbymon-a10-audit/src \
 python3 -m fmn_filters.a10_storage_inventory \
 > /root/orbymon-audit/depois.json
sudo env PYTHONPATH=/opt/orbymon-a10-audit/src \
 python3 -m fmn_filters.a10_storage_trend \
 --before /root/orbymon-audit/antes.json \
 --after /root/orbymon-audit/depois.json
```

Os snapshots contêm somente contagens, tamanhos, horários e
uso de disco, **não** conteúdo de assinantes. O comparador
mede crescimento *líquido* dos arquivos após rotações
e compactações ocorridas no intervalo; não confundir com
geração bruta e não extrapolar janelas curtas ou onde houve
remoção/alteração de arquivos. O forecast é apenas indicativo.
Não apaga nada nem altera configuração de produção.
