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
