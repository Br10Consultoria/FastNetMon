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
