# A10: verificar o enquadramento TCP original sem mudar o CGNAT

O `rsyslog` atualmente salva mensagens A10 no TCP/5514 em blocos NDJSON, alguns com `rawmsg` de 65.536 bytes, que contêm vários cabeçalhos RFC5424 concatenados. Isso **não** é prova de delimitação, continuidade, nem integridade jurídica. O diagnóstico sobre os arquivos gravados não substitui a inspeção do stream TCP original.

## Escopo deste incremento

`src/fmn_filters/a10_tcp_framing.py` lê uma **captura PCAP clássica local**, reconstruindo trechos TCP pela sequência de bytes. Não envia rede, não muda A10, Huawei, rsyslog, firewall ou MariaDB e não imprime IP/porta/payload de assinantes. Contabiliza:

- Mensagens RFC5424 que aparecem coladas após `]`, separadas por LF/NUL ou com prefixos de comprimento RFC6587;
- Prefixos octet-counting cujo comprimento coincide com o próximo frame;
- Retransmissões, lacunas, sobreposições conflitantes, truncamento por snaplen, ausência de SYN/FIN na captura;
- Limites de leitura para impedir consumo excessivo de RAM.

Suporta PCAP clássico Ethernet (incluindo VLAN), Linux SLL, Linux SLL2 (`tcpdump -i any`) e RAW IPv4. Não suporta pcapng, IPv6 ou fragmentação IP. Reenvios, perda durante captura e mensagens incompletas impedem declarar continuidade segura. A análise é **indicativa** mesmo quando a captura parece completa.

## Execução no servidor flow, com supervisão

Sem reiniciar o rsyslog e sem alterar o A10, capture por intervalo curto em local de acesso restrito. O arquivo contém **dados sigilosos de NAT** e deve permanecer no próprio servidor:

```bash
cd /opt/orbymon
git pull --ff-only origin main
sudo bash -c 'umask 077; timeout 20 tcpdump -i any -s 0 -B 4096 \
  -w /root/a10-framing-local.pcap "src host 10.100.10.10 and tcp dst port 5514"'
```

A saída do `timeout` pode ser 124 (normal ao completar o intervalo). Se não houver `tcpdump`, verifique instalação antes de coletar. O buffer do `tcpdump` e o armazenamento devem ser acompanhados; informe perdas de pacotes mostradas por ele, pois uma captura com perda é inconclusiva.

```bash
sudo env PYTHONPATH=/opt/orbymon/src \
  /opt/orbymon/.venv/bin/python -m fmn_filters.a10_tcp_framing \
  --pcap /root/a10-framing-local.pcap --source-ip 10.100.10.10 --port 5514
```

Compartilhe **somente o JSON agregado**, nunca o arquivo PCAP ou as linhas brutas. Proteja e descarte a captura de forma segura conforme sua política operacional; a ferramenta não remove evidências automaticamente. O diagnóstico não gera nem valida um histórico de NAT.

Se a conexão TCP já estiver aberta antes da captura, normalmente `conexoes_sem_syn_na_captura > 0`. Não reinicie rsyslog ou A10 apenas para obter SYN; qualquer reconexão precisa de janela supervisionada devido ao risco de perda de logs.

## Interpretação

- `concatenacao_sem_delimitador_visivel`: cabeçalhos RFC5424 colados no mesmo stream, como `]` seguido de `<PRI>1`. Prioridade é corrigir/homologar framing; **não** separar e gravar traduções NAT automaticamente.
- `octet_counting_compativel_na_amostra`: prefixos de comprimento e offsets coerentes. Exige validação adicional do emissor, da continuidade e do armazenamento.
- `delimitacao_lf_ou_nul_compativel_na_amostra`: alguns cabeçalhos aparecem após delimitadores; conferir todas as conexões, falhas e a recepção efetiva no rsyslog.
- `inconclusivo`: amostra insuficiente, não reconhecida ou sem delimitadores demonstráveis.

`captura_tcp_completa_no_intervalo_observado` é **apenas um indicador local da amostra**, não prova entrega contínua dos eventos, sincronização de relógios, devida gravação, fechamento de sessões ou atendimento legal. `correlacao_automatica_permitida` permanece sempre `false`.

## Próximo bloqueio para habilitar histórico pesquisável

Confirmar o framing no wire e a compatibilidade de configuração da versão **ACOS instalada**; medir diferenças dos contadores acumulados `Log Packets Dropped` e `TCP Connection Lost`; registrar lacunas e perdas do rsyslog, e testar reinício/rotação; só então definir um parser validado para `LSN:PortAllocated`/`LSN:PortFreed` com idempotência, retenção protegida e correlação temporal posterior com PPPoE/RADIUS. Não ativar log de todas as sessões ou `batched-logging-disable` sem estudo de impacto.


## Segunda etapa: auditoria estrutural dos candidatos NAT (somente leitura)

Depois de validar o transporte e identificar a cadeia ativa
`ORBY_LOG_TEMPLATE` -> `ORBY_SYSLOG` ->
`187.87.201.198:5514/TCP`, pode-se medir quais eventos TCP/UDP
`LSN:PortAllocated` e `LSN:PortFreed` estão sintaticamente completos
**dentro da captura local já realizada**.

Atualizar **somente** o worktree de auditoria:
```bash
git -C /opt/orbymon-a10-audit fetch origin feat/a10-tcp-framing-audit
git -C /opt/orbymon-a10-audit switch --detach FETCH_HEAD
```

Executar sem alterar o rsyslog nem os logs históricos:
```bash
sudo env PYTHONPATH=/opt/orbymon-a10-audit/src \
  python3 -m fmn_filters.a10_tcp_framing \
  --pcap /root/a10-framing-local.pcap \
  --source-ip 10.100.10.10 --port 5514 \
  --audit-nat-candidates
```

Campos adicionais começam por `candidate_`:
- `candidate_nat_sintaticamente_candidato` conta eventos com um único marcador TCP/UDP, intervalo entre dois cabeçalhos RFC5424, endereços/portas nos pools conhecidos e fechamento `]`;
- `candidate_nat_sem_terminador`, `candidate_marcadores_ambiguos`,
  `candidate_nat_mapeamento_invalido_ou_fora_pool` descrevem motivos
  de rejeição;
- `candidate_ultimo_evento_sem_fronteira_comprovada` reflete
  eventos terminais não confirmados no recorte da captura.

**Atenção:** ainda que `candidate_nat_sintaticamente_candidato` seja alto,
o método usa detecção heurística de cabeçalhos, **não** framing RFC6587
comprovado; `captura_tcp_completa_no_intervalo_observado` pode ser
`false` por conexões abertas e gaps. Nenhum evento é salvo, nenhum
usuário é identificado, nenhum vínculo é homologado e a flag
`correlacao_automatica_permitida` permanece `false`. A porcentagem
de candidatos aceitos não é taxa de entrega comprovada.

Depois deste teste, a evolução planejada é um coletor experimental
com framing verificável, controle de continuidade por conexão e
fila durável, sem interromper a porta TCP 5514 atual.


## 31/10/2026: segunda execução com dados reais

A saída do flow, utilizando o PCAP de 20 segundos e a flag
`--audit-nat-candidates`, foi:

- `candidate_cabecalhos_detectados=69196`;
- `candidate_eventos_delimitados_por_outro_cabecalho=69190`;
- `candidate_nat_sintaticamente_candidato=65277`;
- `candidate_outro_tipo_ou_sem_nat_tcp_udp=3913`;
- `candidate_ultimo_evento_sem_fronteira_comprovada=6`;
- `lacunas_tcp=1`, `captura_tcp_completa_no_intervalo_observado=false`.

O percentual `65277/69190 = 94,34%` representa exclusivamente a
proporção de candidatos NAT sintaticamente reconhecidos **entre os
eventos delimitados heuristicamente por outro cabeçalho**. Os 3913
restantes podem ser ICMP, controle ou outros formatos; **não são
3913 erros nem 3913 perdas comprovadas**. Os seis últimos eventos
de trechos não têm cabeçalho seguinte e não foram classificados.

### Terceira iteração: detalhamento sem conteúdo sensível

Foi incluída decomposição automática, dentro do mesmo modo
`--audit-nat-candidates`, utilizando somente nomes fixos. Atualize
o worktree de testes (`/opt/orbymon-a10-audit`) e rode novamente
o comando acima sobre **o mesmo PCAP**, sem reconfigurar serviços.

Novos grupos de contadores:
- `candidate_detalhe_nat_allocated_tcp`,
  `candidate_detalhe_nat_freed_tcp`,
  `candidate_detalhe_nat_allocated_udp` e
  `candidate_detalhe_nat_freed_udp`: tipo de candidato NAT validado
  estruturalmente.
- `candidate_detalhe_outro_lsn_icmp`,
  `candidate_detalhe_outro_lsn_gre`,
  `candidate_detalhe_outro_lsn_esp`,
  `candidate_detalhe_outro_lsn_lote_portas`,
  `candidate_detalhe_outro_lsn_sessao`,
  `candidate_detalhe_outro_lsn_outro_marcador` e
  `candidate_detalhe_outro_sem_marcador_lsn`: grupos
  predefinidos de eventos não reconhecidos como NAT TCP/UDP.

As somas dos quatro detalhes NAT e dos sete detalhes `outro_`
devem bater com seus respectivos totais quando todos os formatos
seguirem as categorias testadas. Marcadores desconhecidos não são
exibidos como texto e não se gravam traduções.

**Continua read-only:** não prova ausência de lacunas no stream,
não valida duração de alocações e não libera correlação com PPPoE.


## 31/10/2026 — Verificação de lacunas e perdas do A10

Depois de confirmar que os `3913` eventos não-TCP/UDP da
captura são marcadores `LSN:ICMP` (os demais `65277`
candidatos são eventos PortAllocated/PortFreed TCP/UDP),
foram adicionados dois diagnósticos **somente leitura**:

1. O auditor PCAP reporta `lacunas_tcp_bytes` (soma das
   lacunas entre segmentos de uma mesma conexão TCP) e
   `lacunas_tcp_inicio_bytes` (bytes iniciais não capturados
   em conexões cujo SYN foi observado). Lacuna em PCAP não prova
   perda no A10 ou no rsyslog; não publicar payload nem pacotes.
2. `python3 -m fmn_filters.a10_logging_health` compara
   **duas** saídas de `show cgnv6 logging statistics`
   tomadas em um intervalo cronometrado. Analisa somente campos
   numéricos conhecidos, detecta reset/wrap de contadores e
   informa incrementos de `Log Packets Dropped` e
   `TCP Connection Lost`. Não faz Telnet/SSH, não altera A10
   e não lê logs de assinantes.

Para comparar duas leituras, salve *apenas* a saída de
`show cgnv6 logging statistics` em dois arquivos locais
restritos, obtidas em um intervalo medido (por exemplo, 60s):
`/root/a10-before.txt` e `/root/a10-after.txt`.
Sem automação de login nem inclusão de credenciais no texto.

```bash
sudo env PYTHONPATH=/opt/orbymon-a10-audit/src python3 \
  -m fmn_filters.a10_logging_health \
  --before /root/a10-before.txt --after /root/a10-after.txt \
  --seconds 60
```

Use o intervalo efetivamente medido; não utilize 60 se houve
mais ou menos tempo. Os números de `Log Packets Sent` e
`Log Packets Dropped` se referem a **pacotes de logging**,
não a um evento NAT individual, e não comprovam entrega,
integridade histórica ou correlação PPPoE/RADIUS.

Para verificar as lacunas do PCAP anterior (sem nova captura),
atualize o worktree de auditoria e rode novamente
`a10_tcp_framing --audit-nat-candidates`. São adicionados
os campos `lacunas_tcp_bytes` e
`trechos_tcp_contiguos` sem imprimir tráfego.


## 31/10/2026 — lacuna TCP de 123 bytes localizada na auditoria

Nova leitura do flow, usando a mesma captura de 20 segundos,
commit `6a00a9b`:

- `lacunas_tcp=1`, `lacunas_tcp_bytes=123`;
- `trechos_tcp_contiguos=6`;
- `conexoes_observadas=9`, 5 sem SYN e 5 sem FIN na captura;
- `candidate_nat_sintaticamente_candidato=65277` e
  `candidate_detalhe_outro_lsn_icmp=3913`.

A lacuna é um **intervalo de bytes ausentes da sequência capturada e
reconstruída**, não necessariamente perda no emissor, enlace ou rsyslog.
Zero drops no `tcpdump` não elimina falhas na captura nem no Syslog.
Uma mensagem RFC5424 concatenada não equivale necessariamente a um
registro individual confiável para fins históricos.

### Nova ferramenta de localização por conexão (sem conteúdo)

O auditor atualizado agora produz `diagnostico_de_lacunas_por_conexao`:
somente índice anônimo da conexão **na ordem de observação no PCAP**,
quantidade de bytes faltantes, número de trechos, observação de SYN/FIN/RST
e número de segmentos com payload. Não inclui IPs, portas, sequências
TCP, timestamps de assinantes nem payload. Também conta
`conexoes_com_rst` e `conexoes_sem_fin_nem_rst_na_captura`.

Não interpretar RST como causa isolada de perda. A existência de RST
no PCAP não garante que a aplicação perdeu mensagens; ausência de FIN
em captura curta tampouco demonstra desconexão.

Após atualizar o **worktree de auditoria**, não a produção:
```bash
git -C /opt/orbymon-a10-audit fetch origin feat/a10-tcp-framing-audit
git -C /opt/orbymon-a10-audit switch --detach origin/feat/a10-tcp-framing-audit
sudo env PYTHONPATH=/opt/orbymon-a10-audit/src \
 python3 -m fmn_filters.a10_tcp_framing \
 --pcap /root/a10-framing-local.pcap --audit-nat-candidates
```

Não apague o PCAP até terminar a análise aprovada pela política de
evidências. Não compartilhe o PCAP nem arquivos NDJSON brutos.


## Modo de diagnóstico seguro das bordas da lacuna (após 6c2469e)

A captura local de 20 segundos informou **1 lacuna com 123 bytes**
na **conexão 3**, com 13768 segmentos de payload, 2 trechos TCP
contíguos e nenhum SYN/FIN/RST capturado nessa conexão.

O auditor offline agora apresenta, dentro de
`diagnostico_de_lacunas_por_conexao`:
`contexto_estrutural_das_lacunas`, uma lista limitada de
indicadores booleanos sobre os bytes **imediatamente adjacentes**
a cada lacuna. Não mostra o texto dos eventos, endereços ou portas.
Nada é considerado prova de integridade ou de perda no emissor.

Atualizar exclusivamente o worktree de testes:
```bash
git -C /opt/orbymon-a10-audit fetch origin feat/a10-tcp-framing-audit
git -C /opt/orbymon-a10-audit switch --detach origin/feat/a10-tcp-framing-audit
sudo env PYTHONPATH=/opt/orbymon-a10-audit/src \
  python3 -m fmn_filters.a10_tcp_framing \
  --pcap /root/a10-framing-local.pcap --audit-nat-candidates
```

Interpretação: se `trecho_anterior_termina_colchete=true` e
`trecho_seguinte_inicia_cabecalho_rfc5424=true`, a lacuna está
entre fronteiras **aparentemente** alinhadas, mas pode conter
um ou vários eventos ausentes. Se forem `false`, a lacuna
pode ter partido um evento; não reconstruir conteúdo ausente.
Em ambos os casos, `eventos_adjacentes_nao_homologados=true`
e `correlacao_automatica_permitida=false`.

Depois deste diagnóstico não é necessário repetir a mesma captura
para obter novas contagens; prosseguir com verificações independentes
de emissão/recepção antes de criar histórico CGNAT.
