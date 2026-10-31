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
