# OrbyMon: NTP A10 e armazenamento separado de CGNAT

## Diagnostico confirmado em 2026-10-30

- A10 Thunder: `show clock detail` informou hardware calendar, sem servidor NTP.
- Gateway Huawei ligado ao A10: 10.100.10.9; IP de origem do A10: 10.100.10.10.
- O servidor flow estava NTP sincronizado, timezone America/Bahia.
- Coletor registrou delta de ~10.238 segundos entre timestamp do A10 e recebimento.
  Isso pode incluir atraso de fila e nao eh medida NTP exata.
- A10 registrou 1.945 Log Packets Dropped e 15 TCP Connection Lost:
  **contadores acumulados**, requerem diferenca entre duas amostras.
- Raw Syslog apresentou 8.096 bytes fixos por rawmsg, com fragmentos de
  cabeçalho; antes de correlacionar NAT deve-se corrigir framing e clocks.
- Crescimento medido: 11.693.507 bytes / 30s (~31,36 GiB/dia, sem compressao).
- A10 usa pools públicos NAT-POOL-08/09/10/11 e rede 100.64.64.0/19.

## 1. Sincronizacao NTP A10

O A10 esta quase 3h atrasado. **Programar janela supervisionada** e registrar
um marcador temporal da transicao: ajuste de varias horas pode causar
lacunas/ordem anomala nos logs e afetar operacao dependente de timeouts.
Nao usar `clock set` manual, nao alterar timezone -03 ou relógio do flow.

NTP.br publica a.ntp.br, b.ntp.br, c.ntp.br:
- a.ntp.br = 200.160.0.8
- b.ntp.br = 200.189.40.8
- c.ntp.br = 200.192.232.8

Validar acesso UDP/123 e via de saida do ACOS antes de habilitar.
Exemplo para sintaxe ACOS com submodo por servidor; verificar `show version`,
`ntp ?` e `ntp server ?` no firmware efetivamente instalado:

    enable
    configure
    ntp server 200.160.0.8
      prefer
    exit
    ntp server 200.189.40.8
    exit
    ntp server 200.192.232.8
    exit
    exit
    show ntp status
    show ntp servers
    show clock detail

Algumas versões antigas exigem `ntp server enable` no modo config;
nao executar sem confirmar sintaxe por CLI. Apos sincronizacao, salvar
`write memory`. Se NTP nao sincronizar, verificar interface/rota,
gateway 10.100.10.9, DNS (se usar hostname), UDP/123 ACL.
Nao presumir que 10.100.10.9 ja funciona como servidor NTP.

Referencias oficiais:
- https://documentation.a10networks.com/ACOS/702x/ACOS_7.0.2/pdf/System_Configuration_and_Administration.pdf
- https://www.ntp.br/faq/

## 2. Novo disco para CGNAT

Os arquivos Syslog sao sensiveis e nao devem ficar no diretorio de
dashboard ou expostos ao Grafana. Recomendacao: **segundo disco SSD/HDD
de 2 TB** com backup do historico que for indispensavel, preferencialmente
armazenamento duravel. Dimensionar a capacidade efetiva apos uma semana
medindo compressao, retencao e consultas.

Taxa medida de 11.693.507 bytes/30s implicaria, se constante:
- 7 dias: ~219,6 GiB raw;
- 30 dias: ~940,9 GiB raw;
- 365 dias: ~11,18 TiB raw.

Disco de 1 TB decimal oferece ~931 GiB antes de overhead; portanto,
**nao garante sequer 30 dias sem compressao** com essa taxa.
O coletor atual rotaciona/comprime sem exclusao automatica.

### Antes de tocar na particao/disco

No flow, depois de adicionar disco:

    lsblk -o NAME,SIZE,FSTYPE,TYPE,MOUNTPOINTS,UUID,MODEL
    blkid
    df -hT
    sudo du -sh /var/log/orbymon/a10

**Nao executar mkfs, fdisk ou mount com /dev/sdb presumido.**
Identificar disco/UUID a partir da saida real. Nao formatar a unidade
que ja contenha arquivos. Para migrar, planejar parada curta do
recebedor rsyslog (o A10 pode continuar gerando logs e descartar
enquanto sem coletor), preservar historico, verificar checksums,
permissoes e UUID do fstab. Preferir filesystem dedicado montado em
/var/log/orbymon/a10 quando validado, com symlink/bind apenas se
permissoes e reinicio de servicos foram testados.

Nao fornecemos script que apaga dados ou formata disco sem inspecao
manual; esta etapa e intencionalmente **read-only**.

## 3. Retencao e conversao para consultas

**Politica desejada (condicionada a verificacao):**
- Raw Syslog ativo: rotacao, compactacao e disponibilidade para auditoria
  de integridade durante 30 dias.
- Historico estruturado: guardar toda informacao necessaria para consulta
  por prazo legal aplicavel (IP privado/porta, IP publico/porta, protocolo,
  time UTC, alocacao/liberacao, fonte, identificador da sessao PPPoE/RADIUS).
- Armazenamento columnar compactado (como Parquet/Zstd ou ClickHouse),
  particionado por dia/pool, com checksums, index e trilha de auditoria.
  MariaDB/Grafana podem manter índices/resumos operacionais mais curtos;
  **não** basta salvar somente alertas DDoS ou contagens agregadas.
- **Nao apagar raw automaticamente ainda**. So apos verificacao de
  enquadramento TCP, sincronizacao A10, importacao idempotente sem lacunas,
  reconciliacao de lifecycle de NAT e politicas de retencao juridica.
  Arquivos somente podem ser removidos quando o registro normalizado
  comprovadamente preserva os dados e prazos legalmente exigidos, com
  redundancia e restauracao testada.

Conforme art. 13 da Lei 12.965/2014, registros de conexao de provedores
devem ser guardados um ano. O Decreto 12.975/2026 (com vigencia 60 dias
apos a publicacao de 21/05/2026) alterou o Decreto 8.771/2016, incluindo
art. 15-A sobre **porta logica de origem** sempre que necessaria para
identificacao inequivoca. A obrigacao legal independe de o provedor
pretender usar dados para investigacao judicial. Consultar responsavel
juridico/DPO sobre o conjunto exato a preservar, solicitações de guarda
adicional e formas admitidas de armazenamento:
- https://www.planalto.gov.br/ccivil_03/_ato2011-2014/2014/lei/l12965.htm
- https://legis.senado.leg.br/norma/43306825/publicacao/43309287

## 4. Medicao segura

    cd /opt/orbymon
    sudo -u orbymon env PYTHONPATH=/opt/orbymon/src \
      python3 -m fmn_filters.a10_syslog_capacity --seconds 15

O script informa crescimento, projeções para 7 e 30 dias, detecta
mudanca de inode por rotacao e **nao** escreve no disco.
