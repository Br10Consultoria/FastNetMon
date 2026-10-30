# OrbyMon - Auditoria do enquadramento Syslog A10

Em 30/10/2026, a amostra do servidor flow mostrou 978 linhas NDJSON,
61.125 marcadores LSN:PortAllocated/LSN:PortFreed e 60.821 candidatos.
Uma linha de rsyslog contem dezenas de mensagens RFC 5424 concatenadas,
o que ainda exige investigar delimitacao TCP e possivel truncamento.

## Executar auditoria SEM ALTERAR A10 OU O BANCO

    cd /opt/orbymon
    git pull --ff-only origin main
    sudo -u orbymon env PYTHONPATH=/opt/orbymon/src \
      python3 -m fmn_filters.a10_syslog_audit --last 1000

A ferramenta mostra cabecalhos RFC5424 por linha, fragmentos sem
cabecalho, eventos com timestamp e formato candidato completo,
percentual estrutural reconhecido e periodo observado.
Nao imprime IPs privados/publicos ou portas de assinantes.
Nao implementa correlacao PPPoE nem grava NAT no MariaDB.
A flag correlacao_automatica_permitida permanece false:
reconhecimento estrutural nao confirma entrega, continuidade e pareamento
historico de todos os eventos.

## Verificar enquadramento, perdas e espaco

    sudo journalctl -u rsyslog.service --since "1 hour ago" --no-pager \
      | grep -Ei 'trunc|oversize|frame|error|discard|queue' || true
    sudo grep -RInE 'MaxMessageSize|imtcp|imptcp|MaxFrameSize' \
      /etc/rsyslog.conf /etc/rsyslog.d
    sudo du -sh /var/log/orbymon/a10
    df -h /var/log/orbymon

Conforme RFC 6587, Syslog TCP pode ser separado por LF ou comprimento
do frame em octetos. O texto puro recebido mistura mensagens RFC5424,
o que demanda comparar framing do A10 com o rsyslog.
Nao alterar formato/MaxMessageSize/MaxFrameSize de producao sem identificar
comprovar a causa. A diferenca de 304 marcadores tem causas possiveis
variadas; nao declarar 304 eventos perdidos sem evidencia.

A rotacao dos arquivos A10 nao possui exclusao automatica;
monitorar espaco, controle de acesso e retencao adequada para dados NAT.

## Diagnostico adicional: limite 8 KiB e diferenca de relogio

O rsyslog possui limite global default maxMessageSize de 8 KiB quando
nao configurado; mensagens acima disso podem ser truncadas. Uma
concentracao de rawmsg_bytes_p50/p95 perto de 8192 e muitos fragmentos
sugerem investigar tamanho/framing, MAS nao provam sozinho truncamento.
A auditoria agora mostra quantidades perto de 4096 e 8192 bytes.

A diferenca delta_coletor_menos_a10_segundos_p50/p95 compara o horario
timegenerated (received_at do receptor) com o timestamp do header do A10,
com offsets timezone respeitados. Pode ter atraso/buffering alem de
desvio de relogio; por isso revisar NTP em ambos os servidores antes
de atribuir o offset inteiramente a hora incorreta.

No flow:

    timedatectl status
    date -Ins

No A10 (somente leitura, sintaxe varia por ACOS):

    show clock
    show cgnv6 logging statistics

Para avaliar taxa REAL de crescimento do log ATIVO:

    antes=$(stat -c %s /var/log/orbymon/a10/a10-current.ndjson)
    sleep 30
    depois=$(stat -c %s /var/log/orbymon/a10/a10-current.ndjson)
    echo "Bytes em 30 segundos: $((depois-antes))"

A contagem de bytes sera invalida se logrotate girar o arquivo entre
as duas medicoes (valor negativo ou proximo de zero); acompanhe
`du -sh /var/log/orbymon/a10` tambem. Nao habilitar limpeza
automatica de logs CGNAT sem politica legal e capacidade de arquivo.
