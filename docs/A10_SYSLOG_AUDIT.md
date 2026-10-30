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
