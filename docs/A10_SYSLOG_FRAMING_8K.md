# A10 Syslog TCP 5514: tamanho 8096 e integridade de enquadramento

## Evidencia coletada no flow (30/10/2026)
- Ultimas 500 linhas: rawmsg_bytes_p50, p95 e max = 8096, 500/500 iguais;
- 33.298 cabecalhos RFC5424 nas 500 linhas, 494 prefixos fragmentados;
- 31.448 marcadores NAT, 31.033 eventos com timestamp e mapeamento candidato,
  170 sem mapeamento completo, percentual estrutural 98,68%;
- Diferenca coletor-A10 mediana 0,750s e p95 1,218s (NTP corrigido);
- rsyslog 8.2312.0 recebe TCP/5514, sem MaxMessageSize explicito no grep;
- correlacao automatica continua DESABILITADA e deve permanecer assim.

O default rsyslog e 8k. O tamanho fixo 8096 e muito sugestivo de
truncamento, mas nao prova que os bytes de chegada estejam em um frame
TCP valido. Rsyslog global(maxMessageSize) e global, afeta todos os
inputs e pode aumentar memoria. RFC6587 descreve framing por comprimento
(octet-counting) ou por delimitador LF/NUL.

Referencias:
https://docs.rsyslog.com/doc/rainerscript/global.html
https://docs.rsyslog.com/doc/configuration/global/index.html
https://www.rfc-editor.org/rfc/rfc6587.html

## Experimento controlado, sem mudar o A10

Nao executar novamente setup-a10-syslog.sh somente para este ajuste:
esse instalador reinicia o rsyslog. Em vez disso, use o script especifico
que prepara backup e deixa o restart inteiramente para o operador.

    cd /opt/orbymon
    git pull --ff-only origin main
    sudo python3 scripts/prepare-a10-rsyslog-maxsize.py

Se check passar, preparar arquivo com backup e validacao rsyslogd -N1:

    sudo python3 scripts/prepare-a10-rsyslog-maxsize.py --apply

O script nao reinicia. Em janela supervisionada, sabendo que a conexao
TCP do A10 sera desconectada e pode haver lacuna de logs no intervalo:

    sudo systemctl restart rsyslog
    sudo systemctl is-active rsyslog
    sudo ss -lntp | grep ':5514'

Depois de chegarem novos logs, executar auditoria:

    sudo -u orbymon env PYTHONPATH=/opt/orbymon/src \
      /opt/orbymon/.venv/bin/python -m fmn_filters.a10_syslog_audit --last 500

Interpretacao:
- Tamanhos variados maiores que 8k: havia gargalo no limite, mas
  integridade do framing ainda NAO esta homologada.
- Tamanhos todos proximos de 64k com fragmentos: pode ser stream
  concatenado sem delimitador. Nao declarar solucao.
- Tamanhos ainda 8096: emissor A10 ou outro componente pode estar
  gerando os limites, verificar framing bruto com captura local
  de acesso restrito; NUNCA compartilhar IPs/portas de assinantes.
- Nao descartar nem reimportar logs antigos, nao criar sessoes NAT a
  partir de candidatos sem validar integralmente cada evento.

Rollback (usar o nome EXATO impresso por [BACKUP]):

    sudo cp -a /etc/rsyslog.conf.orbymon-before64k-AAAAMMDDTHHMMSSZ.bak /etc/rsyslog.conf
    sudo rsyslogd -N1
    sudo systemctl restart rsyslog

A preparacao altera apenas a configuracao do servidor flow; nao muda
equipamento Huawei, A10, CGNAT, NetFlow, MariaDB ou Grafana.
