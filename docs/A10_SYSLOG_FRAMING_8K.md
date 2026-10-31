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


## Apos maxMessageSize=64k: corrigir o auditor para NDJSON maior que 64 KiB

O operador aplicou a configuracao e reiniciou rsyslog com sucesso.
Uma amostra de 500 linhas mostrou 46 com mais de 65536 bytes, que a
auditoria anterior ignorou. As outras 454 tinham rawmsg de 8096 bytes.
Nao interpretar rawmsg_bytes_max=8096 como tamanho maximo real do arquivo:
ele se refere somente as linhas analisadas, excluindo as 46 maiores.

O auditor (read-only) agora aceita ate 256 KiB por linha NDJSON e usa
janela de leitura de 64 MB por padrao, adequada a 500 mensagens
novas de aproximadamente 64 KiB. O antigo inspector conserva o limite
historico de 64 KiB, sem mudar sua interface.

    cd /opt/orbymon
    git pull --ff-only origin main
    sudo -u orbymon env PYTHONPATH=/opt/orbymon/src \
      /opt/orbymon/.venv/bin/python -m fmn_filters.a10_syslog_audit \
      --last 500 --max-bytes 64000000

Interpretar os novos campos:
- linhas_maiores_64KiB: registros NDJSON maiores que o limite antigo;
- linhas_descartadas_por_limite_de_leitura: registros acima do NOVO
  limite, nao analisados; precisam ser zerados para medicao confiavel;
- rawmsg_entre_64000_66000_bytes: possiveis chunks no novo limite;
- rawmsg_acima_8192_bytes: registros efetivamente maiores que 8 KiB;
- rawmsg_bytes_p05/p50/p95/max: distribuicao apenas de registros validos;
- fragmentos_antes_do_cabecalho e eventos_sem_mapeamento_completo:
  devem permanecer sob investigacao; mensagens concatenadas sem
  delimitação TCP nao viram automaticamente eventos completos.

Esta alteracao NAO modifica a configuracao rsyslog nem reinicia servicos.
Nao muda logs historicos e nao habilita gravacao de NAT ou assinantes.
