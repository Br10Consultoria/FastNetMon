# A10 CGNAT - diagnóstico da recepção e capacidade

## Resultados observados no flow em 30 de outubro de 2026

- 1.000 registros de Syslog com rawmsg de **8.096 bytes exatos**;
  valor coerente com o limite global padrão de 8 KiB do rsyslog.
  O receptor pode estar dividindo um stream TCP sem enquadramento correto.
  Ele nao necessariamente perdeu todos os bytes, mas fragmentos nao possuem
  timestamp individual e nao devem ser usados para correlacao automatica.
- **992/1.000** linhas com fragmentos antes do primeiro header RFC5424.
- A auditoria encontrou aproximadamente **10.238 segundos** entre o
  timestamp do A10 e o recebido pelo flow (podendo incluir buffering).
  O flow indicou NTP sincronizado, enquanto o A10 apresentou *show clock
  com asterisco. Consultar show ntp status e show clock detail no A10
  ANTES de corrigir horario; NAO dar clock set em producao sem planejar
  efeito nos logs de NAT e seus timestamps.
- **11.693.507 bytes/30s**, equivalente a **~31,36 GiB/dia** antes da
  compactacao, caso a taxa se mantenha; disco com ~80 GiB livres.
- A10 reportou **1.945 Log Packets Dropped** e
  **15 TCP Connection Lost**. Sao contadores acumulados. Registrar uma
  segunda amostra para medir crescimento; nao inferir perda correspondente
  a 1.945 mapeamentos especificos.

## Comandos seguros, sem parar coletor e sem modificar A10

    cd /opt/orbymon
    git pull --ff-only origin main
    sudo -u orbymon env PYTHONPATH=/opt/orbymon/src \
      python3 -m fmn_filters.a10_syslog_capacity --seconds 15
    sudo -u orbymon env PYTHONPATH=/opt/orbymon/src \
      python3 -m fmn_filters.a10_syslog_audit --last 1000

Se o arquivo girar durante a medicao, o calculo reportara invalido,
em vez de inventar uma taxa de crescimento. As projecoes sao
antes da compressao e nao constituem limite/retencao final.

No A10 (apenas leitura e conforme comandos suportados):

    show clock detail
    show ntp status
    show running-config | include ntp
    show cgnv6 logging statistics
    show version

## Proximas etapas seguras

1. Dimensionar disco externo/dedicado/backup e politica de retencao;
   o coletor atual nao exclui logs CGNAT.
2. Corrigir NTP do A10 de forma planejada (sem alterar timestamps no
   banco nem associar assinantes durante salto de horario).
3. Determinar o modo de framing TCP RFC6587 do A10 (LF ou octet counting).
   Nao alterar maxMessageSize global do rsyslog as cegas; pode apenas
   aumentar o tamanho de fragmentos sem recuperar o framing correto.
4. Verificar contadores de perda no A10 por delta e, apos a correção,
   reavaliar integridade do stream e checkpoint antes de correlacao NAT.

NENHUM script deste passo altera Huawei, A10, rsyslog, firewall,
logs originais, tabelas MariaDB ou regras de deteccao.
