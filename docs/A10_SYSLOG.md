# OrbyMon - A10 CGNAT Syslog Receiver (piloto)

## O que esta pronto

Instalador do servidor flow cria uma entrada syslog TCP exclusiva (porta
5514 por padrao) usando rsyslog, filtrando pelo IP REAL de origem do A10.
Guarda mensagens brutas em NDJSON em /var/log/orbymon/a10/
(com permissao de leitura restrita ao grupo orbymon), e gera rotacao
horaria com compactacao e SEM exclusao automatica de registros.

Nao altera NAT pools, A10, Huawei, firewall, Nginx, Grafana, NetFlow
nem a deteccao DDoS da fase 3. A fonte de origem deve ser confirmada
antes de liberar conectividade do A10. O next-hop Huawei 10.100.10.10
pode, mas nao necessariamente precisa, ser a origem do Syslog.

## Instalacao

No Ubuntu flow:

    cd /opt/orbymon
    git pull --ff-only origin main
    PYTHONPATH=src python3 -m unittest discover -s tests -q
    sudo bash scripts/setup-a10-syslog.sh --a10-source-ip 10.100.10.10

Altere o --a10-source-ip caso o log saia por outra interface/source no A10.
O instalador nao altera regras do firewall ou MikroTik.
Permita TCP 5514 somente ao endereco confirmado do A10 na borda
e no firewall do servidor, de preferencia pela rede privada de gerencia.
TCP 5514 simples NAO criptografa; em transito por rede nao confiavel,
substitua por TLS ou transporte cifrado.

## Verificacoes

    sudo ss -ltnp | grep 5514
    sudo systemctl status rsyslog --no-pager
    logger --tcp --server 127.0.0.1 --port 5514 -t ORBYMON-TEST 'collector-healthcheck'
    sudo -u orbymon env PYTHONPATH=/opt/orbymon/src python3 -m fmn_filters.a10_syslog_inspect

A mensagem collector-healthcheck aparecera como 'unrecognized': esperado.

Se a instalacao anterior retornar Permission denied ao inspecionar
'a10-current.ndjson', atualize o repositorio e execute novamente o
instalador com o mesmo --a10-source-ip. A rotina preserva o conteudo do
arquivo existente, corrige owner/group para syslog:orbymon (0640), e
configura novos arquivos com fileOwner=syslog e fileGroup=orbymon.
O logrotate ja usava 'create 0640 syslog orbymon'. Nao use chmod 777
nem exponha registros brutos de CGNAT.
Verifique recebimento do A10 com:

    sudo tcpdump -ni any 'tcp port 5514' -c 15
    sudo ls -lh /var/log/orbymon/a10
    sudo -u orbymon tail -n 5 /var/log/orbymon/a10/a10-current.ndjson

Nao compartilhe publicamente o raw: logs NAT podem conter enderecos e
portas de assinantes. O inspector exibe exemplos com IPs ocultos.

## Configuracao do A10: planejar antes de aplicar

A10 ACOS documenta cgnv6 server / cgnv6 service-group,
cgnv6 template logging e cgnv6 lsn logging default-template.
Exemplo conceitual (validar firmware, source IP, reachability e
comandos suportados com '?' no CLI ANTES de executar):

    cgnv6 server ORBY_LOG 187.87.201.198
      port 5514 tcp
    cgnv6 service-group ORBY_LOG tcp
      member ORBY_LOG 5514
    cgnv6 template logging ORBY_LOG_TEMPLATE
      format rfc5424
      log port-mappings both
      service-group ORBY_LOG
    cgnv6 lsn logging default-template ORBY_LOG_TEMPLATE

Esse exemplo NAO foi aplicado no A10. O endereco acima e o destino
publico informado do flow, mas prefira IP privado roteavel do servidor.
Nao habilite log sessions para TODAS as conexoes no primeiro momento:
pode gerar altissimo volume e impacto. Primeiro habilite/valide mapeamentos
de portas, inclusive como se comporta com enable-port-batch-v1.
O comando exato de log port-mappings e suas opcoes podem mudar entre
versoes ACOS. Se ja houver default-template, nao substitua sem auditoria.

## Limites do piloto

O inspector apenas classifica marcadores de eventos e compara
um formato textual individual publicado pelo fabricante com
os pools publicos e rede 100.64.64.0/19. Um resultado
unverified_candidate NAO e uma traducao comprovada.
Nao grava mapeamentos em MariaDB, nao identifica assinante
e nao liga logs NAT a PPPoE/RADIUS nesta fase. Uma amostra real do
A10 e a versao do ACOS sao necessarias para criar parser seguro.
Port-batch v1 pode representar faixas de portas, em vez de uma
porta unica, e a interpretacao requer testes com abertura e
fechamento da alocacao.

Para associar assinante: mapeamento IP privado:porta -> IP
publico:porta, protocolo, intervalo de validade e sessao
PPPoE/RADIUS (IP privado -> ID do assinante ao longo do tempo).
Os logs do A10 e da autenticacao precisam de NTP sincronizado;
uma relacao baseada so no IP publico e indevida.

ARMAZENAMENTO: o instalador preserva logs brutos indefinidamente,
nao apaga registros e faz compactacao. Monitore disco e defina
retenção legal, backups, controles de acesso e capacidade antes
de liberar producao ou logs de volume elevado. A fase de compliance
e armazenamento de longo prazo ainda nao esta implementada.

## Enderecamento fisico confirmado

- A10 Thunder no enlace de CGNAT: **10.100.10.10** (origem Syslog, salvo source-interface diferente).
- Huawei borda no enlace com A10: **10.100.10.9** (proximo salto do A10, NAO endereco do coletor).
- Destino Syslog e o IP do servidor flow alcancavel pelo A10: o IP publico usado para Grafana/NetFlow foi 187.87.201.198, mas confirmar rota e filtros antes de configurar; preferir endereco privado real do flow caso exista.

Nao use 10.100.10.9 como destino do log sem encaminhamento explicito configurado na borda: e o endereco do roteador, nao o servidor flow. A confirmacao de ping/rota entre A10 e flow precede a configuracao definitiva no ACOS.


## Logs reais recebidos em 30/10/2026

A origem `10.100.10.10` do A10 ja foi confirmada pelo receptor.
O equipamento esta enviando `LSN:PortAllocated` e `LSN:PortFreed`
(TCP/UDP). A interface Huawei `10.100.10.9` e apenas gateway;
**nao** deve ser configurada como destino do Syslog.

O inspetor agora conta marcadores separados, mesmo quando varias
mensagens aparecem dentro do mesmo `rawmsg`. Os campos novos
`marcadores_por_evento` e `total_marcadores` ajudam a verificar
se ocorrem eventos de alocacao e liberacao. O campo
`candidatos_mapeamento_formato_publicado` e exploratorio; ainda
nao confirma timestamps/portas de traducoes e nao grava NAT no banco.
Eventuais eventos incompletos devem ser examinados quanto a framing
TCP (terminador LF ou octet-counting), sem alterar configuracao A10
ou rsyslog enquanto nao houver evidencia de perda ou erro real.
