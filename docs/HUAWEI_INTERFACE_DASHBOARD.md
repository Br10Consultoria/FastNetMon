# Painéis Huawei / GeoLite2 / CGNAT: unidades, tempo e ifIndex

## Porque Top ASN estava vazio
O dashboard "Tráfego, ASN e Defesa DDoS" buscava ASN e países
no rollup legado `orby_traffic_minute`, normalmente produzido sem GeoIP.
O painel novo de Huawei já usa `orby_ip_pairs_minute` enriquecido.
O Overview agora consulta a fonte enriquecida para painéis ASN e países;
não soma tabelas de fontes diferentes. Volumes pequenos são em MB
e a unidade Grafana é `suffix: MB` (o banco conserva valores numéricos).

## Quando 15 ou 30 minutos ficam sem dados
A coleta é feita de nfcapd para MariaDB em lotes. Fluxos cujo horário
está fora da janela, atraso na rotação, perda do exportador ou diferença
entre bases de consulta podem gerar intervalos sem linhas.
Uma tabela vazia em uma janela não prova falha do relógio ou rede.
Foi acrescentado indicador "Atraso da coleta Huawei (min)" independente
do filtro de tempo para permitir distinguir atraso de ausência real.
Verificar o relógio do banco e o dado realmente gravado com:

    sudo mariadb orbymon -e "
    SELECT UTC_TIMESTAMP() agora_utc,
      (SELECT MAX(bucket_utc) FROM orby_ip_pairs_minute WHERE source='huawei') ultimo_ip,
      (SELECT MAX(bucket_utc) FROM orby_traffic_minute WHERE source='huawei') ultimo_trafego;
    SELECT source,
      SUM(bucket_utc>=UTC_TIMESTAMP()-INTERVAL 15 MINUTE) ult15,
      SUM(bucket_utc>=UTC_TIMESTAMP()-INTERVAL 30 MINUTE) ult30,
      SUM(bucket_utc>=UTC_TIMESTAMP()-INTERVAL 60 MINUTE) ult60
    FROM orby_ip_pairs_minute GROUP BY source;
    "
    systemctl list-timers --all 'orbymon-*'
    sudo journalctl -u orbymon-ip-huawei.service -n 40 --no-pager

Com as fontes conhecidas, usar última coleta UTC para saber se há atraso.
No datasource Grafana, ajustar Session timezone para UTC (+00:00),
pois os bucket_utc são DATETIME em UTC. O layout em America/Bahia
é apenas exibição local dos horários. Não converter bucket_utc duas vezes.

## Nomes reais de interfaces Huawei

O campo `input_if` / `output_if` do NetFlow é ifIndex, não interface.
Índice 0 representa ausência de informação, não porta física.
Antes de povoar a tabela deve consultar os dados reais no Huawei,
por IF-MIB::ifName (.1.3.6.1.2.1.31.1.1.1.1).
NÃO presumir que 86 representa a porta GE0/1/1.
IF-MIB pode mudar depois de software/placas; renovar quando mudar.

Instalação (não altera o roteador):

    cd /opt/orbymon
    git pull --ff-only origin main
    sudo bash scripts/setup-interface-names.sh

Após executar uma consulta SNMP SOMENTE DE LEITURA (não compartilhar
credenciais), salve o resultado sem senha em um arquivo no flow, por
exemplo /root/huawei-ifname.txt contendo linhas:
IF-MIB::ifName.N = STRING: "NomeReal" ou
iso.3.6.1.2.1.31.1.1.1.1.N = STRING: "NomeReal".

Não use dados de exemplo como se fossem do roteador.
Alternativamente, pode fornecer CSV verificado:

    ifindex,ifname
    <indice_real>,<nome_real>

O usuario administrador importa o arquivo via ambiente escritor
pipeline.env sem escrever senhas na linha de comando:

    set -a
    source /etc/orbymon/pipeline.env
    set +a
    /opt/orbymon/.venv/bin/python -m fmn_filters.interface_names \
        --file /root/huawei-ifname.txt --source huawei --dry-run
    /opt/orbymon/.venv/bin/python -m fmn_filters.interface_names \
        --file /root/huawei-ifname.txt --source huawei
    unset ORBYMON_DB_PASSWORD

Evitar executar source de arquivos de configuração não confiáveis.
Os dashboards mostram nome real somente quando o índice está
verificado em orby_interface_names; nos demais, "ifIndex N" ou
"Não informado" para 0.

## Publicar os painéis

    sudo bash scripts/setup-interface-names.sh

O script cria tabela `orby_interface_names` e copia os dashboards
com os mesmos UID; não altera/duplica o banco de fluxos nem configura
Huawei/A10. Em seguida dê Refresh no Grafana e teste 15, 30, 60min.

## Limites

- ASN/GeoIP não cobre todos os endereços, especialmente privados/CGNAT.
- Prefixo só é conhecido quando exportado pelo Huawei.
- A tabela antiga `orby_traffic_minute` continua sendo usada para
  gráficos legados (volume/protocolos); rankings GeoIP usam
  `orby_ip_pairs_minute` enriquecida.
- NetFlow não equivale ao log CGNAT nem identifica assinantes.
