# OrbyMon fase 2 - IPs, prefixos, ASNs, ifIndex e direcao

No Ubuntu flow, que ja possui NetFlow Huawei, MariaDB e Grafana:

    cd /opt/orbymon
    git pull --ff-only origin main
    PYTHONPATH=src python3 -m unittest discover -s tests -q
    sudo bash scripts/setup-ip-analytics.sh

O script:
- Cria tabelas orby_ip_pairs_minute e orby_ip_ingested_files sem alterar as tabelas originais.
- Le arquivos rotacionados nfcapd com janela de 1 hora e checkpoint separado.
- Usa o mesmo usuario escritor MariaDB existente e a mesma expansao amostral do nfdump.
- Habilita timer independente orbymon-ip-huawei.timer para processamento periodico.
- Instala o painel OrbyMon | Huawei - IPs, Redes e Interfaces na pasta OrbyMon.
- Nao muda Mikrotik, Huawei, nfcapd, BGP/PPPoE, firewall nem o timer da fase 1.

## Checagem

    sudo systemctl is-active orbymon-ip-huawei.timer
    sudo journalctl -u orbymon-ip-huawei.service -n 25 --no-pager
    sudo mariadb orbymon -e "SELECT COUNT(*) AS arquivos,SUM(flow_count) AS fluxos FROM orby_ip_ingested_files"
    sudo mariadb orbymon -e "SELECT src_ip,ROUND(SUM(total_bytes)/1000000,2) MB FROM orby_ip_pairs_minute GROUP BY src_ip ORDER BY SUM(total_bytes) DESC LIMIT 10"
    sudo mariadb orbymon -e "SELECT input_if,output_if,COUNT(*) AS linhas FROM orby_ip_pairs_minute GROUP BY input_if,output_if ORDER BY linhas DESC"

## ASN e GeoLite2

Os campos src_as/dst_as numericos do Huawei sao preservados.
Nome de operadora e pais/coordenadas dependem do exporter ou de bases offline
GeoLite2-ASN.mmdb e GeoLite2-City.mmdb (MaxMind, licenca necessaria).
Nao inserimos pais ou nome ficticio quando ausentes.

Se obtiver MMDBs, copie-as para pasta legivel pelo usuario orbymon
e execute no venv:

    cd /opt/orbymon
    .venv/bin/pip install -e '.[full]'

Configure root:orbymon 0640 em /etc/orbymon/ip-analytics.env:

    ORBYMON_ASN_MMDB=/var/lib/orbymon/geoip/GeoLite2-ASN.mmdb
    ORBYMON_CITY_MMDB=/var/lib/orbymon/geoip/GeoLite2-City.mmdb

Novos arquivos serao enriquecidos nas proximas execucoes. Os antigos permanecem
sem enriquecimento; nao reimporte manualmente arquivos processados para
evitar contagem dupla. GeoIP e localizacao aproximada de faixas, nao pessoas.

## Limites atuais

- Interface input_if e output_if sao ifIndex numericos; nomes como GE0/1/1
  exigem tabela ifIndex/ifName de SNMP ou comando do Huawei, ainda pendente.
- NetFlow direction eh campo bruto do exporter: nao inferir upload/download.
- Mesmo pacote visto em interfaces/sentidos distintos pode ser duplicado.
- Valores de volume/PPS sao estimados; nfdump ja aplicou 1:2048.
- Prefixos exigem mascara exportada, nunca sao atribuidos artificialmente.
- Buckets por minuto do fim do fluxo; nao sao medicao precisa por pacote.
- Retencao e limitacao de cardinalidade ainda devem ser homologadas.
