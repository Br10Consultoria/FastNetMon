# GeoIP/ASN para OrbyMon no Ubuntu 24.04

## Diagnostico
Em 30/10/2026, o flow possui timer Huawei ativo, 8.727 registros
de IP/minuto na ultima hora, 357 com ASN numerico e zero com nome ASN,
pais e latitude. Bases MMDB nao estavam presentes; enriquecimento
dependente da MaxMind nao estava habilitado.

## Como habilitar

MaxMind GeoLite2 requer cadastro gratuito e chave de licenca:
https://www.maxmind.com/en/geolite2/signup

No flow:

    sudo apt-get update
    sudo apt-get install -y geoipupdate
    sudoedit /etc/GeoIP.conf

Configure os dados da sua propria conta, com as linhas:

    AccountID SEU_ACCOUNT_ID
    LicenseKey SUA_CHAVE_SECRETA
    EditionIDs GeoLite2-ASN GeoLite2-City

Nao envie chave no chat ou GitHub nem passe na linha de comando.
O geoipupdate do Ubuntu usa /etc/GeoIP.conf por padrao.

    cd /opt/orbymon
    git pull --ff-only origin main
    sudo bash scripts/setup-geoip.sh

O instalador valida a existencia do arquivo de credenciais sem imprimir
segredos, cria /var/lib/orbymon/geoip root:orbymon, baixa MMDBs,
instala geoip2 no .venv, configura ORBYMON_ASN_MMDB e
ORBYMON_CITY_MMDB em /etc/orbymon/ip-analytics.env, faz backup do
env anterior e ativa o timer de atualizacao da base diariamente. Nao altera as tabelas de trafego e NAO reimporta arquivos
ja contabilizados.

## Confirmar

    systemctl is-active orbymon-geoip-update.timer
    systemctl is-active orbymon-ip-huawei.timer
    sudo -u orbymon /opt/orbymon/.venv/bin/python -c 'import geoip2.database; print("OK")'
    sudo -u orbymon test -r /var/lib/orbymon/geoip/GeoLite2-ASN.mmdb
    sudo -u orbymon test -r /var/lib/orbymon/geoip/GeoLite2-City.mmdb
    sudo journalctl -u orbymon-ip-huawei.service -n 25 --no-pager

    sudo mariadb orbymon -e "
    SELECT COUNT(*) registros, SUM(src_asn>0) src_asn,
      SUM(dst_asn>0) dst_asn,
      SUM(src_asn_name!='') src_asn_name,
      SUM(dst_asn_name!='') dst_asn_name,
      SUM(src_country!='') src_country,
      SUM(dst_country!='') dst_country,
      SUM(src_latitude IS NOT NULL) src_geo,
      SUM(dst_latitude IS NOT NULL) dst_geo
    FROM orby_ip_pairs_minute
    WHERE bucket_utc>=UTC_TIMESTAMP()-INTERVAL 1 HOUR;"

As bases somente se aplicam a novos arquivos elegiveis. Nao reimporte
NFCAPD antigo: o sink agrega trafego e reprocessar duplica volume.
Se necessario, futuro backfill deve atualizar metadados por chave,
sem modificar bytes/pacotes/quantidade de fluxos.

CGNAT 100.64/10 e RFC1918 nao possuem geolocalizacao publica.
Nome ASN por GeoLite2 so eh preenchido quando corresponde ao
numero ASN exportado; dados ausentes nao sao inventados.
GeoLite2 mostra localizacao aproximada do bloco, nao do assinante.

Referencias:
https://dev.maxmind.com/geoip/updating-databases/
https://github.com/maxmind/geoipupdate/blob/main/doc/GeoIP.conf.md
