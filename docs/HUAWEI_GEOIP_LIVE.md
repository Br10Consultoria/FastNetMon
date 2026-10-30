# OrbyMon — mapa de tráfego e gráficos quase em tempo real (Huawei)

## O que está no ar

A fonte de dados para o painel "Huawei - Tráfego e GeoIP ao Vivo" e para
os indicadores de tráfego do Overview é `orby_ip_pairs_minute` com
`source='huawei'`, a mesma que recebeu nomes de ASN e país via GeoLite2.
O antigo rollup `orby_traffic_minute` não possui enriquecimento equivalente
e pode atrasar independentemente; o painel ao vivo não depende dele.

Mapas têm funções distintas:
- **Mapa de origens do tráfego Huawei — GeoLite2:** mostra pontos aproximados
  de IPs públicos vistos em NetFlow, ainda que nenhum ataque tenha ocorrido.
  Agrega localizações por coordenadas/ASN e conta IPs distintos.
- **Mapa de alertas DDoS:** só mostra alertas com geolocalização; sem
  alertas, é correto ficar sem pontos. Não gerar alertas fictícios.

Linhas usam buckets de 1 minuto com timestamp do **fim do fluxo**.
Os contadores de pacotes/bytes são estimados e podem refletir
amostragem no Huawei (nfdump já expande), e a contabilização por fim do
fluxo não é uma série contínua precisa. Não somar múltiplas perspectivas
do mesmo fluxo como se fossem interfaces independentes.

## Frequência
- `orbymon-ip-huawei.timer`: a cada ~1 minuto após última execução.
- Arquivos `nfcapd`: rotacionados pelo coletor; há tempo de finalização
  e margem de segurança para não processar arquivo aberto.
- Grafana: refresh 30 segundos (apenas consulta o MariaDB).
- Resultado: **quase em tempo real, frequentemente com atraso de 1 a
  alguns minutos**, não visibilidade por pacote/segundo. Acompanhe o
  painel "Atraso de coleta Huawei (min)". Reduzir o refresh para 5 s
  NÃO torna o exportador mais rápido e pode sobrecarregar MariaDB.

## Atualizar somente os dashboards, sem reiniciar Grafana

    cd /opt/orbymon
    git pull --ff-only origin main
    sudo bash scripts/deploy-live-dashboards.sh

A cópia faz backup de qualquer painel modificado antes de substituir,
mantém UID existentes e não altera equipamentos, serviços/timers nem
credenciais do Grafana. Com provisionamento por arquivo, a atualização
é percebida no próximo ciclo do provedor (30s), talvez com refresh de
página. O dashboard de IPs contém mapa GeoLite2 em seção própria.

## Diagnóstico para mapa vazio ou gráficos sem dados

    sudo mariadb orbymon -e "
    SELECT UTC_TIMESTAMP() AS agora_utc,
      MAX(bucket_utc) AS ultimo_bucket_utc,
      TIMESTAMPDIFF(SECOND,MAX(bucket_utc),UTC_TIMESTAMP()) AS atraso_seg
    FROM orby_ip_pairs_minute WHERE source='huawei';
    SELECT COUNT(*) AS linhas_30m,
      SUM(src_latitude IS NOT NULL AND src_longitude IS NOT NULL) AS geo_30m
    FROM orby_ip_pairs_minute WHERE source='huawei'
      AND bucket_utc>=UTC_TIMESTAMP()-INTERVAL 30 MINUTE;
    "
    systemctl is-active orbymon-ip-huawei.timer
    sudo journalctl -u orbymon-ip-huawei.service -n 30 --no-pager

Se `geo_30m` for maior que zero e o mapa continuar vazio, conferir
"Inspect > Data/Query" do painel e o filtro de tempo. O mapa-base
OpenStreetMap depende de acesso aos tiles externos pelo navegador,
mas os pontos de origem e país são calculados offline via GeoLite2.
Não supor que mapa sem marcadores significa que não há tráfego.

**ASN/GeoIP** localiza um bloco IP público aproximadamente;
não localiza pessoas nem comprova origem de um ataque. O mapa GeoLite2
não mostra tradutores CGNAT por usuário; isto depende de eventos A10
completos e correlacionados, uma etapa futura.
