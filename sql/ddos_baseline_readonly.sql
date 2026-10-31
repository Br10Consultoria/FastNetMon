-- OrbyMon: calibracao DDoS Huawei, somente SELECT, sem IPs no resultado.
-- Janela fixa de 60 minutos consolidada ate pelo menos 5 minutos atras.
-- Volume do NetFlow amostrado: estimativas, nunca contagem de pacotes exata.
-- Nao usar maximos de minutos diferentes como se ocorressem simultaneamente.

-- 1. Continuidade da coleta em 60 minutos: linhas agregadas por bucket.
SELECT
  COUNT(*) AS pares_60min,
  COUNT(DISTINCT bucket_utc) AS minutos_com_dados,
  MAX(bucket_utc) AS ultimo_bucket_consolidado_utc,
  COALESCE(SUM(total_packets),0) AS pacotes_estimados_60min
FROM orby_ip_pairs_minute
WHERE source='huawei'
  AND bucket_utc>=UTC_TIMESTAMP()-INTERVAL 65 MINUTE
  AND bucket_utc<UTC_TIMESTAMP()-INTERVAL 5 MINUTE;

-- 2. Maximo POR DESTINO E MINUTO (sem mostrar enderecos de assinantes).
-- Mantem protocolo e interface/direcao separados, como faz o detector.
SELECT
  protocol AS protocolo,
  input_if AS if_entrada,
  output_if AS if_saida,
  netflow_direction AS direcao_raw,
  COUNT(*) AS amostras_destino_minuto,
  ROUND(MAX(pps),0) AS pico_pps_estimado_por_destino,
  ROUND(MAX(mbps),2) AS pico_mbps_estimado_por_destino,
  MAX(origens_observadas) AS pico_origens_observadas_por_destino
FROM (
  SELECT bucket_utc,dst_ip,protocol,input_if,output_if,netflow_direction,
    SUM(total_packets)/60 AS pps,
    SUM(total_bytes)*8/60000000 AS mbps,
    COUNT(DISTINCT src_ip) AS origens_observadas
  FROM orby_ip_pairs_minute
  WHERE source='huawei'
    AND bucket_utc>=UTC_TIMESTAMP()-INTERVAL 65 MINUTE
    AND bucket_utc<UTC_TIMESTAMP()-INTERVAL 5 MINUTE
    AND (dst_ip LIKE '45.238.170.%'
      OR dst_ip LIKE '45.238.171.%'
      OR dst_ip LIKE '187.87.201.%')
  GROUP BY bucket_utc,dst_ip,protocol,input_if,output_if,netflow_direction
) AS amostras
GROUP BY protocol,input_if,output_if,netflow_direction
ORDER BY pico_mbps_estimado_por_destino DESC
LIMIT 25;

-- 3. DNS e NTP requerem contadores por porta destino (53 / 123).
SELECT
  protocol AS protocolo,
  dst_port AS porta_destino,
  input_if AS if_entrada,
  output_if AS if_saida,
  netflow_direction AS direcao_raw,
  ROUND(MAX(pps),0) AS pico_pps_estimado_por_destino,
  ROUND(MAX(mbps),2) AS pico_mbps_estimado_por_destino,
  MAX(origens_observadas) AS pico_origens_observadas_por_destino
FROM (
  SELECT bucket_utc,dst_ip,protocol,dst_port,input_if,output_if,netflow_direction,
    SUM(total_packets)/60 AS pps,
    SUM(total_bytes)*8/60000000 AS mbps,
    COUNT(DISTINCT src_ip) AS origens_observadas
  FROM orby_ip_pairs_minute
  WHERE source='huawei'
    AND bucket_utc>=UTC_TIMESTAMP()-INTERVAL 65 MINUTE
    AND bucket_utc<UTC_TIMESTAMP()-INTERVAL 5 MINUTE
    AND protocol='udp' AND dst_port IN (53,123)
    AND (dst_ip LIKE '45.238.170.%'
      OR dst_ip LIKE '45.238.171.%'
      OR dst_ip LIKE '187.87.201.%')
  GROUP BY bucket_utc,dst_ip,protocol,dst_port,input_if,output_if,netflow_direction
) AS amostras
GROUP BY protocol,dst_port,input_if,output_if,netflow_direction
ORDER BY pico_mbps_estimado_por_destino DESC
LIMIT 25;
