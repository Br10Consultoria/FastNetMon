-- Diagnostico DDoS Huawei: /24 reais das pontas IPv4, SEM IP individual.
-- Somente SELECT; sem logs A10, sem NAT/CGNAT e sem dependencia Zabbix.
-- Nao presumir propriedade de prefixo apenas porque aparece no NetFlow.
-- 60 minutos de amostra, encerrados ha 5 minutos para consolidacao.

SELECT
  lado,
  prefixo_24,
  input_if AS entrada_ifindex,
  output_if AS saida_ifindex,
  netflow_direction AS direcao_raw,
  COUNT(*) AS pares_agregados,
  COUNT(DISTINCT bucket_utc) AS minutos_com_dados,
  ROUND(SUM(total_packets),0) AS pacotes_estimados,
  ROUND(SUM(total_bytes)*8/3600000000,3) AS mbps_medio_estimado
FROM (
  SELECT 'origem' AS lado,
    CONCAT(SUBSTRING_INDEX(src_ip,'.',3),'.0/24') AS prefixo_24,
    bucket_utc,input_if,output_if,netflow_direction,
    total_packets,total_bytes
  FROM orby_ip_pairs_minute
  WHERE source='huawei'
    AND bucket_utc>=UTC_TIMESTAMP()-INTERVAL 65 MINUTE
    AND bucket_utc<UTC_TIMESTAMP()-INTERVAL 5 MINUTE
    AND INET_ATON(src_ip) IS NOT NULL
  UNION ALL
  SELECT 'destino' AS lado,
    CONCAT(SUBSTRING_INDEX(dst_ip,'.',3),'.0/24') AS prefixo_24,
    bucket_utc,input_if,output_if,netflow_direction,
    total_packets,total_bytes
  FROM orby_ip_pairs_minute
  WHERE source='huawei'
    AND bucket_utc>=UTC_TIMESTAMP()-INTERVAL 65 MINUTE
    AND bucket_utc<UTC_TIMESTAMP()-INTERVAL 5 MINUTE
    AND INET_ATON(dst_ip) IS NOT NULL
) AS pontas
GROUP BY lado,prefixo_24,input_if,output_if,netflow_direction
ORDER BY pares_agregados DESC
LIMIT 35;
