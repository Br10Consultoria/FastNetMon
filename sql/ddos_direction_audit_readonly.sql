-- Diagnostico Huawei DDoS: somente SELECT, sem revelar IPs individuais.
-- 60 minutos concluidos com atraso de 5 minutos para consolidacao nfdump.
-- IPs protegidos: 45.238.170.0/23 e 187.87.201.0/24.
-- O fato de nao ver destino protegido NAO comprova ausencia de ataques.
-- Unidades estimadas do NetFlow com sampling 1:2048.

-- Consulta 1: onde os enderecos protegidos aparecem nos registros?
SELECT
  CASE WHEN protected_src=1 AND protected_dst=1 THEN 'ambas_as_pontas'
       WHEN protected_dst=1 THEN 'destino_protegido'
       WHEN protected_src=1 THEN 'origem_protegida'
       ELSE 'nenhuma_ponta_protegida' END AS papel_das_redes,
  COUNT(*) AS pares_agregados,
  COUNT(DISTINCT bucket_utc) AS minutos_com_dados,
  ROUND(SUM(total_packets),0) AS pacotes_estimados,
  ROUND(SUM(total_bytes)*8/1000000,2) AS megabits_estimados,
  MAX(bucket_utc) AS ultimo_bucket_utc
FROM (
  SELECT bucket_utc,total_packets,total_bytes,
    CASE WHEN src_ip LIKE '45.238.170.%' OR src_ip LIKE '45.238.171.%'
           OR src_ip LIKE '187.87.201.%' THEN 1 ELSE 0 END AS protected_src,
    CASE WHEN dst_ip LIKE '45.238.170.%' OR dst_ip LIKE '45.238.171.%'
           OR dst_ip LIKE '187.87.201.%' THEN 1 ELSE 0 END AS protected_dst
  FROM orby_ip_pairs_minute
  WHERE source='huawei'
    AND bucket_utc>=UTC_TIMESTAMP()-INTERVAL 65 MINUTE
    AND bucket_utc<UTC_TIMESTAMP()-INTERVAL 5 MINUTE
) AS classified
GROUP BY papel_das_redes
ORDER BY pares_agregados DESC;

-- Consulta 2: se houver ponta protegida, identificar interface e direcao.
SELECT
  CASE WHEN protected_src=1 AND protected_dst=1 THEN 'ambas_as_pontas'
       WHEN protected_dst=1 THEN 'destino_protegido'
       WHEN protected_src=1 THEN 'origem_protegida'
       ELSE 'nenhuma_ponta_protegida' END AS papel_das_redes,
  protocol AS protocolo,
  input_if AS entrada_ifindex,
  output_if AS saida_ifindex,
  netflow_direction AS direcao_raw,
  COUNT(*) AS pares_agregados,
  COUNT(DISTINCT bucket_utc) AS minutos_com_dados,
  ROUND(SUM(total_packets)/3600,1) AS pps_medio_estimado_janela,
  ROUND(SUM(total_bytes)*8/3600000000,3) AS mbps_medio_estimado_janela
FROM (
  SELECT bucket_utc,protocol,input_if,output_if,netflow_direction,
    total_packets,total_bytes,
    CASE WHEN src_ip LIKE '45.238.170.%' OR src_ip LIKE '45.238.171.%'
           OR src_ip LIKE '187.87.201.%' THEN 1 ELSE 0 END AS protected_src,
    CASE WHEN dst_ip LIKE '45.238.170.%' OR dst_ip LIKE '45.238.171.%'
           OR dst_ip LIKE '187.87.201.%' THEN 1 ELSE 0 END AS protected_dst
  FROM orby_ip_pairs_minute
  WHERE source='huawei'
    AND bucket_utc>=UTC_TIMESTAMP()-INTERVAL 65 MINUTE
    AND bucket_utc<UTC_TIMESTAMP()-INTERVAL 5 MINUTE
) AS classified
WHERE protected_src=1 OR protected_dst=1
GROUP BY papel_das_redes,protocol,input_if,output_if,netflow_direction
ORDER BY pares_agregados DESC LIMIT 25;

-- Consulta 3: principais interfaces/direcoes do Huawei, independentemente
-- dos prefixos protegidos (nao mostrar IPs ou pares de clientes).
SELECT
  protocol AS protocolo,
  input_if AS entrada_ifindex,
  output_if AS saida_ifindex,
  netflow_direction AS direcao_raw,
  COUNT(*) AS pares_agregados,
  COUNT(DISTINCT bucket_utc) AS minutos_com_dados,
  ROUND(SUM(total_packets)/3600,1) AS pps_medio_estimado_janela,
  ROUND(SUM(total_bytes)*8/3600000000,3) AS mbps_medio_estimado_janela
FROM orby_ip_pairs_minute
WHERE source='huawei'
  AND bucket_utc>=UTC_TIMESTAMP()-INTERVAL 65 MINUTE
  AND bucket_utc<UTC_TIMESTAMP()-INTERVAL 5 MINUTE
GROUP BY protocol,input_if,output_if,netflow_direction
ORDER BY pares_agregados DESC LIMIT 25;
