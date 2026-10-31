-- Investigacao do ponto de observacao Huawei / CGNAT.
-- Somente SELECT. Saida agregada por prefixos IPv4 /16 e categoria de endereco.
-- Nao revela src_ip/dst_ip individuais, mapeamentos NAT ou dados de assinantes.
-- Janela de uma hora consolidada, encerrada cinco minutos antes da consulta.
-- Validar quais prefixos realmente pertencem ao provedor antes de configurar protecao.

-- 1) Em quais prefixos IPv4 /16 aparecem as pontas dos fluxos?
SELECT
  lado,
  prefixo_16,
  COUNT(*) AS pares_agregados,
  COUNT(DISTINCT bucket_utc) AS minutos_com_dados,
  ROUND(SUM(total_packets),0) AS pacotes_estimados
FROM (
  SELECT 'origem' AS lado,
         CONCAT(SUBSTRING_INDEX(src_ip,'.',2),'.0.0/16') AS prefixo_16,
         bucket_utc,total_packets
  FROM orby_ip_pairs_minute
  WHERE source='huawei'
    AND bucket_utc>=UTC_TIMESTAMP()-INTERVAL 65 MINUTE
    AND bucket_utc<UTC_TIMESTAMP()-INTERVAL 5 MINUTE
    AND INET_ATON(src_ip) IS NOT NULL
  UNION ALL
  SELECT 'destino' AS lado,
         CONCAT(SUBSTRING_INDEX(dst_ip,'.',2),'.0.0/16') AS prefixo_16,
         bucket_utc,total_packets
  FROM orby_ip_pairs_minute
  WHERE source='huawei'
    AND bucket_utc>=UTC_TIMESTAMP()-INTERVAL 65 MINUTE
    AND bucket_utc<UTC_TIMESTAMP()-INTERVAL 5 MINUTE
    AND INET_ATON(dst_ip) IS NOT NULL
) AS pontas
GROUP BY lado,prefixo_16
ORDER BY pares_agregados DESC
LIMIT 30;

-- 2) Quais categorias de endereco predominam por interface e direcao?
SELECT
  origem_categoria,
  destino_categoria,
  input_if AS entrada_ifindex,
  output_if AS saida_ifindex,
  netflow_direction AS direcao_raw,
  COUNT(*) AS pares_agregados,
  COUNT(DISTINCT bucket_utc) AS minutos_com_dados,
  ROUND(SUM(total_packets)/3600,1) AS pps_medio_estimado,
  ROUND(SUM(total_bytes)*8/3600000000,3) AS mbps_medio_estimado
FROM (
  SELECT
    bucket_utc,input_if,output_if,netflow_direction,total_packets,total_bytes,
    CASE
      WHEN INET_ATON(src_ip) BETWEEN INET_ATON('100.64.0.0') AND INET_ATON('100.127.255.255')
        THEN 'CGNAT_100.64/10'
      WHEN INET_ATON(src_ip) BETWEEN INET_ATON('10.0.0.0') AND INET_ATON('10.255.255.255')
        OR INET_ATON(src_ip) BETWEEN INET_ATON('172.16.0.0') AND INET_ATON('172.31.255.255')
        OR INET_ATON(src_ip) BETWEEN INET_ATON('192.168.0.0') AND INET_ATON('192.168.255.255')
        THEN 'PRIVADO_RFC1918'
      WHEN INET_ATON(src_ip) IS NULL THEN 'IPv6'
      ELSE 'OUTRO_IPv4'
    END AS origem_categoria,
    CASE
      WHEN INET_ATON(dst_ip) BETWEEN INET_ATON('100.64.0.0') AND INET_ATON('100.127.255.255')
        THEN 'CGNAT_100.64/10'
      WHEN INET_ATON(dst_ip) BETWEEN INET_ATON('10.0.0.0') AND INET_ATON('10.255.255.255')
        OR INET_ATON(dst_ip) BETWEEN INET_ATON('172.16.0.0') AND INET_ATON('172.31.255.255')
        OR INET_ATON(dst_ip) BETWEEN INET_ATON('192.168.0.0') AND INET_ATON('192.168.255.255')
        THEN 'PRIVADO_RFC1918'
      WHEN INET_ATON(dst_ip) IS NULL THEN 'IPv6'
      ELSE 'OUTRO_IPv4'
    END AS destino_categoria
  FROM orby_ip_pairs_minute
  WHERE source='huawei'
    AND bucket_utc>=UTC_TIMESTAMP()-INTERVAL 65 MINUTE
    AND bucket_utc<UTC_TIMESTAMP()-INTERVAL 5 MINUTE
) AS amostra
GROUP BY origem_categoria,destino_categoria,input_if,output_if,netflow_direction
ORDER BY pares_agregados DESC
LIMIT 30;
