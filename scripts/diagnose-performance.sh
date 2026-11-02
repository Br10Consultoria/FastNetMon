#!/usr/bin/env bash
# Diagnostico de desempenho (somente leitura). Rode e mande a saida:  sudo bash scripts/diagnose-performance.sh
set -uo pipefail
echo "=== Memoria (buff/cache e memoria reaproveitavel, nao falta) ==="; free -h
echo; echo "=== CPU e espera de disco (wa) em 5 s ==="; vmstat 1 5
echo; echo "=== Disco ==="; df -h / /var/lib/mysql /var/lib/orbymon 2>/dev/null | sort -u
echo; echo "=== MariaDB: memoria e conexoes ==="
mariadb -NBe "SELECT CONCAT(VARIABLE_NAME,'=',VARIABLE_VALUE) FROM information_schema.GLOBAL_VARIABLES WHERE VARIABLE_NAME IN
('INNODB_BUFFER_POOL_SIZE','TMP_TABLE_SIZE','MAX_HEAP_TABLE_SIZE','MAX_CONNECTIONS','INNODB_FLUSH_LOG_AT_TRX_COMMIT')"
echo; echo "=== Maiores tabelas ==="
mariadb orbymon -e "SELECT TABLE_NAME AS tabela, TABLE_ROWS AS linhas_aprox, ROUND((DATA_LENGTH+INDEX_LENGTH)/1e6) AS MB
FROM information_schema.TABLES WHERE TABLE_SCHEMA='orbymon' ORDER BY DATA_LENGTH+INDEX_LENGTH DESC LIMIT 12"
echo; echo "=== Linhas do detalhado por minuto (ultima hora) ==="
mariadb orbymon -e "SELECT COUNT(*)/60 AS linhas_por_minuto FROM orby_flow_minute WHERE bucket_utc>=UTC_TIMESTAMP()-INTERVAL 1 HOUR"
echo; echo "=== Consultas rodando ha mais de 5 s ==="
mariadb -e "SELECT ID,USER,TIME,STATE,LEFT(INFO,160) AS consulta FROM information_schema.PROCESSLIST WHERE COMMAND<>'Sleep' AND TIME>5 ORDER BY TIME DESC"
echo; echo "=== Atraso da coleta ==="
mariadb orbymon -e "SELECT TIMESTAMPDIFF(MINUTE,MAX(bucket_utc),UTC_TIMESTAMP()) AS rollup_min_atras FROM orby_flow_minute;
SELECT TIMESTAMPDIFF(MINUTE,MAX(bucket_utc),UTC_TIMESTAMP()) AS ip_pairs_min_atras FROM orby_ip_pairs_minute" 2>/dev/null
echo; echo "=== Duracao das ultimas execucoes ==="
for u in orbymon-flow-rollup-huawei orbymon-ip-huawei orbymon-traffic-huawei orbymon-bidir-huawei orbymon-ddos-huawei orbymon-filter-rules; do
  journalctl -u "$u" -n 200 --no-pager -o cat 2>/dev/null | grep -E "Consumed|Finished|Failed" | tail -n 2 | sed "s/^/$u: /"
done
echo; echo "=== Processos que mais usam memoria ==="; ps -eo rss,comm --sort=-rss | head -8
