#!/usr/bin/env bash
# Alivia o disco/memoria do MariaDB quando os dashboards ficam lentos.
#   sudo bash scripts/tune-database.sh [--pairs-hours 24]
# 1) Limita a 60 s cada consulta do Grafana: painel abandonado (aba fechada, periodo grande) nao fica rodando.
# 2) Encerra agora as consultas do Grafana com mais de 60 s.
# 3) Reduz a retencao dos pares de IP (orby_ip_pairs_minute, usada pelos dashboards Huawei/CGNAT/Visao geral) de
#    72 h para --pairs-hours (padrao 24 h). A limpeza e gradual (50 mil linhas por execucao do ip-huawei).
# Reversivel: rode de novo com --pairs-hours 72.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
HOURS=24
while [[ $# -gt 0 ]]; do
  case "$1" in
    --pairs-hours) HOURS="${2:-}"; shift 2 ;;
    *) echo "opcao desconhecida: $1" >&2; exit 1 ;;
  esac
done
[[ "$HOURS" =~ ^[0-9]+$ ]] && (( HOURS >= 6 && HOURS <= 72 )) || { echo "--pairs-hours entre 6 e 72" >&2; exit 1; }

echo "=== Limite de 60 s por consulta do Grafana ==="
for host in $(mariadb -NBe "SELECT Host FROM mysql.user WHERE User='orbymon_grafana'"); do
  [[ "$host" =~ ^[A-Za-z0-9_.:%-]+$ ]] || continue
  mariadb -e "ALTER USER 'orbymon_grafana'@'$host' WITH MAX_STATEMENT_TIME 60"
  echo "orbymon_grafana@$host: 60 s"
done

echo "=== Consultas do Grafana rodando ha mais de 60 s ==="
n=0
for id in $(mariadb -NBe "SELECT ID FROM information_schema.PROCESSLIST WHERE USER='orbymon_grafana' AND COMMAND='Query' AND TIME>60"); do
  [[ "$id" =~ ^[0-9]+$ ]] && mariadb -e "KILL QUERY $id" 2>/dev/null && n=$((n+1))
done
echo "encerradas: $n"
# conexoes ja abertas mantem o limite antigo: reinicia o Grafana para abrir novas
systemctl restart grafana-server 2>/dev/null && echo "grafana reiniciado" || true

echo "=== Retencao dos pares de IP: ${HOURS} h ==="
D=/etc/systemd/system/orbymon-ip-huawei.service.d
install -d -m 0755 "$D"
cat > "$D/retention.conf" <<CONF
[Service]
ExecStart=
ExecStart=/opt/orbymon/.venv/bin/python -m fmn_filters.ip_analytics --source huawei --retention-hours ${HOURS}
CONF
systemctl daemon-reload
echo "aplicado; a limpeza acontece aos poucos nas proximas execucoes (journalctl -u orbymon-ip-huawei | grep RETENCAO)"

echo "=== Tamanho atual ==="
mariadb orbymon -e "SELECT TABLE_NAME AS tabela, TABLE_ROWS AS linhas_aprox, ROUND((DATA_LENGTH+INDEX_LENGTH)/1e6) AS MB
FROM information_schema.TABLES WHERE TABLE_SCHEMA='orbymon' ORDER BY DATA_LENGTH+INDEX_LENGTH DESC LIMIT 5"
