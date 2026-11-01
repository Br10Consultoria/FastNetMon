#!/usr/bin/env bash
# Verificacao de saude (coleta, atrasos, disco, servicos, tempo de execucao) com aviso no Telegram.
#   sudo bash scripts/setup-health.sh
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== Tabela ==="
mariadb orbymon < "$BASE/sql/health.sql"
DB_USER=$(sed -n 's/^ORBYMON_DB_USER=//p' /etc/orbymon/pipeline.env | tr -d '"'"'"' ')
[[ "$DB_USER" =~ ^[A-Za-z0-9_]+$ ]] || { echo "ORBYMON_DB_USER invalido em pipeline.env" >&2; exit 1; }
for host in $(mariadb -NBe "SELECT Host FROM mysql.user WHERE User='$DB_USER'"); do
  mariadb -e "GRANT SELECT, INSERT, UPDATE, DELETE ON orbymon.orby_health TO '$DB_USER'@'$host'"
  # leituras usadas nas verificacoes (sem escrita)
  for table in orby_filter_rules orby_filter_rule_state orby_bidir_checks orby_flow_ingested_files; do
    mariadb -e "GRANT SELECT ON orbymon.$table TO '$DB_USER'@'$host'" 2>/dev/null || true
  done
  echo "permissoes concedidas a $DB_USER@$host"
done

echo "=== Timer ==="
install -m 0644 "$BASE/deploy/systemd/orbymon-health.service" /etc/systemd/system/
install -m 0644 "$BASE/deploy/systemd/orbymon-health.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now orbymon-health.timer
systemctl start orbymon-health.service || true
journalctl -u orbymon-health -n 20 --no-pager -o cat || true
echo "Pronto. Painel: pagina Saude."
