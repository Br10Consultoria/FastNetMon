#!/usr/bin/env bash
# Alarmes por filtro: tabelas, modelos (desligados), permissoes e timer de 1 minuto.
#   sudo bash scripts/setup-filter-rules.sh
# Depois, no painel (pagina Alarmes): abra um modelo, clique Testar, ajuste e ligue.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== Tabelas e modelos ==="
mariadb orbymon < "$BASE/sql/filter_rules.sql"

DB_USER=$(sed -n 's/^ORBYMON_DB_USER=//p' /etc/orbymon/pipeline.env | tr -d '"'"'"' ')
[[ "$DB_USER" =~ ^[A-Za-z0-9_]+$ ]] || { echo "ORBYMON_DB_USER invalido em pipeline.env" >&2; exit 1; }
for host in $(mariadb -NBe "SELECT Host FROM mysql.user WHERE User='$DB_USER'"); do
  mariadb -e "GRANT SELECT ON orbymon.orby_filter_rules TO '$DB_USER'@'$host'"
  for table in orby_filter_rule_state orby_filter_rule_samples orby_filter_incidents; do
    mariadb -e "GRANT SELECT, INSERT, UPDATE, DELETE ON orbymon.$table TO '$DB_USER'@'$host'"
  done
  echo "permissoes dos alarmes concedidas a $DB_USER@$host"
done
if mariadb -NBe "SELECT 1 FROM mysql.user WHERE User='orbymon_admin'" | grep -q 1; then
  mariadb -e "GRANT INSERT, UPDATE, DELETE ON orbymon.orby_filter_rules TO 'orbymon_admin'@'127.0.0.1'"
  echo "painel pode editar os alarmes"
fi

echo "=== Timer ==="
install -m 0644 "$BASE/deploy/systemd/orbymon-filter-rules.service" /etc/systemd/system/
install -m 0644 "$BASE/deploy/systemd/orbymon-filter-rules.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now orbymon-filter-rules.timer
systemctl is-active orbymon-filter-rules.timer
mariadb orbymon -e "SELECT id, enabled AS ligado, name AS alarme FROM orby_filter_rules ORDER BY id"
echo "Pronto. Logs: journalctl -u orbymon-filter-rules -n 30 --no-pager"
