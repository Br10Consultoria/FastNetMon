#!/usr/bin/env bash
# Uso de portas por IP publico do pool CGNAT: tabela, permissoes, dashboard "CGNAT - Portas por IP publico" e
# aviso na pagina Saude (80% atencao, 95% critico). Dados do log NAT do A10 (receptor orbymon-a10-nat).
#   sudo bash scripts/setup-cgnat-ports.sh
# O receptor NAT e reiniciado (alguns segundos; o estado volta do log da ultima hora).
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== Tabela ==="
mariadb orbymon < "$BASE/sql/cgnat_ports.sql"
DB_USER=$(sed -n 's/^ORBYMON_DB_USER=//p' /etc/orbymon/pipeline.env | tr -d '"'"'"' ')
[[ "$DB_USER" =~ ^[A-Za-z0-9_]+$ ]] || { echo "ORBYMON_DB_USER invalido em pipeline.env" >&2; exit 1; }
for host in $(mariadb -NBe "SELECT Host FROM mysql.user WHERE User='$DB_USER'"); do
  mariadb -e "GRANT SELECT, INSERT, UPDATE, DELETE ON orbymon.orby_nat_public_minute TO '$DB_USER'@'$host'"
  mariadb -e "GRANT SELECT, INSERT, UPDATE, DELETE ON orbymon.orby_nat_heavy_minute TO '$DB_USER'@'$host'"
done
echo "permissao de gravacao para $DB_USER"

echo "=== Receptor NAT ==="
systemctl restart orbymon-a10-nat
sleep 3
systemctl is-active orbymon-a10-nat

echo "=== Dashboard ==="
bash "$BASE/scripts/deploy-live-dashboards.sh" | grep -i "cgnat-portas" || true
echo "Pronto. Em 1-2 minutos: Grafana > CGNAT - Portas por IP público. Aviso na Saúde acima de 80%."
