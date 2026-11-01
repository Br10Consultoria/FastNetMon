#!/usr/bin/env bash
# Clientes (prefixos dedicados) e RADIUS (login PPPoE) nos avisos e na investigacao.
#   sudo bash scripts/setup-customers.sh
# Depois, no painel (pagina Clientes): cadastre os clientes dedicados e o acesso ao radacct.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== Tabelas ==="
mariadb orbymon < "$BASE/sql/customers.sql"
DB_USER=$(sed -n 's/^ORBYMON_DB_USER=//p' /etc/orbymon/pipeline.env | tr -d '"'"'"' ')
[[ "$DB_USER" =~ ^[A-Za-z0-9_]+$ ]] || { echo "ORBYMON_DB_USER invalido em pipeline.env" >&2; exit 1; }
for host in $(mariadb -NBe "SELECT Host FROM mysql.user WHERE User='$DB_USER'"); do
  for table in orby_customers orby_customer_prefixes; do
    mariadb -e "GRANT SELECT ON orbymon.$table TO '$DB_USER'@'$host'"
  done
  echo "leitura dos clientes concedida a $DB_USER@$host"
done
if mariadb -NBe "SELECT 1 FROM mysql.user WHERE User='orbymon_admin'" | grep -q 1; then
  for table in orby_customers orby_customer_prefixes; do
    mariadb -e "GRANT INSERT, UPDATE, DELETE ON orbymon.$table TO 'orbymon_admin'@'127.0.0.1'"
  done
  echo "painel pode editar os clientes"
fi

echo "=== Configuracao do RADIUS (editavel no painel; contem senha) ==="
RAD=/etc/orbymon/radius.env
if [[ ! -e "$RAD" ]]; then
  CONTENT="# RADIUS (radacct) para mostrar o login PPPoE. Editavel no painel, pagina Clientes. Nunca executado.
RADIUS_DB_HOST=''"
  if [[ -d /etc/orbymon/managed ]] && id orbymon-admin >/dev/null 2>&1; then
    printf '%s\n' "$CONTENT" > /etc/orbymon/managed/radius.env
    chown orbymon-admin:orbymon /etc/orbymon/managed/radius.env
    chmod 0640 /etc/orbymon/managed/radius.env
    ln -s /etc/orbymon/managed/radius.env "$RAD"
  else
    printf '%s\n' "$CONTENT" | install -o root -g orbymon -m 0640 /dev/stdin "$RAD"
  fi
fi
echo "$RAD ok"
if [[ -f /etc/orbymon/admin.env ]]; then
  grep -q ORBYMON_RADIUS_ENV /etc/orbymon/admin.env || echo "ORBYMON_RADIUS_ENV='/etc/orbymon/radius.env'" >> /etc/orbymon/admin.env
  systemctl restart orbymon-admin || true
fi
echo "Pronto. Os avisos (Telegram e alarmes por filtro) leem $RAD a cada execucao."
