#!/usr/bin/env bash
# Etapa 2: excecoes (CIDR/ASN), linha de base por hora e limite dinamico.
#   sudo bash scripts/setup-baseline.sh
# O limite dinamico comeca DESLIGADO: ligue na pagina "Base" do painel depois de alguns dias de linha de base.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== Tabelas ==="
mariadb orbymon < "$BASE/sql/baseline.sql"

DB_USER=$(sed -n 's/^ORBYMON_DB_USER=//p' /etc/orbymon/pipeline.env | tr -d '"'"'"' ')
[[ "$DB_USER" =~ ^[A-Za-z0-9_]+$ ]] || { echo "ORBYMON_DB_USER invalido em pipeline.env" >&2; exit 1; }
for host in $(mariadb -NBe "SELECT Host FROM mysql.user WHERE User='$DB_USER'"); do
  # detector/calibracao leem as excecoes; o sincronizador grava os prefixos; a calibracao grava a base
  mariadb -e "GRANT SELECT, UPDATE, DELETE ON orbymon.orby_exceptions TO '$DB_USER'@'$host'"
  for table in orby_exception_prefixes orby_baseline; do
    mariadb -e "GRANT SELECT, INSERT, UPDATE, DELETE ON orbymon.$table TO '$DB_USER'@'$host'"
  done
  echo "permissoes concedidas a $DB_USER@$host"
done
if mariadb -NBe "SELECT 1 FROM mysql.user WHERE User='orbymon_admin'" | grep -q 1; then
  mariadb -e "GRANT INSERT, UPDATE, DELETE ON orbymon.orby_exceptions TO 'orbymon_admin'@'127.0.0.1'"
  mariadb -e "GRANT INSERT, DELETE ON orbymon.orby_exception_prefixes TO 'orbymon_admin'@'127.0.0.1'"
  echo "painel pode editar as excecoes"
fi

echo "=== Timers ==="
install -m 0644 "$BASE/deploy/systemd/orbymon-exceptions.service" /etc/systemd/system/
install -m 0644 "$BASE/deploy/systemd/orbymon-exceptions.timer" /etc/systemd/system/
install -m 0644 "$BASE/deploy/systemd/orbymon-calibrate.service" /etc/systemd/system/   # agora com --baseline
systemctl daemon-reload
systemctl enable --now orbymon-exceptions.timer
systemctl is-active orbymon-exceptions.timer

echo "=== Primeira linha de base (ultimas 24 h) ==="
if systemctl start orbymon-calibrate.service; then
  mariadb orbymon -e "SELECT daytype AS dia, COUNT(*) AS horas_medidas, MAX(days) AS dias FROM orby_baseline GROUP BY daytype"
else
  echo "calibracao falhou: journalctl -u orbymon-calibrate -n 30 --no-pager"
fi
echo "Pronto. Painel: paginas Excecoes e Base. O limite dinamico so passa a valer com alguns dias de base por hora (padrao 3, ajustavel)."
