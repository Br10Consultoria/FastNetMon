#!/usr/bin/env bash
# Ajuste do MariaDB para o volume do NetStream completo (milhares de linhas por minuto).
#  - innodb_buffer_pool_size: ~40% da RAM (minimo 1 GB, maximo 8 GB); o padrao do Ubuntu e 128 MB
#  - innodb_flush_log_at_trx_commit=2: grava o log no disco 1x por segundo em vez de a cada commit.
#    Em queda de energia perde no maximo ~1 s de metricas; o checkpoint de arquivo fica na mesma
#    transacao dos dados, entao o arquivo e reimportado e nada fica pela metade.
# Uso: sudo bash scripts/tune-mariadb.sh            (mostra o que faria, nao altera)
#      sudo bash scripts/tune-mariadb.sh --apply    (grava a configuracao e reinicia o MariaDB)
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
MEMINFO="${ORBYMON_MEMINFO:-/proc/meminfo}"
CNF_DIR="${ORBYMON_CNF_DIR:-/etc/mysql/mariadb.conf.d}"
CNF="$CNF_DIR/60-orbymon.cnf"

ram_kb=$(awk '/^MemTotal:/ {print $2}' "$MEMINFO")
ram_mb=$((ram_kb / 1024))
pool_mb=$((ram_mb * 40 / 100))
(( pool_mb < 1024 )) && pool_mb=1024
(( pool_mb > 8192 )) && pool_mb=8192
pool_mb=$((pool_mb / 512 * 512))
if (( ram_mb < 3072 )); then
  echo "RAM de ${ram_mb} MB e pequena para o NetStream completo; aumente a VM antes de ajustar." >&2
  exit 1
fi

NEW=$(cat <<EOF
# Gerado por scripts/tune-mariadb.sh (OrbyMon)
[mysqld]
innodb_buffer_pool_size = ${pool_mb}M
innodb_flush_log_at_trx_commit = 2
innodb_log_file_size = 512M
innodb_flush_method = O_DIRECT
EOF
)

echo "RAM total: ${ram_mb} MB -> innodb_buffer_pool_size = ${pool_mb} MB"
if command -v mariadb >/dev/null && [[ -z "${ORBYMON_CNF_DIR:-}" ]]; then
  echo "Valores atuais:"
  mariadb -NBe "SELECT CONCAT('  ',VARIABLE_NAME,' = ',VARIABLE_VALUE) FROM information_schema.GLOBAL_VARIABLES
                WHERE VARIABLE_NAME IN ('INNODB_BUFFER_POOL_SIZE','INNODB_FLUSH_LOG_AT_TRX_COMMIT',
                                        'INNODB_LOG_FILE_SIZE','INNODB_FLUSH_METHOD')" || true
fi
echo "--- configuracao proposta ($CNF):"
echo "$NEW"

[[ "${1:-}" == "--apply" ]] || { echo "--- nada alterado. Para aplicar: sudo bash $0 --apply"; exit 0; }

BACKUP=""
if [[ -e "$CNF" ]]; then
  BACKUP="$CNF.bak.$(date +%Y%m%d%H%M%S)"
  cp -p "$CNF" "$BACKUP"
fi
printf '%s\n' "$NEW" > "$CNF"
chmod 0644 "$CNF"
[[ -n "${ORBYMON_CNF_DIR:-}" ]] && { echo "modo teste: arquivo gravado em $CNF"; exit 0; }

echo "Reiniciando MariaDB (os pipelines retomam sozinhos no proximo ciclo)..."
if ! systemctl restart mariadb || ! systemctl is-active --quiet mariadb; then
  echo "MariaDB nao subiu com a configuracao nova; revertendo." >&2
  if [[ -n "$BACKUP" ]]; then cp -p "$BACKUP" "$CNF"; else rm -f "$CNF"; fi
  systemctl restart mariadb
  systemctl is-active mariadb
  exit 1
fi
mariadb -NBe "SELECT CONCAT('  ',VARIABLE_NAME,' = ',VARIABLE_VALUE) FROM information_schema.GLOBAL_VARIABLES
              WHERE VARIABLE_NAME IN ('INNODB_BUFFER_POOL_SIZE','INNODB_FLUSH_LOG_AT_TRX_COMMIT')"
echo "MariaDB ativo com a configuracao nova."
