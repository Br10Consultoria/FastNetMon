#!/usr/bin/env bash
# Restaura um backup do OrbyMon (feito por orbymon-backup.sh), no mesmo servidor ou num servidor novo.
#
#   sudo bash scripts/orbymon-restore.sh ARQUIVO              # mostra o conteudo e o que seria feito
#   sudo bash scripts/orbymon-restore.sh ARQUIVO --yes [--only etc|db|history|grafana]
#
# Servidor novo: instale o OrbyMon (prepare-ubuntu + setup-*), restaure com --yes e rode de novo os setup-* para
# recriar usuarios/permissoes do banco e as units. A configuracao atual vai para /etc/orbymon.antes-restore-<data>.
set -euo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo "Execute como root" >&2; exit 1; }
FILE="${1:-}"; shift || true
YES=0 ONLY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes) YES=1; shift ;;
    --only) ONLY="$2"; shift 2 ;;
    *) echo "opcao desconhecida: $1" >&2; exit 1 ;;
  esac
done
[[ -f "$FILE" ]] || { echo "uso: $0 ARQUIVO [--yes] [--only etc|db|history|grafana]" >&2; exit 1; }
[[ -z "$ONLY" || "$ONLY" =~ ^(etc|db|history|grafana)$ ]] || { echo "--only: etc, db, history ou grafana" >&2; exit 1; }
KEY="${ORBYMON_BACKUP_KEY:-/etc/orbymon/backup.key}"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
if [[ "$FILE" == *.enc ]]; then
  [[ -f "$KEY" ]] || { echo "backup cifrado: copie a chave para $KEY (root, 0600)" >&2; exit 1; }
  openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass "file:$KEY" -in "$FILE" -out "$WORK/b.tar.gz"
else
  cp "$FILE" "$WORK/b.tar.gz"
fi
mkdir "$WORK/b"
tar -C "$WORK/b" -xzf "$WORK/b.tar.gz"
cat "$WORK/b/MANIFEST.txt"
want() { [[ -z "$ONLY" || "$ONLY" == "$1" ]]; }

if [[ $YES -ne 1 ]]; then
  echo
  echo "Nada foi alterado. Para restaurar: $0 $FILE --yes [--only etc|db|history|grafana]"
  exit 0
fi

TIMERS=$( (systemctl list-units 'orbymon-*.timer' --state=active --plain --no-legend 2>/dev/null || true) | awk '{print $1}')
echo "=== Pausando timers ==="
[[ -z "$TIMERS" ]] || systemctl stop $TIMERS

if want etc && [[ -f "$WORK/b/etc.tar" ]]; then
  echo "=== /etc/orbymon ==="
  [[ -d /etc/orbymon ]] && cp -a /etc/orbymon "/etc/orbymon.antes-restore-$(date +%Y%m%d%H%M%S)"
  tar -C / -xpf "$WORK/b/etc.tar"
fi
if want db && [[ -f "$WORK/b/db-config.sql" ]]; then
  echo "=== Banco: configuracao ==="
  mariadb orbymon < "$WORK/b/db-config.sql"
fi
if want history && [[ -f "$WORK/b/db-history.sql" ]]; then
  echo "=== Banco: historico ==="
  mariadb orbymon < "$WORK/b/db-history.sql"
fi
if want grafana && [[ -d "$WORK/b/grafana" ]]; then
  echo "=== Grafana ==="
  systemctl stop grafana-server 2>/dev/null || true
  [[ -f "$WORK/b/grafana/provisioning.tar" ]] && tar -C / -xpf "$WORK/b/grafana/provisioning.tar"
  if [[ -f "$WORK/b/grafana/grafana.db" ]]; then
    [[ -f /var/lib/grafana/grafana.db ]] && cp -a /var/lib/grafana/grafana.db "/var/lib/grafana/grafana.db.antes-restore-$(date +%Y%m%d%H%M%S)"
    install -o grafana -g grafana -m 0640 "$WORK/b/grafana/grafana.db" /var/lib/grafana/grafana.db
  fi
  systemctl start grafana-server 2>/dev/null || true
fi

echo "=== Retomando timers ==="
[[ -z "$TIMERS" ]] || systemctl start $TIMERS
systemctl restart orbymon-admin 2>/dev/null || true
echo "Restaurado. Em servidor novo, rode de novo: setup-bidir, setup-admin, setup-telegram (sem --chat), setup-reputation,"
echo "setup-filter-rules, setup-baseline, setup-health, setup-customers, setup-backup (recriam usuarios, permissoes e units)."
