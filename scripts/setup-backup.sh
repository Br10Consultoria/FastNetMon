#!/usr/bin/env bash
# Backup diario do OrbyMon (configuracao, banco de configuracao/historico e Grafana).
#   sudo bash scripts/setup-backup.sh             # instala o timer (03:37) e faz o primeiro backup
#   sudo bash scripts/setup-backup.sh --encrypt   # tambem cria a chave de criptografia (/etc/orbymon/backup.key)
# Copia para fora do servidor: ORBYMON_ARCHIVE_CMD em /etc/orbymon/retention-archive.conf (ex.: rclone).
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"
ENCRYPT=0
[[ "${1:-}" == "--encrypt" ]] && ENCRYPT=1

DIR=/var/lib/orbymon/backups
install -d -o root -g orbymon -m 0750 "$DIR"
if id orbymon-admin >/dev/null 2>&1 && command -v setfacl >/dev/null; then
  setfacl -m u:orbymon-admin:rx "$DIR"          # painel so lista (os arquivos sao 0600 do root)
fi
if [[ ! -e /etc/orbymon/backup.conf ]]; then
  install -o root -g root -m 0600 /dev/stdin /etc/orbymon/backup.conf <<CONF
# Backup do OrbyMon (somente root). Lido como dados.
ORBYMON_BACKUP_DIR=$DIR
ORBYMON_BACKUP_KEEP=14
ORBYMON_BACKUP_HISTORY=1
CONF
fi
if [[ $ENCRYPT -eq 1 && ! -e /etc/orbymon/backup.key ]]; then
  openssl rand -base64 48 | install -o root -g root -m 0600 /dev/stdin /etc/orbymon/backup.key
  echo "Chave criada: /etc/orbymon/backup.key"
  echo "GUARDE UMA COPIA DESSA CHAVE FORA DO SERVIDOR (cofre de senhas). Sem ela os backups cifrados nao abrem."
fi
chmod 0755 "$BASE/scripts/orbymon-backup.sh" "$BASE/scripts/orbymon-restore.sh"
install -m 0644 "$BASE/deploy/systemd/orbymon-backup.service" /etc/systemd/system/
install -m 0644 "$BASE/deploy/systemd/orbymon-backup.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now orbymon-backup.timer
echo "=== Primeiro backup ==="
systemctl start orbymon-backup.service && journalctl -u orbymon-backup -n 8 --no-pager -o cat
ls -lh "$DIR"
echo "Restaurar: sudo bash $BASE/scripts/orbymon-restore.sh $DIR/<arquivo>   (sem --yes so mostra o conteudo)"
