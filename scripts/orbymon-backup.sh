#!/usr/bin/env bash
# Backup diario do OrbyFlow (executado como root pelo orbymon-backup.timer; tambem pode ser rodado a mao).
#
# Conteudo (um arquivo orbymon-backup-AAAAMMDD-HHMMSS.tar.gz):
#   etc/orbymon/...        configuracao completa (inclui segredos: token do Telegram, senhas de banco/API)
#   db-config.sql          tabelas de configuracao: usuarios do painel, regras/alarmes, filtros salvos, excecoes,
#                          clientes, linha de base, nomes de interface
#   db-history.sql         historico: eventos de ataque, incidentes, listas de reputacao, auditoria
#   grafana/               provisionamento e banco do Grafana (dashboards editados na interface)
#   MANIFEST.txt           versao do OrbyFlow, servidor, data e tamanhos
# Fluxos (nfcapd) e logs NAT NAO entram: sao grandes e ja tem retencao/arquivamento proprios.
#
# Opcoes (arquivo /etc/orbymon/backup.conf, somente root):
#   ORBYMON_BACKUP_DIR=/var/lib/orbymon/backups   ORBYMON_BACKUP_KEEP=14   ORBYMON_BACKUP_HISTORY=1
# Criptografia: se existir /etc/orbymon/backup.key (root, 0600), o arquivo sai cifrado (.tar.gz.enc, AES-256).
# Copia externa: ORBYMON_ARCHIVE_CMD de /etc/orbymon/retention-archive.conf (ex.: rclone copy {} remoto:orbymon/).
set -euo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo "Execute como root" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"
CONF="${ORBYMON_BACKUP_CONF:-/etc/orbymon/backup.conf}"
KEY="${ORBYMON_BACKUP_KEY:-/etc/orbymon/backup.key}"
ARCHIVE_CONF="${ORBYMON_ARCHIVE_CONF:-/etc/orbymon/retention-archive.conf}"

conf_value() {   # conf_value <arquivo> <CHAVE>: valor sem aspas (arquivo lido como dados, nunca executado)
  [[ -f "$1" ]] || return 0
  sed -n "s/^$2=//p" "$1" | tail -n 1 | sed -e "s/^'\(.*\)'\$/\1/" -e 's/^"\(.*\)"$/\1/'
}
root_only() {    # arquivos que influenciam comandos como root precisam ser do root e sem escrita de outros
  [[ -f "$1" && ! -L "$1" && "$(stat -c '%u' "$1")" == 0 && $(( 0$(stat -c '%a' "$1") & 022 )) -eq 0 ]]
}

DIR=/var/lib/orbymon/backups KEEP=14 HISTORY=1
if root_only "$CONF"; then
  DIR="$(conf_value "$CONF" ORBYMON_BACKUP_DIR)"; DIR="${DIR:-/var/lib/orbymon/backups}"
  KEEP="$(conf_value "$CONF" ORBYMON_BACKUP_KEEP)"; KEEP="${KEEP:-14}"
  HISTORY="$(conf_value "$CONF" ORBYMON_BACKUP_HISTORY)"; HISTORY="${HISTORY:-1}"
elif [[ -e "$CONF" ]]; then
  echo "IGNORADO $CONF: precisa ser do root e sem escrita para grupo/outros" >&2
fi
[[ "$DIR" == /* && "$KEEP" =~ ^[0-9]+$ && "$KEEP" -ge 1 ]] || { echo "configuracao de backup invalida" >&2; exit 1; }
install -d -o root -g orbymon -m 0750 "$DIR" 2>/dev/null || install -d -m 0750 "$DIR"

STAMP=$(date +%Y%m%d-%H%M%S)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/b"

echo "=== Configuracao (/etc/orbymon) ==="
tar -C / -cf "$WORK/b/etc.tar" etc/orbymon

echo "=== Banco (configuracao) ==="
CONFIG_TABLES="orby_admin_users orby_interface_names orby_saved_filters orby_filter_rules orby_exceptions
orby_exception_prefixes orby_baseline orby_customers orby_customer_prefixes orby_net_prefixes"
HISTORY_TABLES="orby_attack_events orby_filter_incidents orby_notify_incidents orby_reputation_listings
orby_reputation_sources orby_admin_audit"
existing() {     # so as tabelas que existem (etapas ainda nao instaladas sao puladas)
  local out=""
  for t in $1; do
    mariadb -NBe "SHOW TABLES FROM orbymon LIKE '$t'" | grep -qx "$t" && out="$out $t"
  done
  echo "$out"
}
TABLES=$(existing "$CONFIG_TABLES")
[[ -n "$TABLES" ]] && mariadb-dump --single-transaction --skip-lock-tables orbymon $TABLES > "$WORK/b/db-config.sql"
if [[ "$HISTORY" == 1 ]]; then
  echo "=== Banco (historico) ==="
  TABLES=$(existing "$HISTORY_TABLES")
  [[ -n "$TABLES" ]] && mariadb-dump --single-transaction --skip-lock-tables orbymon $TABLES > "$WORK/b/db-history.sql"
fi

if [[ -d /etc/grafana || -f /var/lib/grafana/grafana.db ]]; then
  echo "=== Grafana ==="
  mkdir -p "$WORK/b/grafana"
  [[ -d /etc/grafana/provisioning ]] && tar -C / -cf "$WORK/b/grafana/provisioning.tar" etc/grafana/provisioning
  if [[ -f /var/lib/grafana/grafana.db ]]; then
    if command -v sqlite3 >/dev/null; then
      sqlite3 /var/lib/grafana/grafana.db ".backup '$WORK/b/grafana/grafana.db'"   # copia consistente
    else
      cp /var/lib/grafana/grafana.db "$WORK/b/grafana/grafana.db"
    fi
  fi
fi

{
  echo "OrbyFlow backup $STAMP"
  echo "servidor: $(hostname)"
  echo "versao: $(git -C "$BASE" rev-parse --short HEAD 2>/dev/null || echo desconhecida)"
  (cd "$WORK/b" && find . -type f -printf '%P %s\n' | sort)
} > "$WORK/b/MANIFEST.txt"

OUT="$DIR/orbymon-backup-$STAMP.tar.gz"
tar -C "$WORK/b" -czf "$WORK/out.tar.gz" .
if [[ -f "$KEY" ]]; then
  root_only "$KEY" || { echo "$KEY precisa ser do root e 0600" >&2; exit 1; }
  OUT="$OUT.enc"
  openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass "file:$KEY" -in "$WORK/out.tar.gz" -out "$WORK/out.enc"
  mv "$WORK/out.enc" "$OUT"
else
  mv "$WORK/out.tar.gz" "$OUT"
fi
chmod 0600 "$OUT"
echo "backup: $OUT ($(du -h "$OUT" | cut -f1))"

ARCHIVE=""
if root_only "$ARCHIVE_CONF"; then
  ARCHIVE="$(conf_value "$ARCHIVE_CONF" ORBYMON_ARCHIVE_CMD)"
fi
if [[ -n "$ARCHIVE" ]]; then
  [[ -f "$KEY" ]] || echo "AVISO: enviando backup SEM criptografia (crie $KEY para cifrar)" >&2
  if bash -c "${ARCHIVE//\{\}/\"$OUT\"}"; then echo "copia externa: ok"; else echo "AVISO: copia externa falhou" >&2; fi
fi

# rotacao: mantem os KEEP mais recentes
ls -1t "$DIR"/orbymon-backup-*.tar.gz* 2>/dev/null | tail -n +"$((KEEP + 1))" | while read -r old; do
  rm -f -- "$old"; echo "removido: $old"
done
