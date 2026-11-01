#!/usr/bin/env bash
# Retencao de arquivos do OrbyFlow (executado de hora em hora pelo systemd).
#  - compacta logs NAT por hora (TSV) assim que a hora termina;
#  - apaga, apos N dias: logs NAT, spool antigo do rsyslog do A10 e arquivos nfcapd;
#  - opcional: ORBYMON_ARCHIVE_CMD envia o arquivo para a nuvem ANTES de apagar
#    (ex.: "rclone copy {} remoto:orbymon/"); se o envio falhar, o arquivo NAO e apagado.
# Configuracao (lida como dados; os arquivos nunca sao executados):
#   /etc/orbymon/retention.env (editavel pelo painel web)
#     ORBYMON_LOG_RETENTION_DAYS=15     (logs NAT e spool A10)
#     ORBYMON_FLOW_RETENTION_DAYS=15    (arquivos nfcapd)
#   /etc/orbymon/retention-archive.conf (somente root; nunca pelo painel, pois roda como root)
#     ORBYMON_ARCHIVE_CMD=rclone copy {} remoto:orbymon/    (vazio = nao envia; {} = caminho)
set -euo pipefail
RET_ENV="${ORBYMON_RETENTION_ENV:-/etc/orbymon/retention.env}"
ARCHIVE_CONF="${ORBYMON_ARCHIVE_CONF:-/etc/orbymon/retention-archive.conf}"

env_value() {   # env_value <arquivo> <CHAVE>: valor sem aspas, ou vazio
  [[ -f "$1" ]] || return 0
  sed -n "s/^$2=//p" "$1" | tail -n 1 | sed -e "s/^'\(.*\)'\$/\1/" -e 's/^"\(.*\)"$/\1/'
}

LOG_DAYS="$(env_value "$RET_ENV" ORBYMON_LOG_RETENTION_DAYS)"; LOG_DAYS="${LOG_DAYS:-15}"
FLOW_DAYS="$(env_value "$RET_ENV" ORBYMON_FLOW_RETENTION_DAYS)"; FLOW_DAYS="${FLOW_DAYS:-15}"
ARCHIVE=""
if [[ -f "$ARCHIVE_CONF" && ! -L "$ARCHIVE_CONF" ]]; then
  # o comando roda como root: so vale se o arquivo for do root e ninguem mais puder escrever
  if [[ "$(stat -c '%u' "$ARCHIVE_CONF")" == 0 && $(( 0$(stat -c '%a' "$ARCHIVE_CONF") & 022 )) -eq 0 ]]; then
    ARCHIVE="$(env_value "$ARCHIVE_CONF" ORBYMON_ARCHIVE_CMD)"
  else
    echo "IGNORADO $ARCHIVE_CONF: precisa ser do root e sem escrita para grupo/outros" >&2
  fi
fi
NAT_DIR="${ORBYMON_NAT_DIR:-/var/log/orbymon/a10nat}"
SPOOL_DIR="${ORBYMON_SPOOL_DIR:-/var/log/orbymon/a10}"
FLOW_DIR="${ORBYMON_FLOW_DIR:-/var/lib/orbymon/flows}"

for value in "$LOG_DAYS" "$FLOW_DAYS"; do
  [[ "$value" =~ ^[0-9]+$ && "$value" -ge 1 ]] || { echo "retencao invalida: $value" >&2; exit 1; }
done

expire() {   # expire <arquivo>: arquiva (se configurado) e apaga
  local file="$1"
  if [[ -n "$ARCHIVE" ]]; then
    if ! bash -c "${ARCHIVE//\{\}/\"$file\"}"; then
      echo "ARQUIVAMENTO FALHOU, mantido: $file" >&2
      return 0
    fi
  fi
  rm -f -- "$file"
  echo "removido: $file"
}

# 1) compactar logs NAT de horas ja encerradas
if [[ -d "$NAT_DIR" ]]; then
  find "$NAT_DIR" -maxdepth 1 -type f -name 'nat-events-*.tsv' -mmin +65 -print0 |
    xargs -0 -r gzip -9
  find "$NAT_DIR" -maxdepth 1 -type f -name 'nat-events-*.tsv.gz' -mtime +"$((LOG_DAYS - 1))" -print0 |
    while IFS= read -r -d '' f; do expire "$f"; done
fi

# 2) spool antigo do rsyslog (somente arquivos rotacionados; nunca o arquivo ativo)
if [[ -d "$SPOOL_DIR" ]]; then
  find "$SPOOL_DIR" -maxdepth 1 -type f -name 'a10-current.ndjson-*' -mtime +"$((LOG_DAYS - 1))" -print0 |
    while IFS= read -r -d '' f; do expire "$f"; done
fi

# 3) arquivos nfcapd de cada coletor
if [[ -d "$FLOW_DIR" ]]; then
  find "$FLOW_DIR" -mindepth 2 -maxdepth 2 -type f -name 'nfcapd.20*' -mtime +"$((FLOW_DAYS - 1))" -delete
fi

df -h "$NAT_DIR" "$FLOW_DIR" 2>/dev/null | tail -n +2 || true
