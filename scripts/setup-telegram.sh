#!/usr/bin/env bash
# Configura os alertas de ataque no Telegram.
#  1. No Telegram, fale com @BotFather -> /newbot -> copie o token.
#  2. Mande uma mensagem ao bot (ou adicione o bot a um grupo e escreva algo no grupo).
#  3. sudo bash scripts/setup-telegram.sh            (pede o token e mostra os chats encontrados)
#  4. sudo bash scripts/setup-telegram.sh --chat ID  (grava, envia teste e ativa o timer)
# Opcoes: --min-severity warning|high|critical (padrao high)  --grafana-url URL  --site NOME
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"
PY="$BASE/.venv/bin/python"
ENV_FILE=$(readlink -f /etc/orbymon/telegram.env 2>/dev/null || echo /etc/orbymon/telegram.env)
ENV_OWNER=$(stat -c %u "$ENV_FILE" 2>/dev/null || echo 0)   # preserva o dono (painel web)
CHAT="" SEV="high" SITE="" GRAFANA=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --chat) CHAT="$2"; shift 2 ;;
    --min-severity) SEV="$2"; shift 2 ;;
    --grafana-url) GRAFANA="$2"; shift 2 ;;
    --site) SITE="$2"; shift 2 ;;
    *) echo "opcao desconhecida: $1" >&2; exit 1 ;;
  esac
done
[[ "$SEV" =~ ^(warning|high|critical)$ ]] || { echo "--min-severity: warning, high ou critical" >&2; exit 1; }
[[ -z "$CHAT" || "$CHAT" =~ ^-?[0-9]+(,-?[0-9]+)*$ ]] || { echo "--chat deve ser numerico (ex.: -1001234567890)" >&2; exit 1; }

TOKEN=""
if [[ -s "$ENV_FILE" ]]; then
  TOKEN=$(sed -n 's/^TELEGRAM_BOT_TOKEN=//p' "$ENV_FILE" | tail -n 1 | sed -e "s/^'\(.*\)'\$/\1/" -e 's/^"\(.*\)"$/\1/')
fi
if [[ -z "$TOKEN" ]]; then
  read -rsp "Token do bot (do @BotFather; nao aparece na tela): " TOKEN; echo
fi
[[ "$TOKEN" =~ ^[0-9]+:[A-Za-z0-9_-]{30,}$ ]] || { echo "Token com formato invalido" >&2; exit 1; }
if [[ -z "$GRAFANA" ]]; then
  GRAFANA="https://$(hostname -I | awk '{print $1}'):3000"
fi

if [[ -z "$CHAT" ]]; then
  echo "=== Chats que ja falaram com o bot ==="
  TELEGRAM_BOT_TOKEN="$TOKEN" PYTHONPATH="$BASE/src" "$PY" -m fmn_filters.notify_telegram --find-chat
  echo
  echo "Escolha o chat_id e rode: sudo bash $0 --chat <chat_id>   (grupos comecam com -100)"
  # guarda o token para a proxima execucao nao pedir de novo
  install -o "$ENV_OWNER" -g orbymon -m 0640 /dev/stdin "$ENV_FILE" <<ENV
TELEGRAM_BOT_TOKEN='$TOKEN'
TELEGRAM_CHAT_IDS=''
ENV
  exit 0
fi

FIRST=0
grep -Eq "^TELEGRAM_CHAT_IDS='?-?[0-9]" "$ENV_FILE" 2>/dev/null || FIRST=1
[[ "$GRAFANA$SITE" != *"'"* && "$GRAFANA$SITE" != *\\* ]] || { echo "--site/--grafana-url sem aspas simples ou barra invertida" >&2; exit 1; }
install -o "$ENV_OWNER" -g orbymon -m 0640 /dev/stdin "$ENV_FILE" <<ENV
# Alertas OrbyFlow no Telegram (arquivo com segredo: nao compartilhe). Tambem editavel no painel web.
TELEGRAM_BOT_TOKEN='$TOKEN'
TELEGRAM_CHAT_IDS='$CHAT'
ORBYMON_NOTIFY_MIN_SEVERITY='$SEV'
ORBYMON_NOTIFY_REMINDER_MIN='30'
ORBYMON_NOTIFY_CLOSE_AFTER_MIN='20'
ORBYMON_GRAFANA_URL='$GRAFANA'
ORBYMON_TZ='America/Bahia'
ORBYMON_SITE_NAME='$SITE'
ENV

echo "=== Tabelas de notificacao ==="
mariadb orbymon < "$BASE/sql/bidir.sql"
if [[ $FIRST -eq 1 ]]; then
  # comeca do zero: eventos antigos nao viram uma enxurrada de mensagens
  mariadb orbymon -e "UPDATE orby_attack_events SET notified_at=UTC_TIMESTAMP() WHERE notified_at IS NULL"
fi

echo "=== Mensagem de teste ==="
# o arquivo e lido como dados (nunca executado com source)
PYTHONPATH="$BASE/src" "$PY" -m fmn_filters.notify_telegram --env-file "$ENV_FILE" --test

install -m 0644 "$BASE/deploy/systemd/orbymon-telegram.service" /etc/systemd/system/
install -m 0644 "$BASE/deploy/systemd/orbymon-telegram.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now orbymon-telegram.timer
systemctl is-active orbymon-telegram.timer
echo "Alertas ativos (severidade >= $SEV). Logs: journalctl -u orbymon-telegram -n 20 --no-pager"
