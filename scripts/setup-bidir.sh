#!/usr/bin/env bash
# Instala a F4: receptor NAT do A10, rollup bidirecional e detector (entrada/saida).
# Somente alertas: nao altera Huawei, A10, firewall nem faz bloqueio.
# Uso: sudo bash scripts/setup-bidir.sh [--no-start] [--replace-config]
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
START=1
REPLACE_CONFIG=0
for arg in "$@"; do
  case "$arg" in
    --no-start) START=0 ;;
    --replace-config) REPLACE_CONFIG=1 ;;   # backup + instala o exemplo atual (regras novas)
    *) echo "opcao desconhecida: $arg" >&2; exit 1 ;;
  esac
done
BASE="$(cd "$(dirname "$0")/.." && pwd)"
PY="$BASE/.venv/bin/python"
[[ -x "$PY" ]] || { echo "venv Python ausente ($BASE/.venv)" >&2; exit 1; }
[[ -s /etc/orbymon/pipeline.env ]] || { echo "pipeline.env da Fase 1 ausente" >&2; exit 1; }
for table in orby_alerts orby_ip_pairs_minute; do
  mariadb orbymon -NBe "SHOW TABLES LIKE '$table'" | grep -qx "$table" || {
    echo "Tabela $table ausente: instale as fases 1 e 2 antes (setup-ip-analytics.sh)" >&2; exit 1; }
done
[[ -s /etc/orbymon/cgnat-profiles.json ]] || {
  echo "Perfil CGNAT ausente: execute antes sudo bash scripts/setup-cgnat-baseline.sh" >&2; exit 1; }

echo "=== Tabelas F4 ==="
mariadb orbymon < "$BASE/sql/bidir.sql"

echo "=== Permissao de limpeza (DELETE) para o usuario do pipeline ==="
DB_USER=$(sed -n 's/^ORBYMON_DB_USER=//p' /etc/orbymon/pipeline.env | tr -d '"'"'"' ')
[[ "$DB_USER" =~ ^[A-Za-z0-9_]+$ ]] || { echo "ORBYMON_DB_USER invalido em pipeline.env" >&2; exit 1; }
HOSTS=$(mariadb -NBe "SELECT Host FROM mysql.user WHERE User='$DB_USER'")
[[ -n "$HOSTS" ]] || { echo "Usuario $DB_USER nao existe no MariaDB" >&2; exit 1; }
for host in $HOSTS; do
  for table in orby_flow_minute orby_nat_user_minute orby_flow_ingested_files \
               orby_ip_pairs_minute orby_ip_ingested_files; do
    mariadb -e "GRANT DELETE ON orbymon.$table TO '$DB_USER'@'$host'"
  done
  echo "DELETE concedido a $DB_USER@$host (somente tabelas com retencao)"
done

echo "=== Configuracao ==="
if [[ -e /etc/orbymon/bidir.json && $REPLACE_CONFIG -eq 1 ]]; then
  CFG_REAL=$(readlink -f /etc/orbymon/bidir.json)      # pode ser link para o diretorio do painel
  cp -p "$CFG_REAL" "/etc/orbymon/bidir.json.bak.$(date +%Y%m%d%H%M%S)"
  install -o "$(stat -c %u "$CFG_REAL")" -g orbymon -m 0640 "$BASE/rules/bidir.example.json" "$CFG_REAL"
  echo "bidir.json substituido pelo exemplo atual (backup .bak criado)"
elif [[ ! -e /etc/orbymon/bidir.json ]]; then
  install -o root -g orbymon -m 0640 "$BASE/rules/bidir.example.json" /etc/orbymon/bidir.json
else
  echo "/etc/orbymon/bidir.json ja existe: preservado (compare com rules/bidir.example.json)"
fi
"$PY" -m fmn_filters.bidir_detector --config /etc/orbymon/bidir.json --validate

echo "=== Diretorio de logs NAT (retencao em /etc/orbymon/retention.env, padrao 15 dias) ==="
install -d -o orbymon -g orbymon -m 0750 /var/log/orbymon/a10nat
install -d -o orbymon -g orbymon -m 0750 /var/lib/orbymon/calibration

echo "=== Units systemd ==="
# Compactacao diaria antiga substituida pela retencao horaria.
if [[ -e /etc/systemd/system/orbymon-a10nat-compress.timer ]]; then
  systemctl disable --now orbymon-a10nat-compress.timer 2>/dev/null || true
  rm -f /etc/systemd/system/orbymon-a10nat-compress.timer /etc/systemd/system/orbymon-a10nat-compress.service
fi
for unit in orbymon-a10-nat.service orbymon-flow-rollup-huawei.service \
            orbymon-flow-rollup-huawei.timer orbymon-bidir-huawei.service \
            orbymon-bidir-huawei.timer orbymon-retention.service \
            orbymon-retention.timer orbymon-calibrate.service orbymon-calibrate.timer; do
  install -m 0644 "$BASE/deploy/systemd/$unit" /etc/systemd/system/
done
chmod 0755 "$BASE/scripts/orbymon-retention.sh"
if [[ ! -e /etc/orbymon/retention.env ]]; then
  install -o root -g orbymon -m 0640 /dev/stdin /etc/orbymon/retention.env <<'ENV'
# Dias de retencao (apaga depois disso). Envio a nuvem: /etc/orbymon/retention-archive.conf
ORBYMON_LOG_RETENTION_DAYS='15'
ORBYMON_FLOW_RETENTION_DAYS='15'
ENV
fi
if [[ ! -e /etc/orbymon/retention-archive.conf ]]; then
  ARCH_OLD=$(sed -n 's/^ORBYMON_ARCHIVE_CMD=//p' /etc/orbymon/retention.env | tail -n 1)
  install -o root -g root -m 0600 /dev/stdin /etc/orbymon/retention-archive.conf <<ENV
# Somente root. Envia o arquivo a nuvem antes de apagar ({} = caminho). Vazio = apenas apaga.
# Ex.: ORBYMON_ARCHIVE_CMD=rclone copy {} remoto:orbymon/
ORBYMON_ARCHIVE_CMD=$ARCH_OLD
ENV
  sed -i '/^ORBYMON_ARCHIVE_CMD=/d' "$(readlink -f /etc/orbymon/retention.env)"
fi
systemctl daemon-reload

SPOOL=/var/log/orbymon/a10/a10-current.ndjson
if [[ -r "$SPOOL" ]] || sudo -u orbymon test -r "$SPOOL" 2>/dev/null; then
  echo "=== Teste do novo framing sobre o spool atual do rsyslog (somente contagens) ==="
  sudo -u orbymon env PYTHONPATH="$BASE/src" "$PY" -m fmn_filters.a10_nat \
    --config /etc/orbymon/bidir.json --replay-rsyslog "$SPOOL" --replay-max-lines 2000 || true
fi

if [[ $START -eq 1 ]]; then
  systemctl enable orbymon-a10-nat.service
  systemctl restart orbymon-a10-nat.service      # carrega codigo novo apos git pull
  systemctl enable --now orbymon-flow-rollup-huawei.timer
  systemctl enable --now orbymon-bidir-huawei.timer
  systemctl enable --now orbymon-retention.timer
  systemctl enable --now orbymon-calibrate.timer
  sleep 2
  systemctl is-active orbymon-a10-nat.service orbymon-flow-rollup-huawei.timer orbymon-bidir-huawei.timer
fi
cat <<'MSG'

F4 instalada (apenas alertas). Proximos passos MANUAIS:
 1. Ligar o receptor NAT ao A10 sem mexer no A10: sudo bash scripts/a10-receiver-cutover.sh
    (o receptor assume a porta 5514 no lugar do rsyslog; desfazer com --rollback)
 2. Desativar a deteccao antiga F3 (limite de linhas baixo para o NetStream completo):
    sudo systemctl disable --now orbymon-ddos-huawei.timer
 3. Confirme recepcao:   journalctl -u orbymon-a10-nat -n 20 --no-pager
 4. Simulacao sem gravar: sudo -u orbymon env $(cat /etc/orbymon/pipeline.env | xargs) \
      /opt/orbymon/.venv/bin/python -m fmn_filters.bidir_detector --config /etc/orbymon/bidir.json --dry-run
 5. Calibrar limites (apos 24 h de dados): sudo bash scripts/calibrate.sh
                          revisar e aplicar:      sudo bash scripts/calibrate.sh --apply
Veja docs/BIDIRECTIONAL.md.
MSG
