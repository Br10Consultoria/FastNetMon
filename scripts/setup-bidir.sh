#!/usr/bin/env bash
# Instala a F4: receptor NAT do A10, rollup bidirecional e detector (entrada/saida).
# Somente alertas: nao altera Huawei, A10, firewall nem faz bloqueio.
# Uso: sudo bash scripts/setup-bidir.sh [--no-start]
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
START=1
[[ "${1:-}" == "--no-start" ]] && START=0
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

echo "=== Configuracao ==="
if [[ ! -e /etc/orbymon/bidir.json ]]; then
  install -o root -g orbymon -m 0640 "$BASE/rules/bidir.example.json" /etc/orbymon/bidir.json
else
  echo "/etc/orbymon/bidir.json ja existe: preservado (compare com rules/bidir.example.json)"
fi
"$PY" -m fmn_filters.bidir_detector --config /etc/orbymon/bidir.json --validate

echo "=== Diretorio de logs NAT (retencao legal definida por voce; nada e apagado) ==="
install -d -o orbymon -g orbymon -m 0750 /var/log/orbymon/a10nat

echo "=== Units systemd ==="
for unit in orbymon-a10-nat.service orbymon-flow-rollup-huawei.service \
            orbymon-flow-rollup-huawei.timer orbymon-bidir-huawei.service \
            orbymon-bidir-huawei.timer orbymon-a10nat-compress.service \
            orbymon-a10nat-compress.timer; do
  install -m 0644 "$BASE/deploy/systemd/$unit" /etc/systemd/system/
done
systemctl daemon-reload

SPOOL=/var/log/orbymon/a10/a10-current.ndjson
if [[ -r "$SPOOL" ]] || sudo -u orbymon test -r "$SPOOL" 2>/dev/null; then
  echo "=== Teste do novo framing sobre o spool atual do rsyslog (somente contagens) ==="
  sudo -u orbymon env PYTHONPATH="$BASE/src" "$PY" -m fmn_filters.a10_nat \
    --config /etc/orbymon/bidir.json --replay-rsyslog "$SPOOL" || true
fi

if [[ $START -eq 1 ]]; then
  systemctl enable --now orbymon-a10-nat.service
  systemctl enable --now orbymon-flow-rollup-huawei.timer
  systemctl enable --now orbymon-bidir-huawei.timer
  systemctl enable --now orbymon-a10nat-compress.timer
  sleep 2
  systemctl is-active orbymon-a10-nat.service orbymon-flow-rollup-huawei.timer orbymon-bidir-huawei.timer
fi
cat <<'MSG'

F4 instalada (apenas alertas). Proximos passos MANUAIS:
 1. Firewall: liberar TCP 5515 SOMENTE para o IP do A10 (10.100.10.10).
 2. A10: aponte uma SEGUNDA destinacao de log para o servidor flow, porta 5515, sem remover
    a atual (5514/rsyslog) ate validar. Valide a sintaxe no ACOS com '?' antes de aplicar.
 3. Confirme recepcao:   journalctl -u orbymon-a10-nat -n 20 --no-pager
 4. Simulacao sem gravar: sudo -u orbymon env $(cat /etc/orbymon/pipeline.env | xargs) \
      /opt/orbymon/.venv/bin/python -m fmn_filters.bidir_detector --config /etc/orbymon/bidir.json --dry-run
 5. Calibrar limites:     python -m fmn_filters.attack_report --top-talkers 60
                          python -m fmn_filters.attack_report --nat-top 60
Veja docs/BIDIRECTIONAL.md.
MSG
