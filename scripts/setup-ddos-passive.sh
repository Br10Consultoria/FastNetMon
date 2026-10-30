#!/usr/bin/env bash
# Instala somente detector passivo e dashboard; nao altera Huawei/Firewall.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"
[[ -x "$BASE/.venv/bin/python" ]] || { echo "venv Python ausente" >&2; exit 1; }
[[ -s /etc/orbymon/pipeline.env ]] || { echo "pipeline.env da Fase 1 ausente" >&2; exit 1; }
mariadb orbymon -NBe "SHOW TABLES LIKE 'orby_ip_pairs_minute'" |
 grep -qx orby_ip_pairs_minute || {
  echo "Fase 2 nao instalada. Execute sudo bash scripts/setup-ip-analytics.sh" >&2
  exit 1
}
echo "=== Criando tabelas de estado F3 ==="
mariadb orbymon < "$BASE/sql/ddos_passive.sql"
if [[ ! -e /etc/orbymon/ddos-rules.json ]]; then
  install -o root -g orbymon -m 0640 \
    "$BASE/rules/ddos-passive.example.json" /etc/orbymon/ddos-rules.json
fi
"$BASE/.venv/bin/python" -m fmn_filters.ddos_passive \
 --config /etc/orbymon/ddos-rules.json --validate
echo "=== Instalando servico e timer isolados F3 ==="
install -m 0644 "$BASE/deploy/systemd/orbymon-ddos-huawei.service" /etc/systemd/system/
install -m 0644 "$BASE/deploy/systemd/orbymon-ddos-huawei.timer" /etc/systemd/system/
systemctl daemon-reload
echo "=== Importando dashboard OrbyMon F3 ==="
DASH_DIR=/var/lib/grafana/dashboards/orbymon
if [[ -d "$DASH_DIR" ]] && id grafana >/dev/null 2>&1; then
  install -o grafana -g grafana -m 0644 \
    "$BASE/grafana/dashboards/orbymon-ddos-passive.json" "$DASH_DIR/"
  systemctl try-restart grafana-server
else
  echo "Grafana nao localizado; dashboard disponivel no repositorio"
fi
systemctl start orbymon-ddos-huawei.service
systemctl enable --now orbymon-ddos-huawei.timer
echo "=== Status fase 3 ==="
systemctl is-active orbymon-ddos-huawei.timer
mariadb orbymon -e "SELECT * FROM orby_ddos_checks"
echo "Fase 3 ativa: apenas alertas passivos. Nenhum bloqueio de trafego."
