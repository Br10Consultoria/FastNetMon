#!/usr/bin/env bash
# Fase 2: nao altera nfcapd, Huawei, firewall ou pipeline da Fase 1.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"
for bin in mariadb nfdump python3 systemctl runuser; do
  command -v "$bin" >/dev/null || { echo "Dependencia ausente: $bin" >&2; exit 1; }
done
[[ -x "$BASE/.venv/bin/python" ]] || { echo "Venv ausente: $BASE/.venv" >&2; exit 1; }
[[ -s /etc/orbymon/pipeline.env ]] || { echo "Fase 1 pipeline.env ausente" >&2; exit 1; }
mariadb orbymon -e "SELECT 1" >/dev/null
echo "=== Criando tabelas IP sem alterar schema existente ==="
mariadb orbymon < "$BASE/sql/ip_analytics.sql"
mariadb orbymon < "$BASE/sql/interface_names.sql"
echo "=== Validacao de leitura de arquivos reais ==="
runuser -u orbymon -- "$BASE/.venv/bin/python" -m fmn_filters.ip_analytics \
  --source huawei --dry-run --max-files 2
echo "=== Configurando timer e servico Fase 2 ==="
install -m 0644 "$BASE/deploy/systemd/orbymon-ip-huawei.service" /etc/systemd/system/
install -m 0644 "$BASE/deploy/systemd/orbymon-ip-huawei.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl start orbymon-ip-huawei.service
systemctl enable --now orbymon-ip-huawei.timer
echo "=== Importando dashboard Grafana ==="
DASH_DIR=/var/lib/grafana/dashboards/orbymon
if [[ -d "$DASH_DIR" ]] && id grafana >/dev/null 2>&1; then
  install -o grafana -g grafana -m 0644 \
    "$BASE/grafana/dashboards/orbymon-ip-analytics.json" "$DASH_DIR/"
  systemctl try-restart grafana-server
  echo "Dashboard OrbyMon - IPs, Redes e Interfaces importado por provisioning."
else
  echo "Diretorio Grafana ausente: execute setup-grafana.sh primeiro."
fi
echo "=== Verificacao ==="
systemctl is-active orbymon-ip-huawei.timer
mariadb orbymon -e \
  "SELECT COUNT(*) arquivos,COALESCE(SUM(flow_count),0) fluxos FROM orby_ip_ingested_files"
echo "Fase 2 ativa; Fase 1 e equipamento Huawei inalterados."
