#!/usr/bin/env bash
# Read-only route to map Huawei ifIndex, with no router operations and no invented names.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"
command -v mariadb >/dev/null || { echo "MariaDB client ausente" >&2; exit 1; }
mariadb orbymon -e 'SELECT 1' >/dev/null
echo "=== Instalando tabela de referencia para IF-MIB ==="
mariadb orbymon < "$BASE/sql/interface_names.sql"
D=/var/lib/grafana/dashboards/orbymon
if [[ -d "$D" ]] && id grafana >/dev/null 2>&1; then
  for dash in orbymon-ip-analytics.json orbymon-cgnat.json orbymon-overview.json; do
    install -o grafana -g grafana -m 0644 "$BASE/grafana/dashboards/$dash" "$D/$dash"
  done
  echo "[OK] Dashboards provisionados em $D (mesmos UID, sem duplicatas)"
else
  echo "[AVISO] Grafana nao encontrado, tabela criada; instale dashboards pelo setup-grafana."
fi
echo "=== Nomes de interfaces conhecidos (apenas metadados) ==="
mariadb orbymon -e "SELECT source,if_index,if_name FROM orby_interface_names ORDER BY source,if_index LIMIT 30"
echo "[INFO] Para atribuir nomes reais, importe CSV ou SNMP walk verificado; nenhum nome foi inventado."
