#!/usr/bin/env bash
# Update only OrbyMon dashboard files. No Grafana service restart, secrets or router actions.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute como root/sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"
D=/var/lib/grafana/dashboards/orbymon
[[ -d "$D" ]] || { echo "Diretorio Grafana ausente: $D" >&2; exit 1; }
id grafana >/dev/null || { echo "Usuario grafana ausente" >&2; exit 1; }
for name in orbymon-huawei-live.json orbymon-overview.json orbymon-ip-analytics.json; do
  SRC="$BASE/grafana/dashboards/$name"
  python3 -m json.tool "$SRC" >/dev/null
done
for name in orbymon-huawei-live.json orbymon-overview.json orbymon-ip-analytics.json; do
  SRC="$BASE/grafana/dashboards/$name"
  DEST="$D/$name"
  if [[ -f "$DEST" ]] && ! cmp -s "$SRC" "$DEST"; then
    cp -a "$DEST" "$DEST.bak.$(date -u +%Y%m%dT%H%M%SZ)"
  fi
  install -o grafana -g grafana -m 0644 "$SRC" "$DEST"
  echo "[OK] $name"
done
echo "Provisionamento: mesmos UIDs. Grafana atualizara os arquivos em aproximadamente 30s."
echo "Coleta NetFlow, NTP, A10, MariaDB e servicos inalterados."
