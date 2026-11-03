#!/usr/bin/env bash
# Atualiza os paineis OrbyFlow e a tabela de nomes de paises (orby_country_names).
# Sem reiniciar o Grafana, sem segredos e sem acoes em roteadores.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute como root/sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"
D=/var/lib/grafana/dashboards/orbymon
DASHBOARDS="orbymon-huawei-live.json orbymon-overview.json orbymon-ip-analytics.json orbymon-cgnat.json orbymon-f4-ataques.json orbymon-reputacao.json orbymon-cgnat-portas.json orbymon-cgnat-assinantes.json"
[[ -d "$D" ]] || { echo "Diretorio Grafana ausente: $D" >&2; exit 1; }
id grafana >/dev/null || { echo "Usuario grafana ausente" >&2; exit 1; }
if command -v mariadb >/dev/null; then
  mariadb orbymon < "$BASE/sql/country_names.sql"
  echo "[OK] nomes de paises em portugues: $(mariadb orbymon -NBe 'SELECT COUNT(*) FROM orby_country_names')"
  # blocos do provedor usados pelos dashboards (nada fixo no SQL: serve para qualquer provedor)
  mariadb orbymon < "$BASE/sql/net_prefixes.sql"
  if [[ -s /etc/orbymon/pipeline.env && -s /etc/orbymon/bidir.json ]]; then
    DB_USER=$(sed -n 's/^ORBYMON_DB_USER=//p' /etc/orbymon/pipeline.env | tr -d '"'"'"' ')
    for host in $(mariadb -NBe "SELECT Host FROM mysql.user WHERE User='$DB_USER'"); do
      mariadb -e "GRANT SELECT, INSERT, DELETE ON orbymon.orby_net_prefixes TO '$DB_USER'@'$host'"
    done
    id orbymon-admin >/dev/null 2>&1 && mariadb -e "GRANT SELECT, INSERT, DELETE ON orbymon.orby_net_prefixes TO 'orbymon_admin'@'127.0.0.1'" 2>/dev/null || true
    sudo -u orbymon env $(grep -v '^#' /etc/orbymon/pipeline.env | xargs) PYTHONPATH="$BASE/src" \
      "$BASE/.venv/bin/python" -m fmn_filters.net_prefixes --config /etc/orbymon/bidir.json
  fi
fi
# com o ClickHouse configurado (setup-clickhouse.sh), os dashboards de trafego leem dele
CH_DS=/etc/grafana/provisioning/datasources/orbyflow-clickhouse.yaml
src_of() {
  if [[ -f "$CH_DS" && -f "$BASE/grafana/dashboards-clickhouse/$1" ]]; then echo "$BASE/grafana/dashboards-clickhouse/$1"
  else echo "$BASE/grafana/dashboards/$1"; fi
}
for name in $DASHBOARDS; do
  python3 -m json.tool "$(src_of "$name")" >/dev/null
done
for name in $DASHBOARDS; do
  SRC="$(src_of "$name")"
  DEST="$D/$name"
  if [[ -f "$DEST" ]] && ! cmp -s "$SRC" "$DEST"; then
    cp -a "$DEST" "$DEST.bak.$(date -u +%Y%m%dT%H%M%SZ)"
  fi
  install -o grafana -g grafana -m 0644 "$SRC" "$DEST"
  echo "[OK] $name$([[ "$SRC" == *dashboards-clickhouse* ]] && echo ' (ClickHouse)')"
done
echo "Provisionamento: mesmos UIDs. Grafana atualizara os arquivos em aproximadamente 30s."
echo "Coleta NetFlow, NTP, A10 e servicos inalterados."
