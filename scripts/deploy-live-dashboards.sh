#!/usr/bin/env bash
# Atualiza os paineis OrbyFlow e a tabela de nomes de paises (orby_country_names).
# Sem reiniciar o Grafana, sem segredos e sem acoes em roteadores.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute como root/sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"
D=/var/lib/grafana/dashboards/orbymon
DASHBOARDS="orbyflow-huawei-live.json orbyflow-overview.json orbyflow-ip-analytics.json orbyflow-cgnat.json orbyflow-f4-ataques.json orbyflow-reputacao.json orbyflow-cgnat-portas.json orbyflow-cgnat-assinantes.json orbyflow-ataques-originados.json orbyflow-alarmes.json orbyflow-c2-botnets.json orbyflow-grupos-asn.json orbyflow-analise-ataques.json"
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
    # grupos de ASN/CDN (dashboard Trafego por grupo): editaveis no painel, pagina Grupos de ASN
    mariadb orbymon < "$BASE/sql/asn_groups.sql"
    for host in $(mariadb -NBe "SELECT Host FROM mysql.user WHERE User='$DB_USER'"); do
      mariadb -e "GRANT SELECT, INSERT, DELETE ON orbymon.orby_asn_group_members TO '$DB_USER'@'$host'"
      mariadb -e "GRANT SELECT ON orbymon.orby_asn_groups TO '$DB_USER'@'$host'"
    done
    if id orbymon-admin >/dev/null 2>&1; then
      mariadb -e "GRANT SELECT, INSERT, UPDATE, DELETE ON orbymon.orby_asn_groups TO 'orbymon_admin'@'127.0.0.1'" 2>/dev/null || true
      mariadb -e "GRANT SELECT, INSERT, DELETE ON orbymon.orby_asn_group_members TO 'orbymon_admin'@'127.0.0.1'" 2>/dev/null || true
    fi
    sudo -u orbymon env $(grep -v '^#' /etc/orbymon/pipeline.env | xargs) PYTHONPATH="$BASE/src" \
      "$BASE/.venv/bin/python" -m fmn_filters.asn_groups
    # ClickHouse ja instalado: cria a copia da tabela de grupos e libera o TRUNCATE dela para o pipeline
    UX=/etc/clickhouse-server/users.d/orbyflow.xml
    if [[ -s /etc/orbymon/clickhouse-admin.env && -f "$UX" ]]; then
      if ! grep -q orby_asn_group_members "$UX"; then
        sed -i 's#^\(\s*\)<query>GRANT TRUNCATE ON orbyflow.orby_net_prefixes</query>#&\n\1<query>GRANT TRUNCATE ON orbyflow.orby_asn_group_members</query>#' "$UX"
      fi
      PYTHONPATH="$BASE/src" "$BASE/.venv/bin/python" - <<'PY' || echo "[AVISO] ClickHouse: tabela de grupos nao criada (rode scripts/setup-clickhouse.sh)"
from pathlib import Path
from fmn_filters import clickhouse as ch
from fmn_filters.admin.config_store import read_env
c = ch.Client.from_env(read_env(Path("/etc/orbymon/clickhouse-admin.env")))
for sql in ch.schema(30, c.database):
    if "CREATE TABLE IF NOT EXISTS" in sql and "orby_asn_group_members" in sql:
        c.execute(sql)
print("[OK] ClickHouse: tabela de grupos de ASN")
PY
    fi
    # tabelas do dashboard C2 e botnets (vazias ate rodar scripts/setup-threat-intel.sh)
    mariadb orbymon < "$BASE/sql/threat_intel.sql"
    mariadb orbymon < "$BASE/sql/attack_analysis.sql"     # dashboard Analise de ataques (setup-attack-analysis.sh)
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
# nomes antigos (orbymon-*.json): saem do provisionamento para nao duplicar os dashboards OrbyFlow
shopt -s nullglob
OLD=( "$D"/orbymon-*.json )
if (( ${#OLD[@]} )); then
  install -d -m 0750 /var/lib/orbymon/grafana-antigos
  mv -f "${OLD[@]}" /var/lib/orbymon/grafana-antigos/
  echo "[OK] ${#OLD[@]} dashboard(s) com nome antigo movido(s) para /var/lib/orbymon/grafana-antigos"
fi
shopt -u nullglob
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
