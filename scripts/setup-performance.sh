#!/usr/bin/env bash
# Tabelas agregadas para os dashboards (consultas de 24 h ou mais sem varrer o detalhado).
#   sudo bash scripts/setup-performance.sh
# Cria as tabelas, da permissao ao pipeline, preenche com o que ja existe no detalhado e atualiza os dashboards.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== Tabelas agregadas ==="
mariadb orbymon < "$BASE/sql/flow_aggregates.sql"
DB_USER=$(sed -n 's/^ORBYMON_DB_USER=//p' /etc/orbymon/pipeline.env | tr -d '"'"'"' ')
[[ "$DB_USER" =~ ^[A-Za-z0-9_]+$ ]] || { echo "ORBYMON_DB_USER invalido em pipeline.env" >&2; exit 1; }
for host in $(mariadb -NBe "SELECT Host FROM mysql.user WHERE User='$DB_USER'"); do
  for table in orby_flow_agg_minute orby_flow_ip_minute orby_flow_port_5m orby_flow_remote_5m; do
    mariadb -e "GRANT SELECT, INSERT, UPDATE, DELETE ON orbymon.$table TO '$DB_USER'@'$host'"
  done
done
echo "o rollup passa a gravar os agregados na proxima execucao"
systemctl restart orbymon-flow-rollup-huawei.service 2>/dev/null || true

echo "=== Preenchendo com o historico do detalhado (opcional; blocos de 15 min, mostra 1 linha por hora; Ctrl+C pode interromper) ==="
# mesmo usuario e ambiente dos servicos (o EnvironmentFile e lido pelo systemd, nunca executado)
# baixa prioridade de disco/CPU; uma falha aqui nao impede o resto (os agregados se completam com o tempo)
if ! systemd-run --quiet --wait --pipe --collect -p User=orbymon -p EnvironmentFile=/etc/orbymon/pipeline.env \
  -p Nice=10 -p IOSchedulingClass=idle \
  --setenv=PYTHONPATH="$BASE/src" "$BASE/.venv/bin/python" -m fmn_filters.flow_rollup \
  --config /etc/orbymon/bidir.json --backfill-aggregates 2>&1; then
  echo "AVISO: preenchimento do historico incompleto; os dashboards ja usam os dados novos (pode rodar de novo depois)"
fi

echo "=== Dashboards ==="
bash "$BASE/scripts/deploy-live-dashboards.sh" >/dev/null && echo "dashboards atualizados"
mariadb orbymon -e "SELECT TABLE_NAME AS tabela, TABLE_ROWS AS linhas_aprox, ROUND((DATA_LENGTH+INDEX_LENGTH)/1e6) AS MB
FROM information_schema.TABLES WHERE TABLE_SCHEMA='orbymon' AND TABLE_NAME LIKE 'orby_flow%' ORDER BY 3 DESC"
