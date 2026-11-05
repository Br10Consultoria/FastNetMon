#!/usr/bin/env bash
# Analise automatica dos ataques + resumo semanal de seguranca.
#   sudo bash scripts/setup-attack-analysis.sh
# - tabela orby_attack_analysis e permissoes (pipeline grava; painel le);
# - timer de 2 em 2 minutos: cada ataque novo ganha vetor, origens e checagem de carpet bombing
#   (aparece no painel, no Telegram e no dashboard "Analise de ataques");
# - resumo semanal no Telegram (segunda 08:13);
# - analisa as ultimas 24 h agora.
# Nao altera firewall, roteadores, A10 nem BGP.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"
[[ -s /etc/orbymon/pipeline.env ]] || { echo "pipeline.env ausente" >&2; exit 1; }
[[ -s /etc/orbymon/bidir.json ]] || { echo "bidir.json ausente: rode setup-bidir.sh antes" >&2; exit 1; }
command -v nfdump >/dev/null || { echo "nfdump ausente" >&2; exit 1; }

echo "=== Tabela ==="
mariadb orbymon < "$BASE/sql/attack_analysis.sql"
DB_USER=$(sed -n 's/^ORBYMON_DB_USER=//p' /etc/orbymon/pipeline.env | tr -d '"'"'"' ')
[[ "$DB_USER" =~ ^[A-Za-z0-9_]+$ ]] || { echo "ORBYMON_DB_USER invalido em pipeline.env" >&2; exit 1; }
for host in $(mariadb -NBe "SELECT Host FROM mysql.user WHERE User='$DB_USER'"); do
  mariadb -e "GRANT SELECT, INSERT, UPDATE, DELETE ON orbymon.orby_attack_analysis TO '$DB_USER'@'$host'"
  # resumo semanal le as tabelas das outras etapas (as que existirem)
  for t in orby_attack_events orby_threat_hits orby_reputation_listings orby_nat_public_minute orby_nat_heavy_minute \
           orby_filter_incidents; do
    mariadb -NBe "SELECT 1 FROM information_schema.tables WHERE table_schema='orbymon' AND table_name='$t'" | grep -q 1 \
      && mariadb -e "GRANT SELECT ON orbymon.$t TO '$DB_USER'@'$host'"
  done
  echo "permissoes concedidas a $DB_USER@$host"
done
if mariadb -NBe "SELECT 1 FROM mysql.user WHERE User='orbymon_admin'" | grep -q 1; then
  mariadb -e "GRANT SELECT ON orbymon.orby_attack_analysis TO 'orbymon_admin'@'127.0.0.1'"
fi

echo "=== Servicos ==="
install -m 0644 "$BASE"/deploy/systemd/orbymon-attack-analysis.{service,timer} \
  "$BASE"/deploy/systemd/orbymon-weekly-report.{service,timer} /etc/systemd/system/
systemctl daemon-reload

echo "=== Analisando os ataques das ultimas 24 h (sem avisar no Telegram) ==="
sudo -u orbymon env $(grep -v '^#' /etc/orbymon/pipeline.env | xargs) PYTHONPATH="$BASE/src" \
  "$BASE/.venv/bin/python" -m fmn_filters.attack_analysis --config /etc/orbymon/bidir.json --hours 24 --limit 60 \
  || echo "[AVISO] analise inicial falhou (o timer tenta de novo)"
systemctl enable --now orbymon-attack-analysis.timer orbymon-weekly-report.timer
systemctl is-active orbymon-attack-analysis.timer orbymon-weekly-report.timer
id orbymon-admin >/dev/null 2>&1 && systemctl restart orbymon-admin.service || true

if [[ -d /var/lib/grafana/dashboards/orbymon ]]; then
  python3 -m json.tool "$BASE/grafana/dashboards/orbyflow-analise-ataques.json" >/dev/null
  install -o grafana -g grafana -m 0644 "$BASE/grafana/dashboards/orbyflow-analise-ataques.json" /var/lib/grafana/dashboards/orbymon/
  echo "OrbyFlow | Analise de ataques (aparece no Grafana em ~30 s)"
fi
cat <<MSG

Pronto. Cada ataque novo e analisado em ate 2 minutos: painel > Ataques (coluna Regra · vetor e detalhe),
Telegram ("Analise do ataque") e Grafana > Analise de ataques.
Resumo semanal: segunda 08:13. Para ver agora sem enviar:
  sudo -u orbymon env \$(grep -v '^#' /etc/orbymon/pipeline.env | xargs) PYTHONPATH=$BASE/src \\
    $BASE/.venv/bin/python -m fmn_filters.weekly_report --print
MSG
