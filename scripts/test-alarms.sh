#!/usr/bin/env bash
# Simula TODOS os alarmes por filtro (inclusive os modelos desligados) no trafego real dos ultimos N minutos.
# Nada e gravado e nenhum aviso e enviado. Use para escolher os limites antes de ligar no painel (pagina Alarmes).
#   sudo bash scripts/test-alarms.sh [minutos]      (padrao 60, de 5 a 120)
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"
MIN="${1:-60}"
[[ "$MIN" =~ ^[0-9]+$ ]] && (( MIN >= 5 && MIN <= 120 )) || { echo "minutos entre 5 e 120" >&2; exit 1; }
# mesmo usuario e ambiente do servico (o EnvironmentFile e lido pelo systemd como dado, nunca executado)
systemd-run --quiet --wait --pipe --collect -p User=orbymon -p EnvironmentFile=/etc/orbymon/pipeline.env \
  -p Nice=10 -p IOSchedulingClass=idle --setenv=PYTHONPATH="$BASE/src" \
  "$BASE/.venv/bin/python" -m fmn_filters.filter_rules --config /etc/orbymon/bidir.json \
  --flow-root /var/lib/orbymon/flows --testar-todos "$MIN"
