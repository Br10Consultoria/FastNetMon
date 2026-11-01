#!/usr/bin/env bash
# Calibracao dos limites da F4 com o trafego real.
#   sudo bash scripts/calibrate.sh             -> relatorio + proposta (nao altera nada)
#   sudo bash scripts/calibrate.sh --apply     -> backup de /etc/orbymon/bidir.json e aplica a proposta
# Opcoes extras sao repassadas (ex.: --hours 24 --factor 2.5). O detector usa a configuracao
# nova no minuto seguinte, sem reiniciar servicos. Para desfazer, copie o .bak de volta.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"
OUT=/var/lib/orbymon/calibration
install -d -o orbymon -g orbymon -m 0750 "$OUT"
set -a; source /etc/orbymon/pipeline.env; set +a
STAMP=$(date +%Y%m%d%H%M)
PYTHONPATH="$BASE/src" "$BASE/.venv/bin/python" -m fmn_filters.calibrate \
  --config /etc/orbymon/bidir.json --write "$OUT/bidir.proposed.json" --json "$OUT/relatorio-$STAMP.json" "$@"
"$BASE/.venv/bin/python" -m json.tool "$OUT/bidir.proposed.json" >/dev/null
chown orbymon:orbymon "$OUT/bidir.proposed.json" "$OUT/relatorio-$STAMP.json"
echo "Relatorio completo: $OUT/relatorio-$STAMP.json"
