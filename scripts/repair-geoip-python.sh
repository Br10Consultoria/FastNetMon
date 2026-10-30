#!/usr/bin/env bash
# Repair Python dependencies installed with restrictive umask.
# Does not re-download GeoLite2 databases or touch MariaDB/A10/NetFlow.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"
PY="$BASE/.venv/bin/python"
[[ -x "$PY" ]] || { echo "Ambiente virtual nao encontrado: $PY" >&2; exit 1; }
id orbymon >/dev/null || { echo "Usuario orbymon ausente" >&2; exit 1; }
check_import() {
  runuser -u orbymon -- "$PY" -c 'import geoip2.database; import maxminddb; import fmn_filters.enrichment'
}
if check_import >/dev/null 2>&1; then
  echo "[OK] geoip2.database e fmn_filters ja importaveis por orbymon."
  exit 0
fi
echo "[INFO] Reinstalando dependencias GeoIP no mesmo venv com permissoes de leitura."
(
  umask 022
  "$PY" -m pip install --force-reinstall -e "$BASE[geo]"
)
echo "[INFO] Validando imports como usuario orbymon, sem PYTHONPATH..."
if ! check_import; then
  echo "[ERRO] Bibliotecas ainda inacessiveis. Confira permissoes e caminho:" >&2
  "$PY" -m pip show geoip2 || true
  "$PY" -c 'import sysconfig; print("site-packages:",sysconfig.get_paths()["purelib"])' || true
  exit 1
fi
echo "[OK] geoip2.database e fmn_filters podem ser importados pelo servico Huawei."
echo "[INFO] Bases e registros no MariaDB nao foram alterados."
