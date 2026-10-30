#!/usr/bin/env bash
# Read-only SNMPv2c IF-MIB mapping for the Huawei exporter.
# Net-SNMP reads the community from a protected /root/.snmp/snmp.conf.
set -euo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo "Execute com sudo/root" >&2; exit 1; }
if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Uso: sudo bash scripts/sync-huawei-ifnames-snmp.sh IP_HUAWEI [--dry-run]" >&2
  exit 2
fi
HOST="$1"
[[ "$HOST" =~ ^[a-zA-Z0-9.:-]+$ ]] || { echo "Host invalido" >&2; exit 2; }
DRY=0
if [[ $# -eq 2 ]]; then
  [[ "$2" == "--dry-run" ]] || { echo "Opcao invalida" >&2; exit 2; }
  DRY=1
fi
BASE="$(cd "$(dirname "$0")/.." && pwd)"
PY="$BASE/.venv/bin/python"
[[ -x "$PY" ]] || { echo "Python OrbyMon ausente" >&2; exit 1; }
command -v snmpwalk >/dev/null || { echo "Instale o pacote snmp (apt install snmp)" >&2; exit 1; }
SNMP_CONF=/root/.snmp/snmp.conf
if [[ ! -r "$SNMP_CONF" ]] || ! grep -Eq '^[[:space:]]*defCommunity[[:space:]]+[^[:space:]#]+' "$SNMP_CONF"; then
  echo "Configure defCommunity com permissao de leitura em $SNMP_CONF (root 0600)." >&2
  echo "Nunca informe a comunidade na linha de comando ou no GitHub." >&2
  exit 2
fi
MODE="$(stat -c '%a' "$SNMP_CONF")"
if [[ "$MODE" != 600 && "$MODE" != 400 ]]; then
  echo "$SNMP_CONF precisa ter permissao 0600 ou 0400 (atual: $MODE)." >&2
  exit 2
fi
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
OID=1.3.6.1.2.1.31.1.1.1.1
echo "[INFO] Consultando IF-MIB::ifName em $HOST (somente leitura)."
snmpwalk -v2c -On -t 3 -r 1 "$HOST" "$OID" > "$TMP" || {
  echo "[ERRO] Consulta SNMP falhou: confira IP, ACL UDP 161 e comunidade de leitura." >&2
  exit 1
}
if [[ ! -s "$TMP" ]]; then
  echo "[ERRO] Huawei nao retornou ifName." >&2
  exit 1
fi
echo "[INFO] Verificando indices encontrados:"
PYTHONPATH="$BASE/src" "$PY" - "$TMP" <<'PY'
from pathlib import Path
import sys
from fmn_filters.interface_names import parse_text
m=parse_text(Path(sys.argv[1]).read_text(),fmt='snmpwalk')
print(f"Interfaces identificadas: {len(m)}")
for index in (16,86,334):
    print(f"  ifIndex {index}: {m.get(index,'nao retornou ifName')}")
PY
if (( DRY )); then
  echo "[OK] Leitura e validacao concluida; --dry-run, banco nao alterado."
  exit 0
fi
[[ -r /etc/orbymon/pipeline.env ]] || {
  echo "[ERRO] /etc/orbymon/pipeline.env ausente" >&2; exit 1;
}
# Trusted root-owned environment file from the existing OrbyMon deployment.
set -a
# shellcheck source=/dev/null
source /etc/orbymon/pipeline.env
set +a
PYTHONPATH="$BASE/src" "$PY" -m fmn_filters.interface_names \
  --source huawei --file "$TMP" --format snmpwalk
echo "[OK] ifName atualizado no MariaDB. Atualize a pagina do Grafana."
