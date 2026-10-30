#!/usr/bin/env bash
# Install OrbyMon GeoLite2 integration without reading secrets into shell history.
set -euo pipefail
umask 027
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"
GEOIP_DIR=/var/lib/orbymon/geoip
ENV_FILE=/etc/orbymon/ip-analytics.env
[[ -x "$BASE/.venv/bin/python" ]] || { echo "Venv .venv ausente" >&2; exit 1; }
id orbymon >/dev/null || { echo "Usuario orbymon ausente" >&2; exit 1; }
if ! command -v geoipupdate >/dev/null; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y geoipupdate
fi
if [[ ! -s /etc/GeoIP.conf ]] ||
   ! grep -Eq '^[[:space:]]*AccountID[[:space:]]+[0-9]+' /etc/GeoIP.conf ||
   ! grep -Eq '^[[:space:]]*LicenseKey[[:space:]]+[^[:space:]#]+' /etc/GeoIP.conf ||
   ! grep -E '^[[:space:]]*EditionIDs[[:space:]]+' /etc/GeoIP.conf | grep -q 'GeoLite2-ASN' ||
   ! grep -E '^[[:space:]]*EditionIDs[[:space:]]+' /etc/GeoIP.conf | grep -q 'GeoLite2-City' ||
   grep -Eq '^[[:space:]]*(AccountID|LicenseKey)[[:space:]]+(YOUR_|SUA_|SEU_)' /etc/GeoIP.conf; then
  echo "Configure /etc/GeoIP.conf: AccountID, LicenseKey e EditionIDs GeoLite2-ASN GeoLite2-City" >&2
  echo "Nao compartilhe chave nem coloque-a no GitHub/chat." >&2
  exit 2
fi
chown root:root /etc/GeoIP.conf
chmod 0600 /etc/GeoIP.conf
install -d -m 0750 -o root -g orbymon "$GEOIP_DIR"
bash "$BASE/scripts/update-geoip.sh"
"$BASE/.venv/bin/python" -m pip install -e "$BASE[geo]"
"$BASE/.venv/bin/python" -c 'import geoip2.database'
install -d -m 0750 -o root -g orbymon /etc/orbymon
TMP="$(mktemp /etc/orbymon/.geoip-XXXXXXXX)"
trap 'rm -f "$TMP"' EXIT
if [[ -f "$ENV_FILE" ]]; then
  grep -vE '^ORBYMON_(ASN|CITY)_MMDB=' "$ENV_FILE" > "$TMP" || true
  cp -p "$ENV_FILE" "$ENV_FILE.bak.$(date -u +%Y%m%dT%H%M%SZ)"
fi
printf 'ORBYMON_ASN_MMDB=%s/GeoLite2-ASN.mmdb\n' "$GEOIP_DIR" >> "$TMP"
printf 'ORBYMON_CITY_MMDB=%s/GeoLite2-City.mmdb\n' "$GEOIP_DIR" >> "$TMP"
install -m 0640 -o root -g orbymon "$TMP" "$ENV_FILE"
install -m 0644 "$BASE/deploy/systemd/orbymon-geoip-update.service" /etc/systemd/system/
install -m 0644 "$BASE/deploy/systemd/orbymon-geoip-update.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now orbymon-geoip-update.timer
echo "GeoLite2 configurada; apenas novos flows elegiveis receberao ASN/geo."
echo "Nao reimporte arquivos previamente contabilizados."
ls -lh "$GEOIP_DIR"/GeoLite2-{ASN,City}.mmdb
