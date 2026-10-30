#!/usr/bin/env bash
set -euo pipefail
umask 027
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
GEOIP_DIR=/var/lib/orbymon/geoip
[[ -s /etc/GeoIP.conf ]] || { echo "Credenciais MaxMind ausentes" >&2; exit 2; }
id orbymon >/dev/null
install -d -m 0750 -o root -g orbymon "$GEOIP_DIR"
geoipupdate -d "$GEOIP_DIR"
for name in GeoLite2-ASN.mmdb GeoLite2-City.mmdb; do
  path="$GEOIP_DIR/$name"
  [[ -s "$path" && ! -L "$path" ]] || { echo "Base invalida: $name" >&2; exit 1; }
  chown root:orbymon "$path"
  chmod 0640 "$path"
done
echo "Bases GeoLite2 atualizadas."
