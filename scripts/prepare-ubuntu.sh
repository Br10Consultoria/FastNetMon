#!/usr/bin/env bash
# Apenas dependencias de laboratorio; NAO modifica FastNetMon, BGP ou firewall.
set -euo pipefail
if [[ $(id -u) -ne 0 ]]; then echo 'Execute com sudo' >&2; exit 1; fi
. /etc/os-release
if [[ "$ID" != ubuntu && "$ID" != debian ]]; then echo 'SO nao suportado' >&2; exit 1; fi
apt-get update
apt-get install -y python3 nfdump git
echo 'Dependencias instaladas. Configure os exportadores e regras; rode scripts/verify.sh'
