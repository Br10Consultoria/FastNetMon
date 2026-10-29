#!/usr/bin/env bash
# Le somente arquivos rotacionados, sem modificar coletores ou roteadores.
set -euo pipefail
source_name="${1:-}"
case "$source_name" in
  huawei|mikrotik) ;;
  *) echo 'Uso: bash scripts/inspect-pilot.sh huawei|mikrotik' >&2; exit 2;;
esac
root="/var/lib/orbymon/flows/$source_name"
if [[ ! -d "$root" ]]; then echo "Diretorio ausente: $root" >&2; exit 1; fi
if ! command -v nfdump >/dev/null 2>&1; then echo 'nfdump nao instalado' >&2; exit 1; fi
last="$(find "$root" -maxdepth 1 -type f -name 'nfcapd.20*' -printf '%T@ %f\n' | sort -nr | head -n 1 | cut -d' ' -f2-)"
if [[ -z "$last" ]]; then
  echo "Ainda sem arquivos rotacionados para $source_name. Aguarde 30-90 segundos, confira firewall e exportacao." >&2
  exit 1
fi
file="$root/$last"
echo "Fonte: $source_name | Arquivo: $file"
echo
echo "===== Resumo de trafego ====="
nfdump -r "$file" -I
echo
echo "===== Top 10: IP origem, destino, portas, protocolos ====="
nfdump -r "$file" -s srcip/bytes -s dstip/bytes -s dstport/bytes -s proto/bytes -n 10
echo
echo 'Se precisar de detalhes, use: sudo nfdump -r <arquivo> -o json'
