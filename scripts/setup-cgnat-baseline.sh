#!/usr/bin/env bash
# Fase 4 CGNAT. Apenas leitura dos fluxos e dashboard; nunca altera roteadores.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"
[[ -x "$BASE/.venv/bin/python" ]] || { echo "venv ausente" >&2; exit 1; }
[[ -s /etc/orbymon/pipeline.env ]] || { echo "pipeline.env ausente" >&2; exit 1; }
mariadb orbymon -NBe "SHOW TABLES LIKE 'orby_ip_pairs_minute'" |
 grep -qx orby_ip_pairs_minute || { echo "Fase 2 deve estar instalada" >&2; exit 1; }
# Nao alterar permissoes de /etc/orbymon: o Grafana usa TLS nele.
if [[ ! -d /etc/orbymon ]]; then
  install -d -o root -g orbymon -m 0750 /etc/orbymon
fi
echo "=== Configurando pools A10 conhecidos (preservando dados locais) ==="
"$BASE/.venv/bin/python" -m fmn_filters.configure_a10 \
  --file /etc/orbymon/cgnat-profiles.json \
  --a10-template "$BASE/rules/cgnat-profiles.a10.json"
"$BASE/.venv/bin/python" -m fmn_filters.cgnat_baseline \
 --config /etc/orbymon/cgnat-profiles.json --validate
install -m 0644 "$BASE/deploy/systemd/orbymon-cgnat-report.service" \
 /etc/systemd/system/
systemctl daemon-reload
D=/var/lib/grafana/dashboards/orbymon
if [[ -d "$D" ]] && id grafana >/dev/null 2>&1; then
  install -o grafana -g grafana -m 0644 \
    "$BASE/grafana/dashboards/orbymon-cgnat.json" "$D/"
  echo "Dashboard CGNAT provisionado, sem reiniciar Grafana."
else
  echo "Grafana nao localizado; dashboard disponivel no repositorio."
fi
echo "Rodando relatorio read-only para validar dados reais..."
if systemctl start orbymon-cgnat-report.service; then
  echo "OK: relatorio CGNAT concluido."
else
  echo "Aviso: relatorio sem sucesso; veja journalctl -u orbymon-cgnat-report.service" >&2
fi
echo "Fase 4 de diagnostico instalada. Nao modifica detector F3 ou CGNAT."
echo "Consulte: sudo journalctl -u orbymon-cgnat-report.service -n 120 --no-pager"
