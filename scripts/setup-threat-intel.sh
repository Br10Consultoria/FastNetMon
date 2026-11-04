#!/usr/bin/env bash
# C2 e botnets: clientes conversando com IPs de listas publicas de ameacas.
#   sudo bash scripts/setup-threat-intel.sh
# - tabelas e permissoes no MariaDB (pipeline: so as tabelas de ameacas; painel: leitura);
# - /etc/orbymon/threat.env (editavel no painel, pagina C2 e botnets; Auth-Key do ThreatFox opcional);
# - timer de 10 em 10 minutos + primeira execucao agora (baixa as listas);
# - dashboard "C2 e botnets" no Grafana.
# Nao altera firewall, roteadores, A10 nem BGP.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"
PY="$BASE/.venv/bin/python"
[[ -s /etc/orbymon/pipeline.env ]] || { echo "pipeline.env ausente" >&2; exit 1; }
[[ -s /etc/orbymon/bidir.json ]] || { echo "bidir.json ausente: rode setup-bidir.sh antes" >&2; exit 1; }

echo "=== Tabelas ==="
mariadb orbymon < "$BASE/sql/threat_intel.sql"
DB_USER=$(sed -n 's/^ORBYMON_DB_USER=//p' /etc/orbymon/pipeline.env | tr -d '"'"'"' ')
[[ "$DB_USER" =~ ^[A-Za-z0-9_]+$ ]] || { echo "ORBYMON_DB_USER invalido em pipeline.env" >&2; exit 1; }
for host in $(mariadb -NBe "SELECT Host FROM mysql.user WHERE User='$DB_USER'"); do
  for table in orby_threat_hits orby_threat_sources; do
    mariadb -e "GRANT SELECT, INSERT, UPDATE, DELETE ON orbymon.$table TO '$DB_USER'@'$host'"
  done
  mariadb -e "GRANT SELECT, INSERT ON orbymon.orby_attack_events TO '$DB_USER'@'$host'"
  echo "permissoes concedidas a $DB_USER@$host"
done
if mariadb -NBe "SELECT 1 FROM mysql.user WHERE User='orbymon_admin'" | grep -q 1; then
  for table in orby_threat_hits orby_threat_sources; do
    mariadb -e "GRANT SELECT ON orbymon.$table TO 'orbymon_admin'@'127.0.0.1'"
  done
fi

echo "=== Configuracao ==="
install -d -o orbymon -g orbymon -m 0750 /var/lib/orbymon/threat
TE=/etc/orbymon/threat.env
if [[ ! -e "$TE" ]]; then
  CONTENT="# C2 e botnets (editavel no painel, pagina C2 e botnets). Nunca executado.
ORBYMON_THREAT_DISABLED=''
ORBYMON_THREAT_REFRESH_H='6'
ORBYMON_THREAT_EVENTS_REPUTATION='0'
THREATFOX_AUTH_KEY=''"
  if [[ -d /etc/orbymon/managed ]] && id orbymon-admin >/dev/null 2>&1; then
    printf '%s\n' "$CONTENT" > /etc/orbymon/managed/threat.env
    chown orbymon-admin:orbymon /etc/orbymon/managed/threat.env
    chmod 0640 /etc/orbymon/managed/threat.env
    ln -s /etc/orbymon/managed/threat.env "$TE"
  else
    printf '%s\n' "$CONTENT" | install -o root -g orbymon -m 0640 /dev/stdin "$TE"
  fi
fi
echo "$TE ok"
if id orbymon-admin >/dev/null 2>&1; then
  grep -q ORBYMON_THREAT_ENV /etc/orbymon/admin.env 2>/dev/null || \
    echo "ORBYMON_THREAT_ENV='/etc/orbymon/threat.env'" >> /etc/orbymon/admin.env
fi

echo "=== Servico ==="
install -m 0644 "$BASE/deploy/systemd/orbymon-threat-intel.service" "$BASE/deploy/systemd/orbymon-threat-intel.timer" \
  /etc/systemd/system/
systemctl daemon-reload

echo "=== Primeira execucao (baixa as listas; 1 a 3 minutos) ==="
systemctl start orbymon-threat-intel.service || journalctl -u orbymon-threat-intel -n 20 --no-pager || true
journalctl -u orbymon-threat-intel -n 12 --no-pager -o cat || true
systemctl enable --now orbymon-threat-intel.timer
systemctl is-active orbymon-threat-intel.timer
id orbymon-admin >/dev/null 2>&1 && systemctl restart orbymon-admin.service || true

if [[ -d /var/lib/grafana/dashboards/orbymon ]]; then
  echo "=== Dashboard ==="
  python3 -m json.tool "$BASE/grafana/dashboards/orbyflow-c2-botnets.json" >/dev/null
  install -o grafana -g grafana -m 0644 "$BASE/grafana/dashboards/orbyflow-c2-botnets.json" /var/lib/grafana/dashboards/orbymon/
  echo "OrbyFlow | C2 e botnets (aparece no Grafana em ~30 s)"
fi
cat <<MSG

Pronto. Painel (porta 8443): Investigação > C2 e botnets. Verificado a cada 10 minutos.
Para a lista ThreatFox (a maior de C2 ativos), crie uma Auth-Key gratuita em https://auth.abuse.ch/
e cole na pagina C2 e botnets.
MSG
