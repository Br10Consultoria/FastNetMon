#!/usr/bin/env bash
# Etapa 2: reputacao dos IPs do provedor (listas de bloqueio) + investigacao de denuncias.
#   sudo bash scripts/setup-reputation.sh
# - tabelas e permissoes no MariaDB (usuario do pipeline: somente as tabelas de reputacao);
# - /etc/orbymon/reputation.env (editavel no painel, pagina Reputacao);
# - timer de hora em hora + primeira verificacao agora (avisos no Telegram se configurado);
# - leitura do log NAT pelo painel (pagina Investigar);
# - dashboard "OrbyFlow | Reputacao e ataques originados".
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"
PY="$BASE/.venv/bin/python"
[[ -s /etc/orbymon/pipeline.env ]] || { echo "pipeline.env ausente" >&2; exit 1; }
[[ -s /etc/orbymon/bidir.json ]] || { echo "bidir.json ausente: rode setup-bidir.sh antes" >&2; exit 1; }

echo "=== Tabelas ==="
mariadb orbymon < "$BASE/sql/reputation.sql"
DB_USER=$(sed -n 's/^ORBYMON_DB_USER=//p' /etc/orbymon/pipeline.env | tr -d '"'"'"' ')
[[ "$DB_USER" =~ ^[A-Za-z0-9_]+$ ]] || { echo "ORBYMON_DB_USER invalido em pipeline.env" >&2; exit 1; }
for host in $(mariadb -NBe "SELECT Host FROM mysql.user WHERE User='$DB_USER'"); do
  for table in orby_reputation_listings orby_reputation_sources; do
    mariadb -e "GRANT SELECT, INSERT, UPDATE, DELETE ON orbymon.$table TO '$DB_USER'@'$host'"
  done
  echo "permissoes de reputacao concedidas a $DB_USER@$host"
done

echo "=== Configuracao ==="
REP=/etc/orbymon/reputation.env
if [[ ! -e "$REP" ]]; then
  CONTENT="# Reputacao dos IPs do provedor (editavel no painel, pagina Reputacao). Nunca executado.
ORBYMON_REP_DISABLED=''
ORBYMON_REP_DNSBL='1'
ORBYMON_REP_HEAVY_EVERY_H='6'
ABUSEIPDB_API_KEY=''"
  if [[ -d /etc/orbymon/managed ]] && id orbymon-admin >/dev/null 2>&1; then
    printf '%s\n' "$CONTENT" > /etc/orbymon/managed/reputation.env
    chown orbymon-admin:orbymon /etc/orbymon/managed/reputation.env
    chmod 0640 /etc/orbymon/managed/reputation.env
    ln -s /etc/orbymon/managed/reputation.env "$REP"
  else
    printf '%s\n' "$CONTENT" | install -o root -g orbymon -m 0640 /dev/stdin "$REP"
  fi
fi
echo "$REP ok"

if id orbymon-admin >/dev/null 2>&1; then
  echo "=== Painel: leitura do log NAT (pagina Investigar) ==="
  NAT=/var/log/orbymon/a10nat
  if [[ -d "$NAT" ]]; then
    setfacl -m u:orbymon-admin:x /var/log/orbymon
    setfacl -m u:orbymon-admin:rx "$NAT"
    setfacl -d -m u:orbymon-admin:r "$NAT"
    find "$NAT" -maxdepth 1 -type f -exec setfacl -m u:orbymon-admin:r {} +
    echo "orbymon-admin le $NAT (somente leitura)"
  fi
  install -m 0644 "$BASE/deploy/systemd/orbymon-admin.service" /etc/systemd/system/
  grep -q ORBYMON_NAT_DIR /etc/orbymon/admin.env 2>/dev/null || {
    echo "ORBYMON_NAT_DIR='/var/log/orbymon/a10nat'" >> /etc/orbymon/admin.env
    echo "ORBYMON_REPUTATION_ENV='/etc/orbymon/reputation.env'" >> /etc/orbymon/admin.env; }
fi

echo "=== Resolvedor DNS (para as DNSBL) ==="
ANS=$(getent ahostsv4 2.0.0.127.zen.spamhaus.org | awk 'NR==1{print $1}' || true)
case "$ANS" in
  127.0.0.*) echo "OK: Spamhaus responde ($ANS)";;
  127.255.255.*) echo "AVISO: a Spamhaus recusou ($ANS): o servidor usa DNS publico. Use um recursivo proprio"
                 echo "       (ex.: apt install unbound e nameserver 127.0.0.1) para consultar a Spamhaus.";;
  *) echo "AVISO: sem resposta da Spamhaus ZEN (DNS bloqueado?). As outras fontes funcionam normalmente.";;
esac

echo "=== Servico ==="
install -m 0644 "$BASE/deploy/systemd/orbymon-reputation.service" "$BASE/deploy/systemd/orbymon-reputation.timer" /etc/systemd/system/
systemctl daemon-reload

echo "=== Primeira verificacao (1 a 5 minutos) ==="
sudo -u orbymon env $(grep -v '^#' /etc/orbymon/pipeline.env | xargs) PYTHONPATH="$BASE/src" "$PY" -m fmn_filters.reputation \
  --config /etc/orbymon/bidir.json --env-file "$REP" --telegram-env /etc/orbymon/telegram.env || true
systemctl enable --now orbymon-reputation.timer
systemctl is-active orbymon-reputation.timer
id orbymon-admin >/dev/null 2>&1 && systemctl restart orbymon-admin.service || true

if [[ -d /var/lib/grafana/dashboards/orbymon ]]; then
  echo "=== Dashboard ==="
  python3 -m json.tool "$BASE/grafana/dashboards/orbyflow-reputacao.json" >/dev/null
  install -o grafana -g grafana -m 0644 "$BASE/grafana/dashboards/orbyflow-reputacao.json" /var/lib/grafana/dashboards/orbymon/
  echo "OrbyFlow | Reputacao e ataques originados (aparece no Grafana em ~30 s)"
fi
cat <<MSG

Pronto. No painel (porta 8443): paginas "Reputacao" e "Investigar".
Investigar pelo terminal:
  sudo -u orbymon env \$(grep -v '^#' /etc/orbymon/pipeline.env | xargs) PYTHONPATH=$BASE/src $PY -m fmn_filters.abuse_lookup \\
    --ip 45.238.170.70 --time "2026-10-30 14:05:00" --tz America/Sao_Paulo --port 51234
  (ou --email arquivo.txt com a denuncia inteira)
MSG
