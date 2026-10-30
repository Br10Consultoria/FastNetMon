#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"
command -v mariadb >/dev/null || { echo "MariaDB ausente" >&2; exit 1; }
if ! command -v grafana-server >/dev/null && [[ ! -x /usr/share/grafana/bin/grafana ]]; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y grafana
fi
id grafana >/dev/null 2>&1 || { echo "Grafana nao instalado; configure repo apt.grafana.com" >&2; exit 1; }
[[ -s "$BASE/grafana/dashboards/orbymon-overview.json" ]] || exit 1
mariadb -NBe "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='orbymon'" | grep -qx orbymon || { echo "Banco orbymon ausente" >&2; exit 1; }
install -d -m 0700 /etc/orbymon
install -d -m 0755 /etc/grafana/provisioning/datasources /etc/grafana/provisioning/dashboards /etc/systemd/system/grafana-server.service.d
install -d -m 0755 -o grafana -g grafana /var/lib/grafana/dashboards/orbymon
secret=/etc/orbymon/grafana-db.env
if [[ ! -e "$secret" ]]; then
  pass="$(openssl rand -hex 32)"
  (umask 077; printf 'ORBYMON_GRAFANA_DB_PASSWORD=%s\n' "$pass" > "$secret")
fi
chmod 0600 "$secret"
pass="$(sed -n 's/^ORBYMON_GRAFANA_DB_PASSWORD=//p' "$secret")"
[[ "$pass" =~ ^[a-f0-9]{64}$ ]] || { echo "Credencial invalida em $secret" >&2; exit 1; }
mariadb <<SQL
CREATE USER IF NOT EXISTS 'orbymon_grafana'@'127.0.0.1' IDENTIFIED BY '$pass';
ALTER USER 'orbymon_grafana'@'127.0.0.1' IDENTIFIED BY '$pass';
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'orbymon_grafana'@'127.0.0.1';
GRANT SELECT ON orbymon.* TO 'orbymon_grafana'@'127.0.0.1';
SQL
cat > /etc/grafana/provisioning/datasources/orbymon-mysql.yml <<'YAML'
apiVersion: 1
datasources:
  - name: OrbyMon MariaDB
    uid: orbymon-mysql
    type: mysql
    access: proxy
    url: 127.0.0.1:3306
    user: orbymon_grafana
    isDefault: false
    jsonData:
      database: orbymon
      maxOpenConns: 10
      maxIdleConns: 5
      connMaxLifetime: 14400
      timezone: "+00:00"
    secureJsonData:
      password: $ORBYMON_GRAFANA_DB_PASSWORD
YAML
chmod 0644 /etc/grafana/provisioning/datasources/orbymon-mysql.yml
install -m 0644 "$BASE/grafana/provisioning/dashboards/orbymon.yml" /etc/grafana/provisioning/dashboards/orbymon.yml
install -o grafana -g grafana -m 0644 "$BASE/grafana/dashboards/orbymon-overview.json" /var/lib/grafana/dashboards/orbymon/orbymon-overview.json
cat >/etc/systemd/system/grafana-server.service.d/orbymon.conf <<'UNIT'
[Service]
EnvironmentFile=/etc/orbymon/grafana-db.env
Environment=GF_SERVER_HTTP_ADDR=0.0.0.0
Environment=GF_SERVER_HTTP_PORT=3000
Environment=GF_AUTH_ANONYMOUS_ENABLED=false
Environment=GF_USERS_ALLOW_SIGN_UP=false
UNIT
systemctl daemon-reload
systemctl enable grafana-server
systemctl restart grafana-server
echo "Status: $(systemctl is-active grafana-server)"
ss -lntp | grep ':3000' || true
curl -fsS --max-time 10 http://127.0.0.1:3000/api/health || true
echo
echo "Dashboard OrbyMon importado por provisionamento; acesso http://IP_DO_SERVIDOR:3000"
echo "ATENCAO: HTTP nao criptografado. Configure HTTPS e bloqueio por IP."
