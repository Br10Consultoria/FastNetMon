#!/usr/bin/env bash
# OrbyMon Grafana: HTTPS externo, MariaDB somente leitura e dashboards automaticos.
# Nao modifica Huawei, BGP, nfcapd, timer de NetFlow nem firewall.
set -euo pipefail
umask 077
usage() { echo "Uso: sudo bash scripts/setup-grafana.sh --public-host IP_OU_DOMINIO"; }
PUBLIC_HOST=""
while (($#)); do
  case "$1" in
    --public-host) [[ $# -ge 2 ]] || { usage; exit 2; }; PUBLIC_HOST="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo "Execute com sudo/root" >&2; exit 1; }
[[ -n "$PUBLIC_HOST" && "$PUBLIC_HOST" =~ ^[a-zA-Z0-9.-]+$ ]] || {
  echo "Informe --public-host com IPv4 ou dominio, sem protocolo ou porta" >&2; exit 2;
}
if [[ "$PUBLIC_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  IFS=. read -r a b c d <<< "$PUBLIC_HOST"
  for oct in "$a" "$b" "$c" "$d"; do
    [[ "$oct" =~ ^[0-9]{1,3}$ ]] && ((10#$oct <= 255)) || { echo "IPv4 invalido" >&2; exit 2; }
  done
  SAN="IP:$PUBLIC_HOST"
else
  SAN="DNS:$PUBLIC_HOST"
fi
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
for bin in mariadb openssl curl python3 systemctl; do
  command -v "$bin" >/dev/null || { echo "Dependencia ausente: $bin" >&2; exit 1; }
done
if ! command -v grafana-server >/dev/null; then
  echo "Grafana ausente; tentando instalar do repositorio APT configurado"
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y grafana
fi
id grafana >/dev/null || { echo "Usuario grafana nao encontrado" >&2; exit 1; }
mariadb --batch -N -e "SELECT 1" >/dev/null
# Dashboards Huawei/CGNAT referenciam tabela opcional de ifName confirmado.
# Criar tabela vazia idempotente evita erros SQL antes de importar nomes reais.
mariadb orbymon < "$PROJECT_DIR/sql/interface_names.sql"
FOUND="$(mariadb --batch -N -e "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='orbymon'")"
[[ "$FOUND" == "1" ]] || { echo "Banco orbymon ausente; instale MariaDB e crie o banco antes" >&2; exit 1; }
[[ -d /etc/orbymon ]] || install -d -m 0750 -o root -g orbymon /etc/orbymon
# Grafana precisa atravessar /etc/orbymon para ler certificado root:grafana.
# O x para outros nao revela pipeline.env ou grafana.env (arquivos 0640).
chmod o+x /etc/orbymon
install -d -m 0750 -o root -g grafana /etc/orbymon/grafana-tls
ENV_FILE=/etc/orbymon/grafana.env
ADMIN_FIRST=0
if [[ -f "$ENV_FILE" ]]; then
  DB_PASS="$(sed -n 's/^ORBYMON_GRAFANA_DB_PASSWORD=//p' "$ENV_FILE" | head -n 1)"
  ADMIN_PASS="$(sed -n 's/^GF_SECURITY_ADMIN_PASSWORD=//p' "$ENV_FILE" | head -n 1)"
  [[ "$DB_PASS" =~ ^[a-f0-9]{48}$ && "$ADMIN_PASS" =~ ^[a-f0-9]{48}$ ]] || {
    echo "Arquivo de credenciais existente invalido; nenhuma senha alterada" >&2; exit 1;
  }
else
  DB_PASS="$(openssl rand -hex 24)"
  ADMIN_PASS="$(openssl rand -hex 24)"
  [[ -s /var/lib/grafana/grafana.db ]] || ADMIN_FIRST=1
fi
# Senhas geradas com OpenSSL em hexadecimal; nao sao exibidas nos logs.
mariadb <<SQL
CREATE USER IF NOT EXISTS 'orbymon_grafana'@'127.0.0.1' IDENTIFIED BY '$DB_PASS';
ALTER USER 'orbymon_grafana'@'127.0.0.1' IDENTIFIED BY '$DB_PASS';
GRANT SELECT ON orbymon.* TO 'orbymon_grafana'@'127.0.0.1';
SQL
KEY=/etc/orbymon/grafana-tls/grafana.key
CERT=/etc/orbymon/grafana-tls/grafana.crt
MARKER=/etc/orbymon/grafana-tls/host
if [[ ! -s "$KEY" || ! -s "$CERT" || ! -f "$MARKER" || "$(cat "$MARKER")" != "$PUBLIC_HOST" ]]; then
  openssl req -new -newkey rsa:3072 -x509 -sha256 -nodes -days 365 \
    -subj '/CN=OrbyMon-Grafana' -addext "subjectAltName=$SAN" \
    -keyout "$KEY" -out "$CERT" >/dev/null 2>&1
  printf '%s\n' "$PUBLIC_HOST" > "$MARKER"
fi
chown root:grafana "$KEY" "$CERT"
chmod 0640 "$KEY" "$CERT"
{
  printf 'ORBYMON_GRAFANA_DB_PASSWORD=%s\n' "$DB_PASS"
  printf 'GF_SECURITY_ADMIN_USER=admin\n'
  printf 'GF_SECURITY_ADMIN_PASSWORD=%s\n' "$ADMIN_PASS"
  printf 'GF_SERVER_PROTOCOL=https\nGF_SERVER_HTTP_ADDR=0.0.0.0\nGF_SERVER_HTTP_PORT=3000\n'
  printf 'GF_SERVER_DOMAIN=%s\nGF_SERVER_ROOT_URL=https://%s:3000/\n' "$PUBLIC_HOST" "$PUBLIC_HOST"
  printf 'GF_SERVER_CERT_FILE=%s\nGF_SERVER_CERT_KEY=%s\n' "$CERT" "$KEY"
  printf 'GF_SECURITY_COOKIE_SECURE=true\nGF_AUTH_ANONYMOUS_ENABLED=false\n'
  printf 'GF_USERS_ALLOW_SIGN_UP=false\nGF_SECURITY_DISABLE_GRAVATAR=true\n'
} > "$ENV_FILE.new"
chown root:grafana "$ENV_FILE.new"
chmod 0640 "$ENV_FILE.new"
mv -f "$ENV_FILE.new" "$ENV_FILE"
install -d -m 0755 /etc/systemd/system/grafana-server.service.d
cat > /etc/systemd/system/grafana-server.service.d/zz-orbymon-auto.conf <<'UNIT'
[Service]
EnvironmentFile=/etc/orbymon/grafana.env
UNIT
chmod 0644 /etc/systemd/system/grafana-server.service.d/zz-orbymon-auto.conf
DS_DIR=/etc/grafana/provisioning/datasources
PROVIDER_DIR=/etc/grafana/provisioning/dashboards
BOARD_DIR=/var/lib/grafana/dashboards/orbymon
install -d -m 0755 "$DS_DIR" "$PROVIDER_DIR"
install -d -o grafana -g grafana -m 0755 "$BOARD_DIR"
backup_if_different() {
  if [[ -f "$1" ]] && ! cmp -s "$1" "$2"; then
    cp -a "$1" "$1.bak.$(date -u +%Y%m%dT%H%M%SZ)"
  fi
}
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
cat > "$TMP" <<'YAML'
apiVersion: 1
datasources:
  - name: OrbyMon MariaDB
    uid: orbymon-mysql
    type: mysql
    access: proxy
    url: 127.0.0.1:3306
    user: orbymon_grafana
    isDefault: false
    editable: false
    jsonData:
      database: orbymon
      timezone: '+00:00'
      timeInterval: 1m
      maxOpenConns: 10
      maxIdleConns: 5
    secureJsonData:
      password: $ORBYMON_GRAFANA_DB_PASSWORD
YAML
DS_DEST="$DS_DIR/orbymon-mysql.yml"
backup_if_different "$DS_DEST" "$TMP"
install -m 0644 "$TMP" "$DS_DEST"
PROVIDER_SRC="$PROJECT_DIR/grafana/provisioning/dashboards/orbymon.yml"
PROVIDER_DEST="$PROVIDER_DIR/orbymon.yml"
backup_if_different "$PROVIDER_DEST" "$PROVIDER_SRC"
install -m 0644 "$PROVIDER_SRC" "$PROVIDER_DEST"
shopt -s nullglob
COUNT=0
for src in "$PROJECT_DIR"/grafana/dashboards/*.json; do
  python3 -m json.tool "$src" >/dev/null || { echo "Dashboard JSON invalido: $src" >&2; exit 1; }
  dest="$BOARD_DIR/$(basename "$src")"
  backup_if_different "$dest" "$src"
  install -o grafana -g grafana -m 0644 "$src" "$dest"
  COUNT=$((COUNT+1))
done
((COUNT>0)) || { echo "Sem dashboards JSON para importar" >&2; exit 1; }
if ((ADMIN_FIRST)); then
  {
    printf 'URL: https://%s:3000/\nUsuario: admin\nSenha: %s\n' "$PUBLIC_HOST" "$ADMIN_PASS"
    printf 'Certificado HTTPS autofirmado: confira fingerprint antes de confiar\n'
  } > /root/orbymon-grafana-acesso.txt
  chmod 0600 /root/orbymon-grafana-acesso.txt
fi
systemctl daemon-reload
systemctl enable grafana-server >/dev/null
systemctl restart grafana-server
for _ in {1..30}; do
  if curl -kfsS --max-time 2 https://127.0.0.1:3000/api/health >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -kfsS --max-time 5 https://127.0.0.1:3000/api/health >/dev/null || {
  echo "Grafana nao respondeu; execute journalctl -u grafana-server -n 60" >&2; exit 1;
}
echo "OK: Grafana ativo em https://$PUBLIC_HOST:3000/"
echo "OK: MariaDB somente leitura e datasource provisionado"
echo "OK: $COUNT dashboards JSON copiados e provisionamento configurado"
if ((ADMIN_FIRST)); then
  echo "Credenciais (somente root): sudo cat /root/orbymon-grafana-acesso.txt"
else
  echo "Banco Grafana ja existia: senha admin existente foi preservada"
fi
echo "IMPORTANTE: certificado autofirmado valido por 365 dias; use dominio/certificado confiavel para producao"
echo "IMPORTANTE: firewall nao foi alterado; libere TCP 3000 somente das origens autorizadas"
