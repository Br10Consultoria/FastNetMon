#!/usr/bin/env bash
# Painel web de administracao do OrbyMon (HTTPS, usuario + senha + 2FA TOTP).
#   sudo bash scripts/setup-admin.sh [--port 8443] [--bind 0.0.0.0] [--user admin]
# Pode ser executado de novo (atualiza sem perder usuarios, senhas nem configuracao).
#
# O que faz:
#  - usuario de sistema orbymon-admin (sem shell) e usuario MariaDB orbymon_admin: le o banco
#    orbymon, escreve somente nas tabelas do painel e nos nomes de interface;
#  - move bidir.json, cgnat-profiles.json, telegram.env e retention.env para /etc/orbymon/managed
#    (dono orbymon-admin, grupo orbymon, setgid) e deixa links nos caminhos antigos: os servicos
#    continuam lendo os mesmos caminhos e o painel grava de forma atomica, com backup;
#  - o comando de envio a nuvem (roda como root) fica fora do painel: retention-archive.conf;
#  - certificado TLS autoassinado (troque por um seu em /etc/orbymon/admin-tls/ se quiser);
#  - porta propria (padrao 8443), verificando conflito com Grafana (3000) e outros servicos.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"
PY="$BASE/.venv/bin/python"
PORT=8443 BIND=0.0.0.0 FIRST_USER=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --bind) BIND="$2"; shift 2 ;;
    --user) FIRST_USER="$2"; shift 2 ;;
    *) echo "opcao desconhecida: $1" >&2; exit 1 ;;
  esac
done
[[ "$PORT" =~ ^[0-9]+$ && "$PORT" -ge 1024 && "$PORT" -le 65535 ]] || { echo "--port entre 1024 e 65535" >&2; exit 1; }
[[ "$PORT" != 3000 ]] || { echo "3000 e a porta do Grafana: escolha outra" >&2; exit 1; }
"$PY" -c "import ipaddress,sys; ipaddress.ip_address(sys.argv[1])" "$BIND" 2>/dev/null || { echo "--bind deve ser um IP" >&2; exit 1; }
[[ -x "$PY" ]] || { echo "venv ausente em $BASE/.venv (instale as fases anteriores)" >&2; exit 1; }
[[ -s /etc/orbymon/bidir.json ]] || { echo "/etc/orbymon/bidir.json ausente: rode setup-bidir.sh antes" >&2; exit 1; }

echo "=== Porta $PORT ==="
if ss -ltnpH "sport = :$PORT" | grep -q . && ! ss -ltnpH "sport = :$PORT" | grep -q gunicorn; then
  ss -ltnpH "sport = :$PORT"
  echo "Porta $PORT ja esta em uso por outro servico. Use --port <outra>." >&2; exit 1
fi
echo "livre (ou ja usada pelo proprio painel)"

echo "=== Pacotes ==="
command -v setfacl >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -q acl >/dev/null
command -v openssl >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -q openssl >/dev/null
"$BASE/.venv/bin/pip" install -q "flask==3.1.3" "gunicorn==23.0.0" "segno==1.6.6" "PyMySQL>=1.1,<2"

echo "=== Usuario de sistema ==="
id orbymon-admin >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent \
  --shell /usr/sbin/nologin orbymon-admin
install -d -o orbymon-admin -g orbymon-admin -m 0700 /var/lib/orbymon/admin /var/lib/orbymon/admin/backups
# somente atravessar (sem listar) os diretorios do OrbyMon; nada de grupo orbymon (pipeline.env fica fora)
setfacl -m u:orbymon-admin:x /etc/orbymon /var/lib/orbymon

echo "=== Banco de dados ==="
mariadb orbymon < "$BASE/sql/admin.sql"
mariadb orbymon < "$BASE/sql/interface_names.sql"
mariadb orbymon < "$BASE/sql/saved_filters.sql"
mariadb orbymon < "$BASE/sql/net_prefixes.sql"
mariadb orbymon < "$BASE/sql/filter_rules.sql"
mariadb orbymon < "$BASE/sql/baseline.sql"
mariadb orbymon < "$BASE/sql/customers.sql"
mariadb orbymon < "$BASE/sql/health.sql"
ADMIN_ENV=/etc/orbymon/admin.env
DB_PASS=""
[[ -s "$ADMIN_ENV" ]] && DB_PASS=$(sed -n "s/^ORBYMON_ADMIN_DB_PASSWORD='\(.*\)'$/\1/p" "$ADMIN_ENV")
[[ -n "$DB_PASS" ]] || DB_PASS=$(openssl rand -hex 24)
mariadb <<SQL
CREATE USER IF NOT EXISTS 'orbymon_admin'@'127.0.0.1' IDENTIFIED BY '$DB_PASS';
ALTER USER 'orbymon_admin'@'127.0.0.1' IDENTIFIED BY '$DB_PASS';
GRANT SELECT ON orbymon.* TO 'orbymon_admin'@'127.0.0.1';
GRANT INSERT, UPDATE, DELETE ON orbymon.orby_admin_users TO 'orbymon_admin'@'127.0.0.1';
GRANT INSERT, DELETE ON orbymon.orby_admin_login_fail TO 'orbymon_admin'@'127.0.0.1';
GRANT INSERT ON orbymon.orby_admin_audit TO 'orbymon_admin'@'127.0.0.1';
GRANT INSERT, UPDATE, DELETE ON orbymon.orby_interface_names TO 'orbymon_admin'@'127.0.0.1';
GRANT INSERT, UPDATE, DELETE ON orbymon.orby_saved_filters TO 'orbymon_admin'@'127.0.0.1';
GRANT INSERT, DELETE ON orbymon.orby_net_prefixes TO 'orbymon_admin'@'127.0.0.1';
GRANT INSERT, UPDATE, DELETE ON orbymon.orby_filter_rules TO 'orbymon_admin'@'127.0.0.1';
GRANT INSERT, UPDATE, DELETE ON orbymon.orby_exceptions TO 'orbymon_admin'@'127.0.0.1';
GRANT INSERT, DELETE ON orbymon.orby_exception_prefixes TO 'orbymon_admin'@'127.0.0.1';
GRANT INSERT, UPDATE, DELETE ON orbymon.orby_customers TO 'orbymon_admin'@'127.0.0.1';
GRANT INSERT, UPDATE, DELETE ON orbymon.orby_customer_prefixes TO 'orbymon_admin'@'127.0.0.1';
SQL
install -d -o root -g orbymon-admin -m 0750 /etc/orbymon/admin-tls
SECRET=/etc/orbymon/admin-secret
[[ -s "$SECRET" ]] || { head -c 48 /dev/urandom > "$SECRET"; }
chown root:orbymon-admin "$SECRET"; chmod 0640 "$SECRET"
install -o root -g orbymon-admin -m 0640 /dev/stdin "$ADMIN_ENV" <<ENV
# Painel web do OrbyMon. Somente root altera este arquivo.
ORBYMON_ADMIN_BIND='$BIND:$PORT'
ORBYMON_ADMIN_DB_HOST='127.0.0.1'
ORBYMON_ADMIN_DB_USER='orbymon_admin'
ORBYMON_ADMIN_DB_PASSWORD='$DB_PASS'
ORBYMON_ADMIN_DB_NAME='orbymon'
ORBYMON_ADMIN_SECRET_FILE='$SECRET'
ORBYMON_CONFIG='/etc/orbymon/bidir.json'
ORBYMON_TELEGRAM_ENV='/etc/orbymon/telegram.env'
ORBYMON_RETENTION_ENV='/etc/orbymon/retention.env'
ORBYMON_CALIBRATION_DIR='/var/lib/orbymon/calibration'
ORBYMON_ADMIN_BACKUP_DIR='/var/lib/orbymon/admin/backups'
ORBYMON_REPUTATION_ENV='/etc/orbymon/reputation.env'
ORBYMON_RADIUS_ENV='/etc/orbymon/radius.env'
ORBYMON_NAT_DIR='/var/log/orbymon/a10nat'
ORBYMON_FLOW_ROOT='/var/lib/orbymon/flows'
ORBYMON_QUERY_LOCK='/var/lib/orbymon/admin/query.lock'
ENV

echo "=== Arquivos de configuracao editaveis pelo painel ==="
MANAGED=/etc/orbymon/managed
install -d -o orbymon-admin -g orbymon -m 2750 "$MANAGED"
PROFILE=$("$PY" -c "import json;print(json.load(open('/etc/orbymon/bidir.json'))['cgnat_profile_path'])")
# envio a nuvem sai do retention.env antes de ele passar a ser editavel
if [[ ! -e /etc/orbymon/retention-archive.conf ]]; then
  ARCH_OLD=""
  [[ -f /etc/orbymon/retention.env ]] && ARCH_OLD=$(sed -n 's/^ORBYMON_ARCHIVE_CMD=//p' /etc/orbymon/retention.env | tail -n 1)
  install -o root -g root -m 0600 /dev/stdin /etc/orbymon/retention-archive.conf <<ENV
# Somente root. Envia o arquivo a nuvem antes de apagar ({} = caminho). Vazio = apenas apaga.
# Ex.: ORBYMON_ARCHIVE_CMD=rclone copy {} remoto:orbymon/
ORBYMON_ARCHIVE_CMD=$ARCH_OLD
ENV
fi
[[ -e /etc/orbymon/retention.env ]] || printf "ORBYMON_LOG_RETENTION_DAYS='15'\nORBYMON_FLOW_RETENTION_DAYS='15'\n" > /etc/orbymon/retention.env
[[ -e /etc/orbymon/telegram.env ]] || printf "TELEGRAM_BOT_TOKEN=''\nTELEGRAM_CHAT_IDS=''\n" > /etc/orbymon/telegram.env
EXTRA=""; [[ -e /etc/orbymon/reputation.env ]] && EXTRA=/etc/orbymon/reputation.env
[[ -e /etc/orbymon/radius.env ]] && EXTRA="$EXTRA /etc/orbymon/radius.env"
for file in /etc/orbymon/bidir.json "$PROFILE" /etc/orbymon/telegram.env /etc/orbymon/retention.env $EXTRA; do
  [[ "$file" == /etc/orbymon/* && "$file" != /etc/orbymon/managed/* ]] || { echo "ignorado (fora de /etc/orbymon): $file"; continue; }
  name=$(basename "$file")
  if [[ -L "$file" ]]; then
    [[ "$(readlink -f "$file")" == "$MANAGED/$name" ]] || { echo "AVISO: $file e link para outro lugar; mantido"; continue; }
  else
    cp -p "$file" "/etc/orbymon/$name.antes-do-painel.$(date +%Y%m%d%H%M%S)"
    mv "$file" "$MANAGED/$name"
    ln -s "$MANAGED/$name" "$file"
  fi
  chown orbymon-admin:orbymon "$MANAGED/$name"; chmod 0640 "$MANAGED/$name"
  echo "$file -> $MANAGED/$name"
done

sed -i '/^ORBYMON_ARCHIVE_CMD=/d' "$MANAGED/retention.env" 2>/dev/null || true

echo "=== Leitura da proposta de calibracao ==="
install -d -o orbymon -g orbymon -m 0750 /var/lib/orbymon/calibration
setfacl -m u:orbymon-admin:rx /var/lib/orbymon/calibration
setfacl -d -m u:orbymon-admin:r /var/lib/orbymon/calibration
find /var/lib/orbymon/calibration -maxdepth 1 -type f -exec setfacl -m u:orbymon-admin:r {} +

echo "=== Leitura do log NAT (pagina Investigar) ==="
if [[ -d /var/log/orbymon/a10nat ]]; then
  setfacl -m u:orbymon-admin:x /var/log/orbymon
  setfacl -m u:orbymon-admin:rx /var/log/orbymon/a10nat
  setfacl -d -m u:orbymon-admin:r /var/log/orbymon/a10nat
  find /var/log/orbymon/a10nat -maxdepth 1 -type f -exec setfacl -m u:orbymon-admin:r {} +
fi

echo "=== Leitura dos arquivos de fluxo (pagina Analise) ==="
if [[ -d /var/lib/orbymon/flows ]]; then
  setfacl -m u:orbymon-admin:rx /var/lib/orbymon/flows
  find /var/lib/orbymon/flows -mindepth 1 -maxdepth 1 -type d -exec setfacl -m u:orbymon-admin:rx -m d:u:orbymon-admin:r {} +
fi
command -v nfdump >/dev/null || echo "AVISO: nfdump ausente (apt install nfdump) - a pagina Analise nao funciona sem ele"

echo "=== Certificado TLS ==="
TLS=/etc/orbymon/admin-tls
if [[ ! -s $TLS/cert.pem || ! -s $TLS/key.pem ]]; then
  IP=$(hostname -I | awk '{print $1}')
  openssl req -x509 -newkey rsa:3072 -sha256 -days 1825 -nodes -keyout $TLS/key.pem -out $TLS/cert.pem \
    -subj "/CN=OrbyMon admin" -addext "subjectAltName=IP:$IP,DNS:$(hostname -f 2>/dev/null || hostname)" 2>/dev/null
fi
chown root:orbymon-admin $TLS/key.pem $TLS/cert.pem; chmod 0640 $TLS/key.pem; chmod 0644 $TLS/cert.pem
openssl x509 -in $TLS/cert.pem -noout -fingerprint -sha256

echo "=== Validacao ==="
sudo -u orbymon-admin env $(sed -e "s/'//g" -e '/^#/d' "$ADMIN_ENV" | xargs) PYTHONPATH="$BASE/src" "$PY" -c "
from fmn_filters.admin.config_store import ConfigStore
from fmn_filters.admin.db import Store
c = ConfigStore(); cfg = c.bidir(); c.profile(cfg); Store().users(); print('configuracao e banco OK')"

echo "=== Servico ==="
install -m 0644 "$BASE/deploy/systemd/orbymon-admin.service" /etc/systemd/system/
install -m 0644 "$BASE/deploy/systemd/orbymon-telegram.service" /etc/systemd/system/
install -m 0644 "$BASE/deploy/systemd/orbymon-retention.service" /etc/systemd/system/
chmod 0755 "$BASE/scripts/orbymon-retention.sh"
systemctl daemon-reload
systemctl enable orbymon-admin.service >/dev/null
systemctl restart orbymon-admin.service
sleep 2
systemctl is-active orbymon-admin.service

COUNT=$(mariadb orbymon -NBe "SELECT COUNT(*) FROM orby_admin_users")
if [[ "$COUNT" == 0 ]]; then
  [[ -n "$FIRST_USER" ]] || read -rp "Nome do primeiro usuario administrador: " FIRST_USER
  sudo -u orbymon-admin env $(sed -e "s/'//g" -e '/^#/d' "$ADMIN_ENV" | xargs) PYTHONPATH="$BASE/src" \
    "$PY" -m fmn_filters.admin.cli create-user "$FIRST_USER"
fi

IP=$(hostname -I | awk '{print $1}')
cat <<MSG

Painel: https://$IP:$PORT   (certificado autoassinado: confira a impressao digital SHA256 acima)
No primeiro acesso o usuario cadastra o 2FA (QR code para Google/Microsoft Authenticator, Authy...).
Recomendado: liberar a porta $PORT somente para a rede de gerencia, ex.:
  ufw allow from <rede-gerencia> to any port $PORT proto tcp
Comandos uteis (como root):
  sudo -u orbymon-admin env \$(sed -e "s/'//g" -e '/^#/d' $ADMIN_ENV | xargs) PYTHONPATH=$BASE/src \\
    $PY -m fmn_filters.admin.cli list|create-user|set-password|reset-2fa|unlock <usuario>
  journalctl -u orbymon-admin -n 50 --no-pager
MSG
