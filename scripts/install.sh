#!/usr/bin/env bash
# Instalador completo do OrbyFlow num Ubuntu 22.04/24.04 limpo (ou para completar uma instalacao existente).
#
#   cd /opt && sudo git clone https://github.com/Br10Consultoria/FastNetMon.git orbymon
#   cd /opt/orbymon && sudo bash scripts/install.sh --public-host IP_OU_DOMINIO [opcoes]
#
# Opcoes:
#   --public-host H     IP ou dominio do servidor (certificado HTTPS do Grafana). Padrao: primeiro IP da maquina
#   --admin-user NOME   primeiro usuario do painel (padrao admin; senha gerada em /root/orbyflow-painel-acesso.txt)
#   --a10-ip IP         IP de origem do log NAT do A10: o receptor escuta direto na TCP/5514 aceitando so esse IP
#   --mikrotik          liga tambem o coletor NetFlow do MikroTik (UDP/2057)
#   --sem-clickhouse    nao instala o ClickHouse (dashboards e detalhe ficam no MariaDB)
#   --sem-grafana       nao instala o Grafana (so painel web e deteccao)
#   --sem-geoip         nao pergunta a licenca MaxMind (ASN/pais)
#   --nao-perguntar     nao faz nenhuma pergunta (pula o que dependeria de resposta)
#
# Pode ser executado de novo: cada etapa preserva senhas, configuracao e dados existentes.
# Nao altera firewall, roteadores, A10 nem BGP. Log completo em /var/log/orbyflow-install.log.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"
LOG=/var/log/orbyflow-install.log
PUBLIC_HOST="" ADMIN_USER=admin A10_IP="" MIKROTIK=0 CLICKHOUSE=1 GRAFANA=1 GEOIP=1 ASK=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --public-host) PUBLIC_HOST="${2:-}"; shift 2 ;;
    --admin-user) ADMIN_USER="${2:-}"; shift 2 ;;
    --a10-ip) A10_IP="${2:-}"; shift 2 ;;
    --mikrotik) MIKROTIK=1; shift ;;
    --sem-clickhouse) CLICKHOUSE=0; shift ;;
    --sem-grafana) GRAFANA=0; shift ;;
    --sem-geoip) GEOIP=0; shift ;;
    --nao-perguntar) ASK=0; shift ;;
    -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
    *) echo "opcao desconhecida: $1 (use --help)" >&2; exit 1 ;;
  esac
done
[[ -t 0 ]] || ASK=0

# ------------------------------------------------------------------ verificacoes
. /etc/os-release
[[ "$ID" == ubuntu && ( "$VERSION_ID" == 22.04 || "$VERSION_ID" == 24.04 ) ]] || {
  echo "Suportado: Ubuntu 22.04 ou 24.04 (este e $PRETTY_NAME)" >&2; exit 1; }
[[ "$BASE" == /opt/orbymon ]] || { echo "O repositorio precisa estar em /opt/orbymon (os servicos usam esse caminho)" >&2; exit 1; }
[[ -z "$PUBLIC_HOST" ]] && PUBLIC_HOST=$(hostname -I | awk '{print $1}')
[[ "$PUBLIC_HOST" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "--public-host invalido" >&2; exit 1; }
[[ "$ADMIN_USER" =~ ^[a-z0-9_.-]{3,40}$ ]] || { echo "--admin-user: 3 a 40 caracteres a-z 0-9 . _ -" >&2; exit 1; }
if [[ -n "$A10_IP" ]]; then
  python3 -c "import ipaddress,sys; ipaddress.ip_address(sys.argv[1])" "$A10_IP" 2>/dev/null || {
    echo "--a10-ip invalido" >&2; exit 1; }
fi
RAM_MB=$(( $(awk '/^MemTotal:/ {print $2}' /proc/meminfo) / 1024 ))
(( RAM_MB >= 3500 )) || { echo "RAM de ${RAM_MB} MB: o minimo e 4 GB (recomendado 16 GB)" >&2; exit 1; }
DISK_GB=$(df -BG --output=avail / | tail -1 | tr -dc 0-9)
(( DISK_GB >= 20 )) || { echo "Disco livre de ${DISK_GB} GB: o minimo e 20 GB" >&2; exit 1; }

touch "$LOG"; chmod 0600 "$LOG"
exec > >(tee -a "$LOG") 2>&1
echo; echo "######## OrbyFlow install $(date -Is) host=$PUBLIC_HOST ########"
STEP=""
trap 'rc=$?; if (( rc )); then echo; echo "FALHOU na etapa: $STEP (codigo $rc). Detalhes: $LOG"; echo "Corrija e rode o instalador de novo: as etapas prontas sao preservadas."; fi' EXIT
step() { STEP="$1"; echo; echo "==================== $1 ===================="; }
run() { bash "$BASE/scripts/$1" "${@:2}"; }

# ------------------------------------------------------------------ 1. pacotes
step "1/14 Pacotes do sistema"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q python3 python3-venv python3-pip git nfdump tcpdump mariadb-server mariadb-client openssl \
  curl gnupg ca-certificates apt-transport-https acl iputils-ping traceroute dnsutils rsync gzip >/dev/null
systemctl enable --now mariadb >/dev/null

# ------------------------------------------------------------------ 2. usuario, diretorios e coletores
step "2/14 Usuario orbymon, diretorios e coletores NetFlow"
run bootstrap-pilot.sh
systemctl enable --now orbymon-nfcapd@huawei.service
(( MIKROTIK )) && systemctl enable --now orbymon-nfcapd@mikrotik.service
systemctl is-active orbymon-nfcapd@huawei.service

# ------------------------------------------------------------------ 3. python
step "3/14 Ambiente Python (.venv)"
(
  umask 022                                  # bibliotecas legiveis pelos usuarios dos servicos
  [[ -x "$BASE/.venv/bin/python" ]] || python3 -m venv "$BASE/.venv"
  "$BASE/.venv/bin/pip" install -q --upgrade pip
  "$BASE/.venv/bin/pip" install -q -e "$BASE[full]"
  "$BASE/.venv/bin/pip" install -q "flask==3.1.3" "gunicorn==23.0.0" "segno==1.6.6"
)
runuser -u orbymon -- "$BASE/.venv/bin/python" -c "import fmn_filters, pymysql; print('python ok')"

# ------------------------------------------------------------------ 4. banco
step "4/14 Banco MariaDB (orbymon) e usuario do pipeline"
mariadb -e "CREATE DATABASE IF NOT EXISTS orbymon CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
mariadb orbymon < "$BASE/sql/schema.sql"
mariadb orbymon < "$BASE/sql/ddos_passive.sql"
ENV=/etc/orbymon/pipeline.env
DB_PASS=""
[[ -s "$ENV" ]] && DB_PASS=$(sed -n 's/^ORBYMON_DB_PASSWORD=//p' "$ENV" | tr -d "\"' " | head -n 1)
DB_USER=$([[ -s "$ENV" ]] && sed -n 's/^ORBYMON_DB_USER=//p' "$ENV" | tr -d "\"' " | head -n 1 || true)
DB_USER=${DB_USER:-orbymon_writer}
[[ "$DB_USER" =~ ^[A-Za-z0-9_]+$ ]] || { echo "ORBYMON_DB_USER invalido em $ENV" >&2; exit 1; }
if [[ -z "$DB_PASS" ]]; then
  DB_PASS=$(openssl rand -hex 24)
  tmp=$(mktemp /etc/orbymon/.pipeline.XXXXXX)
  printf 'ORBYMON_DB_HOST=127.0.0.1\nORBYMON_DB_PORT=3306\nORBYMON_DB_NAME=orbymon\nORBYMON_DB_USER=%s\nORBYMON_DB_PASSWORD=%s\n' \
    "$DB_USER" "$DB_PASS" > "$tmp"
  chown root:orbymon "$tmp"; chmod 0640 "$tmp"; mv -f "$tmp" "$ENV"
  echo "credenciais do pipeline criadas em $ENV"
fi
[[ "$DB_PASS" =~ ^[A-Za-z0-9_.@%+=-]+$ ]] || { echo "senha do pipeline com caracteres inesperados em $ENV" >&2; exit 1; }
mariadb <<SQL
CREATE USER IF NOT EXISTS '$DB_USER'@'127.0.0.1' IDENTIFIED BY '$DB_PASS';
ALTER USER '$DB_USER'@'127.0.0.1' IDENTIFIED BY '$DB_PASS';
GRANT SELECT, INSERT, UPDATE ON orbymon.* TO '$DB_USER'@'127.0.0.1';
SQL
echo "usuario $DB_USER pronto (SELECT/INSERT/UPDATE; DELETE so nas tabelas com retencao, pelas etapas seguintes)"

step "5/14 Ajuste do MariaDB para a RAM (${RAM_MB} MB)"
if [[ -e /etc/mysql/mariadb.conf.d/60-orbymon.cnf ]]; then
  echo "ja ajustado (/etc/mysql/mariadb.conf.d/60-orbymon.cnf): sem reiniciar o MariaDB"
  echo "para recalcular depois de mudar a RAM: sudo bash scripts/tune-mariadb.sh --apply"
else
  run tune-mariadb.sh --apply
fi

# ------------------------------------------------------------------ 6. grafana
if (( GRAFANA )); then
  step "6/14 Grafana (HTTPS na porta 3000)"
  if ! command -v grafana-server >/dev/null && [[ ! -f /etc/apt/sources.list.d/grafana.list ]]; then
    install -d -m 0755 /etc/apt/keyrings
    curl -fsSL https://apt.grafana.com/gpg.key | gpg --dearmor --yes -o /etc/apt/keyrings/grafana.gpg
    echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" > /etc/apt/sources.list.d/grafana.list
  fi
  run setup-grafana.sh --public-host "$PUBLIC_HOST"
else
  step "6/14 Grafana: pulado (--sem-grafana)"
fi

# ------------------------------------------------------------------ 7. fluxos e enriquecimento
step "7/14 Pares de IP, interfaces e GeoIP"
run setup-ip-analytics.sh
run setup-interface-names.sh
if (( GEOIP )); then
  if [[ ! -s /etc/GeoIP.conf ]] || ! grep -Eq '^[[:space:]]*LicenseKey[[:space:]]+[A-Za-z0-9_]{10,}' /etc/GeoIP.conf; then
    if (( ASK )); then
      echo "GeoLite2 (ASN e pais dos IPs) precisa de conta gratuita MaxMind (maxmind.com > GeoLite2)."
      read -rp "MaxMind AccountID (Enter para pular): " MM_ID
      if [[ "$MM_ID" =~ ^[0-9]+$ ]]; then
        read -rsp "MaxMind LicenseKey (nao aparece na tela): " MM_KEY; echo
        [[ "$MM_KEY" =~ ^[A-Za-z0-9_]{10,}$ ]] || { echo "LicenseKey invalida; GeoIP pulado"; MM_ID=""; }
        if [[ -n "$MM_ID" ]]; then
          install -m 0600 /dev/stdin /etc/GeoIP.conf <<CONF
AccountID $MM_ID
LicenseKey $MM_KEY
EditionIDs GeoLite2-ASN GeoLite2-City
CONF
        fi
        unset MM_KEY
      fi
    fi
  fi
  if [[ -s /etc/GeoIP.conf ]]; then
    run setup-geoip.sh || echo "AVISO: GeoIP nao configurado agora (confira a licenca e rode scripts/setup-geoip.sh)"
  else
    echo "GeoIP pulado: depois crie /etc/GeoIP.conf e rode sudo bash scripts/setup-geoip.sh"
  fi
fi

# ------------------------------------------------------------------ 8. deteccao
step "8/14 Perfil CGNAT e deteccao bidirecional"
run setup-cgnat-baseline.sh
run setup-bidir.sh
if [[ -n "$A10_IP" ]]; then
  install -d -m 0755 /etc/systemd/system/orbymon-a10-nat.service.d
  cat > /etc/systemd/system/orbymon-a10-nat.service.d/10-porta-5514.conf <<UNIT
[Service]
ExecStart=
ExecStart=$BASE/.venv/bin/python -m fmn_filters.a10_nat --config /etc/orbymon/bidir.json --listen 0.0.0.0 --port 5514 --allow $A10_IP --log-dir /var/log/orbymon/a10nat --time-source received
UNIT
  systemctl daemon-reload
  systemctl restart orbymon-a10-nat
  echo "receptor NAT do A10 na TCP/5514, aceitando so $A10_IP"
fi

# ------------------------------------------------------------------ 9. painel
step "9/14 Painel web (HTTPS na porta 8443)"
run setup-admin.sh --user "$ADMIN_USER" --random-password

# ------------------------------------------------------------------ 10. modulos
step "10/14 Backup diario cifrado"
run setup-backup.sh --encrypt

step "11/14 Reputacao, C2/botnets, analise de ataques, alarmes, clientes, linha de base, mitigacao (simulacao) e saude"
run setup-reputation.sh
run setup-threat-intel.sh
run setup-attack-analysis.sh
run setup-filter-rules.sh
run setup-customers.sh
run setup-baseline.sh
run setup-mitigation.sh
run setup-health.sh

step "12/14 Desempenho e portas do CGNAT"
run setup-performance.sh
run setup-cgnat-ports.sh

# ------------------------------------------------------------------ 13. clickhouse
if (( CLICKHOUSE )); then
  step "13/14 ClickHouse"
  run setup-clickhouse.sh
else
  step "13/14 ClickHouse: pulado (--sem-clickhouse)"
fi
(( GRAFANA )) && run deploy-live-dashboards.sh >/dev/null

# ------------------------------------------------------------------ 14. verificacao
step "14/14 Verificacao"
UNITS="mariadb orbymon-nfcapd@huawei orbymon-a10-nat orbymon-admin orbymon-flow-rollup-huawei.timer
orbymon-ip-huawei.timer orbymon-bidir-huawei.timer orbymon-filter-rules.timer orbymon-health.timer
orbymon-reputation.timer orbymon-backup.timer orbymon-mitigation.timer orbymon-calibrate.timer"
(( GRAFANA )) && UNITS="$UNITS grafana-server"
(( CLICKHOUSE )) && UNITS="$UNITS clickhouse-server"
(( MIKROTIK )) && UNITS="$UNITS orbymon-nfcapd@mikrotik"
FAIL=0
for u in $UNITS; do
  st=$(systemctl is-active "$u" 2>/dev/null || true)
  printf '  %-40s %s\n' "$u" "$st"
  [[ "$st" == active ]] || FAIL=1
done
STEP="verificacao"
IP=$(hostname -I | awk '{print $1}')
cat <<MSG

==================== OrbyFlow instalado ====================
Painel web:  https://$IP:8443   (usuario e senha inicial: sudo cat /root/orbyflow-painel-acesso.txt)
$( (( GRAFANA )) && echo "Grafana:     https://$PUBLIC_HOST:3000  (usuario e senha: sudo cat /root/orbymon-grafana-acesso.txt)")
Certificados autoassinados: o navegador vai pedir confirmacao.

Faltam (pelo painel ou no equipamento):
  1. Painel > Rede: blocos do provedor, pools CGNAT, rede privada e ASN (vem com o exemplo: AJUSTE)
  2. Huawei/roteador: exportar NetStream/NetFlow para $IP UDP/2056$( (( MIKROTIK )) && echo " (MikroTik: UDP/2057)")
  3. A10: enviar o log NAT para $IP TCP/$( [[ -n "$A10_IP" ]] && echo 5514 || echo "5514 (rode de novo com --a10-ip IP_DO_A10)")
  4. Painel > Telegram e E-mail/Webhook: avisos
  5. Painel > Clientes: integracao com o ERP; Painel > Mitigacao: BGP (fica em simulacao)
  6. Firewall (nao alterado): liberar 2056/udp so do roteador, 5514/tcp so do A10,
     8443 e 3000/tcp so da rede de gerencia
  7. Guardar fora do servidor a chave dos backups: /etc/orbymon/backup.key
Log da instalacao: $LOG
MSG
if (( FAIL )); then
  echo "ATENCAO: algum servico acima nao esta ativo; veja journalctl -u <servico> -n 50"
  exit 1
fi
