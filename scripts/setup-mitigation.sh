#!/usr/bin/env bash
# Mitigacao por blackhole (RTBH). Instala em modo SIMULACAO: nada e anunciado ate voce validar.
#
#   sudo bash scripts/setup-mitigation.sh                        # tabelas, permissoes, timer (simulacao, sem BGP)
#   sudo bash scripts/setup-mitigation.sh --neighbor 10.0.0.1 --peer-as 262687 [--local-as 262687]
#        [--router-id 187.87.201.198] [--password SENHA_MD5]      # + GoBGP e sessao com o NE8000 (BGP desligado
#                                                                 #   no controlador ate a validacao no painel)
# Roteiro de validacao: docs/MITIGACAO.md
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"
NEIGHBOR="" PEER_AS="" LOCAL_AS="" ROUTER_ID="" PASSWORD=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --neighbor) NEIGHBOR="$2"; shift 2 ;;
    --peer-as) PEER_AS="$2"; shift 2 ;;
    --local-as) LOCAL_AS="$2"; shift 2 ;;
    --router-id) ROUTER_ID="$2"; shift 2 ;;
    --password) PASSWORD="$2"; shift 2 ;;
    *) echo "opcao desconhecida: $1" >&2; exit 1 ;;
  esac
done

echo "=== Tabelas e permissoes ==="
mariadb orbymon < "$BASE/sql/mitigation.sql"
DB_USER=$(sed -n 's/^ORBYMON_DB_USER=//p' /etc/orbymon/pipeline.env | tr -d '"'"'"' ')
[[ "$DB_USER" =~ ^[A-Za-z0-9_]+$ ]] || { echo "ORBYMON_DB_USER invalido em pipeline.env" >&2; exit 1; }
for host in $(mariadb -NBe "SELECT Host FROM mysql.user WHERE User='$DB_USER'"); do
  for table in orby_mitigations orby_mitigation_status; do
    mariadb -e "GRANT SELECT, INSERT, UPDATE ON orbymon.$table TO '$DB_USER'@'$host'"
  done
done
if mariadb -NBe "SELECT 1 FROM mysql.user WHERE User='orbymon_admin'" | grep -q 1; then
  mariadb -e "GRANT INSERT, UPDATE ON orbymon.orby_mitigations TO 'orbymon_admin'@'127.0.0.1'"
fi

echo "=== Configuracao (editavel no painel, pagina Mitigacao) ==="
CONF=/etc/orbymon/mitigation.json
if [[ ! -e "$CONF" ]]; then
  CONTENT='{"mode": "simulate"}'
  if [[ -d /etc/orbymon/managed ]] && id orbymon-admin >/dev/null 2>&1; then
    printf '%s\n' "$CONTENT" > /etc/orbymon/managed/mitigation.json
    chown orbymon-admin:orbymon /etc/orbymon/managed/mitigation.json; chmod 0640 /etc/orbymon/managed/mitigation.json
    ln -s /etc/orbymon/managed/mitigation.json "$CONF"
  else
    printf '%s\n' "$CONTENT" | install -o root -g orbymon -m 0640 /dev/stdin "$CONF"
  fi
fi
grep -q ORBYMON_MITIGATION_CONFIG /etc/orbymon/admin.env 2>/dev/null || \
  echo "ORBYMON_MITIGATION_CONFIG='$CONF'" >> /etc/orbymon/admin.env

if [[ -n "$NEIGHBOR" ]]; then
  echo "=== GoBGP ==="
  [[ "$NEIGHBOR" =~ ^[0-9a-fA-F.:]+$ && "$PEER_AS" =~ ^[0-9]+$ ]] || { echo "--neighbor IP e --peer-as numero" >&2; exit 1; }
  LOCAL_AS="${LOCAL_AS:-$PEER_AS}"
  ROUTER_ID="${ROUTER_ID:-$(hostname -I | awk '{print $1}')}"
  [[ "$LOCAL_AS" =~ ^[0-9]+$ && "$ROUTER_ID" =~ ^[0-9.]+$ ]] || { echo "--local-as/--router-id invalidos" >&2; exit 1; }
  [[ "$PASSWORD" != *'"'* && "$PASSWORD" != *\\* ]] || { echo "senha sem aspas duplas ou barra invertida" >&2; exit 1; }
  command -v gobgpd >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -q gobgpd
  systemctl disable --now gobgpd 2>/dev/null || true             # unit do pacote: usamos a nossa
  AUTH=""; [[ -n "$PASSWORD" ]] && AUTH="    auth-password = \"$PASSWORD\""
  install -o root -g orbymon -m 0640 /dev/stdin /etc/orbymon/gobgpd.toml <<TOML
# Gerado por setup-mitigation.sh. Sessao so para anunciar blackholes; nada recebido do roteador e aceito.
[global.config]
  as = $LOCAL_AS
  router-id = "$ROUTER_ID"
  port = -1
[global.apply-policy.config]
  default-import-policy = "reject-route"
  default-export-policy = "accept-route"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "$NEIGHBOR"
    peer-as = $PEER_AS
$AUTH
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv4-unicast"
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv6-unicast"
TOML
  install -m 0644 "$BASE/deploy/systemd/orbymon-gobgpd.service" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now orbymon-gobgpd
  sleep 5
  gobgp -u 127.0.0.1 -p 50051 neighbor || true
fi

echo "=== Controlador (30 s) ==="
install -m 0644 "$BASE/deploy/systemd/orbymon-mitigation.service" /etc/systemd/system/
install -m 0644 "$BASE/deploy/systemd/orbymon-mitigation.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now orbymon-mitigation.timer
systemctl restart orbymon-admin 2>/dev/null || true
echo "Pronto em modo SIMULACAO. Siga o roteiro de validacao em docs/MITIGACAO.md antes de mudar o modo."
