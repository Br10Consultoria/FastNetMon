#!/usr/bin/env bash
# Instala dependencias e dois coletores passivos sem iniciar servicos nem modificar firewall/roteadores.
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then
  echo 'Use: sudo bash scripts/bootstrap-pilot.sh' >&2
  exit 1
fi
if [[ ! -f /etc/os-release ]]; then echo 'Sistema nao identificado' >&2; exit 1; fi
. /etc/os-release
if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
  echo 'Script exclusivo para Ubuntu/Debian. Encerrando.' >&2
  exit 1
fi
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if ! command -v apt-get >/dev/null 2>&1; then echo 'apt-get indisponivel' >&2; exit 1; fi
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 git nfdump tcpdump
id -u orbymon >/dev/null 2>&1 || useradd --system --home-dir /var/lib/orbymon --shell /usr/sbin/nologin --user-group orbymon
install -d -m 0750 -o orbymon -g orbymon /var/lib/orbymon /var/lib/orbymon/flows /var/lib/orbymon/flows/huawei /var/lib/orbymon/flows/mikrotik /var/lib/orbymon/state
install -d -m 0750 -o root -g orbymon /etc/orbymon
for name in huawei mikrotik; do
  case "$name" in huawei) port=2056;; mikrotik) port=2057;; esac
  if [[ ! -e "/etc/orbymon/$name.env" ]]; then
    printf 'ORBYMON_PORT=%s\n' "$port" > "/etc/orbymon/$name.env"
    chown root:orbymon "/etc/orbymon/$name.env"
    chmod 0640 "/etc/orbymon/$name.env"
  else
    echo "Mantendo configuracao existente /etc/orbymon/$name.env"
  fi
done
install -m 0644 "$project_dir/deploy/systemd/orbymon-nfcapd@.service" /etc/systemd/system/orbymon-nfcapd@.service
systemctl daemon-reload
echo
echo 'Preparacao concluida; nenhum servico foi iniciado e nenhuma porta foi aberta no firewall.'
echo '1. Revise: /etc/orbymon/{huawei,mikrotik}.env'
echo '2. Restrinja as portas 2056/2057 aos IPs dos exportadores.'
echo '3. Inicie: sudo systemctl enable --now orbymon-nfcapd@huawei.service orbymon-nfcapd@mikrotik.service'
echo '4. Consulte: bash scripts/inspect-pilot.sh huawei  (ou mikrotik)'
