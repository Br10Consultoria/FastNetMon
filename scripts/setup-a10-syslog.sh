#!/usr/bin/env bash
# Receiver A10-only: does not change any router, CGNAT, Grafana or firewall.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
A10_IP=""
PORT=5514
while [[ $# -gt 0 ]]; do
  case "$1" in
    --a10-source-ip)
      [[ $# -ge 2 ]] || { echo "--a10-source-ip exige IP" >&2; exit 2; }
      A10_IP="$2"; shift 2 ;;
    --port)
      [[ $# -ge 2 ]] || { echo "--port exige porta" >&2; exit 2; }
      PORT="$2"; shift 2 ;;
    *) echo "Uso: sudo bash scripts/setup-a10-syslog.sh --a10-source-ip IP_REAL [--port 5514]" >&2; exit 2 ;;
  esac
done
[[ -n "$A10_IP" ]] || { echo "Informe IP real de origem do syslog do A10 (--a10-source-ip)." >&2; exit 2; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$A10_IP" "$PORT" <<'PY'
import ipaddress,sys
try:
    ip=ipaddress.IPv4Address(sys.argv[1])
    if ip.is_unspecified or ip.is_multicast or ip.is_loopback:
        raise ValueError("IP de origem A10 invalido")
    port=int(sys.argv[2])
    if not 1025<=port<=65535:
        raise ValueError("Porta fora do intervalo 1025-65535")
except ValueError as ex:
    sys.exit(str(ex))
PY
if ! command -v rsyslogd >/dev/null || ! command -v logrotate >/dev/null; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y rsyslog logrotate
fi
id syslog >/dev/null || { echo "Usuario syslog ausente" >&2; exit 1; }
id orbymon >/dev/null || { echo "Usuario orbymon ausente" >&2; exit 1; }
install -d -m 0750 -o syslog -g orbymon /var/log/orbymon /var/log/orbymon/a10
install -d -m 0750 -o orbymon -g orbymon /var/lib/orbymon/state
CONF=/etc/rsyslog.d/35-orbymon-a10.conf
BACKUP="$(mktemp)"
HAD_OLD=false
if [[ -e "$CONF" ]]; then cp -p "$CONF" "$BACKUP"; HAD_OLD=true; fi
cleanup() { rm -f "$BACKUP"; }
restore() {
  if [[ "$HAD_OLD" == true ]]; then cp -p "$BACKUP" "$CONF"; else rm -f "$CONF"; fi
}
trap cleanup EXIT
cat > "$CONF" <<'CONFEND'
# Exclusive input TCP/5514 for CGNAT syslog; local sender only for healthcheck.
# No global rules applied; other existing syslog processing untouched.
module(load="imtcp")
template(name="OrbyA10JSON" type="list") {
  constant(value="{\"received_at\":\"")
  property(name="timegenerated" dateFormat="rfc3339")
  constant(value="\",\"source_ip\":\"")
  property(name="fromhost-ip" format="json")
  constant(value="\",\"raw\":\"")
  property(name="rawmsg" format="json")
  constant(value="\"}\n")
}
ruleset(name="OrbyA10Input") {
  if ($fromhost-ip == "__SOURCE__" or $fromhost-ip == "127.0.0.1") then {
    action(type="omfile"
      file="/var/log/orbymon/a10/a10-current.ndjson"
      template="OrbyA10JSON" fileCreateMode="0640" dirCreateMode="0750")
    stop
  }
  stop
}
input(type="imtcp" address="0.0.0.0" port="__PORT__" ruleset="OrbyA10Input")
CONFEND
sed -i "s/__SOURCE__/$A10_IP/g; s/__PORT__/$PORT/g" "$CONF"
if ! rsyslogd -N1; then
  restore
  echo "Configuracao invalida, arquivo antigo restaurado." >&2
  exit 1
fi
if ! systemctl restart rsyslog.service; then
  restore
  systemctl restart rsyslog.service || true
  echo "Nao foi possivel iniciar rsyslog; configuracao restaurada." >&2
  exit 1
fi
# Do not delete CGNAT evidence without a separately defined retention policy.
cat > /etc/logrotate.d/orbymon-a10 <<'ROTATE'
/var/log/orbymon/a10/a10-current.ndjson {
    hourly
    maxsize 128M
    rotate -1
    dateext
    dateformat -%Y%m%d-%H
    compress
    delaycompress
    missingok
    notifempty
    create 0640 syslog orbymon
    sharedscripts
    postrotate
        /usr/bin/systemctl kill --signal=HUP rsyslog.service >/dev/null 2>&1 || true
    endscript
}
ROTATE
install -m 0644 "$BASE/deploy/systemd/orbymon-a10-logrotate.service" /etc/systemd/system/
install -m 0644 "$BASE/deploy/systemd/orbymon-a10-logrotate.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now orbymon-a10-logrotate.timer
echo "A10 Syslog TCP/$PORT pronto; origem autorizada $A10_IP (loopback permitido p/ autoteste)."
ss -ltnp | grep ":$PORT " || true
echo "Log: /var/log/orbymon/a10/a10-current.ndjson"
echo "Nao abriu firewall nem modificou o A10. Restrinja a porta ao IP autorizado na borda."
