#!/usr/bin/env bash
# Troca o recebimento do log NAT do A10: rsyslog (TCP 5514) -> receptor OrbyMon (TCP 5514).
# NAO altera o A10 nem o firewall: o A10 continua enviando para a mesma porta e reconecta sozinho.
# O receptor grava o log NAT compacto em /var/log/orbymon/a10nat (retencao em retention.env).
# Uso:  sudo bash scripts/a10-receiver-cutover.sh            (troca)
#       sudo bash scripts/a10-receiver-cutover.sh --rollback (volta ao rsyslog)
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
CONF=/etc/rsyslog.d/35-orbymon-a10.conf
BACKUP_DIR=/etc/orbymon/backup
DROPIN_DIR=/etc/systemd/system/orbymon-a10-nat.service.d
DROPIN="$DROPIN_DIR/10-porta-5514.conf"
PORT=5514

if [[ "${1:-}" == "--rollback" ]]; then
  LAST=$(ls -1t "$BACKUP_DIR"/35-orbymon-a10.conf.* 2>/dev/null | head -1 || true)
  [[ -n "$LAST" ]] || { echo "Nenhum backup da configuracao rsyslog em $BACKUP_DIR" >&2; exit 1; }
  rm -f "$DROPIN"
  systemctl daemon-reload
  systemctl restart orbymon-a10-nat          # volta para a porta padrao 5515
  install -m 0644 "$LAST" "$CONF"
  rsyslogd -N1 >/dev/null
  systemctl restart rsyslog
  sleep 2
  ss -ltnp | grep -E ":$PORT\b|:5515\b" || true
  echo "ROLLBACK concluido: rsyslog voltou a receber o A10 na porta $PORT ($LAST)."
  exit 0
fi

systemctl is-enabled --quiet orbymon-a10-nat.service || {
  echo "orbymon-a10-nat nao instalado: execute antes sudo bash scripts/setup-bidir.sh" >&2; exit 1; }
[[ -e "$CONF" ]] || echo "Aviso: $CONF nao existe (rsyslog ja nao recebe o A10)."

ExecLine=$(systemctl show -p ExecStart --value orbymon-a10-nat.service |
           sed -n 's/.*argv\[\]=\([^;]*\);.*/\1/p')
[[ "$ExecLine" == *"--port 5515"* ]] || ExecLine=""
[[ -n "$ExecLine" ]] || ExecLine="/opt/orbymon/.venv/bin/python -m fmn_filters.a10_nat --config /etc/orbymon/bidir.json --listen 0.0.0.0 --port 5515 --allow 10.100.10.10 --log-dir /var/log/orbymon/a10nat --time-source received"
NEW_EXEC="${ExecLine/--port 5515/--port $PORT}"

echo "=== 1/4 Backup e desativacao da entrada A10 do rsyslog ==="
install -d -m 0750 "$BACKUP_DIR"
if [[ -e "$CONF" ]]; then
  STAMP=$(date +%Y%m%d%H%M%S)
  cp -p "$CONF" "$BACKUP_DIR/35-orbymon-a10.conf.$STAMP"
  rm -f "$CONF"
  echo "backup: $BACKUP_DIR/35-orbymon-a10.conf.$STAMP"
  if ! rsyslogd -N1 >/dev/null 2>&1; then
    install -m 0644 "$BACKUP_DIR/35-orbymon-a10.conf.$STAMP" "$CONF"
    echo "rsyslog invalido sem a entrada A10; configuracao restaurada, nada foi alterado." >&2
    exit 1
  fi
fi
systemctl restart rsyslog

echo "=== 2/4 Receptor OrbyMon na porta $PORT ==="
install -d -m 0755 "$DROPIN_DIR"
cat > "$DROPIN" <<EOF
[Service]
ExecStart=
ExecStart=$NEW_EXEC
EOF
systemctl daemon-reload
for _ in 1 2 3 4 5; do
  ss -ltn | grep -q ":$PORT\b" || break
  sleep 1
done
if ss -ltn | grep -q ":$PORT\b"; then
  echo "Porta $PORT ainda ocupada por outro processo; desfazendo." >&2
  bash "$0" --rollback
  exit 1
fi
systemctl restart orbymon-a10-nat

echo "=== 3/4 Verificacao ==="
sleep 3
systemctl is-active orbymon-a10-nat
ss -ltnp | grep ":$PORT\b" || true

echo "=== 4/4 Aguardando o A10 reconectar (ate 60 s) ==="
for _ in $(seq 1 12); do
  if ss -tn state established "( sport = :$PORT )" | grep -q "10.100.10.10"; then
    echo "A10 conectado."
    break
  fi
  sleep 5
done
ss -tn state established "( sport = :$PORT )" || true
cat <<MSG

Pronto. Acompanhe:  journalctl -u orbymon-a10-nat -f
Em cerca de 1 minuto devem aparecer linhas "NAT estado=..." com eventos alocados/liberados.
Se o A10 nao reconectar em alguns minutos, verifique 'show cgnv6 logging statistics' no A10.
Para desfazer:      sudo bash scripts/a10-receiver-cutover.sh --rollback
MSG
