# Backup e restauração

```bash
sudo bash scripts/setup-backup.sh --encrypt   # timer diário 03:37, chave de criptografia e primeiro backup
```

**O que entra** (`/var/lib/orbymon/backups/orbymon-backup-AAAAMMDD-HHMMSS.tar.gz[.enc]`, ficam os 14 mais recentes):

| Parte | Conteúdo |
|---|---|
| `etc.tar` | `/etc/orbymon` inteiro (configuração e segredos: Telegram, banco, ERP) |
| `db-config.sql` | usuários do painel (com 2FA), regras de alarme, filtros salvos, exceções, clientes, linha de base, nomes de interface |
| `db-history.sql` | eventos de ataque, incidentes, listas de reputação, auditoria |
| `grafana/` | provisionamento e banco do Grafana (dashboards editados na interface) |

Fluxos (nfcapd) e logs NAT não entram: são grandes e têm retenção e arquivamento próprios (página Retenção).

**Criptografia**: com `/etc/orbymon/backup.key` (criada por `--encrypt`), o arquivo sai cifrado com AES-256.
**Guarde uma cópia da chave fora do servidor** — sem ela o backup não abre.

**Cópia externa**: o mesmo `ORBYMON_ARCHIVE_CMD` de `/etc/orbymon/retention-archive.conf` (somente root), por exemplo
`rclone copy {} remoto:orbymon/`. Sem a chave, o script avisa que está enviando sem criptografia.

Opções em `/etc/orbymon/backup.conf` (somente root): `ORBYMON_BACKUP_DIR`, `ORBYMON_BACKUP_KEEP`,
`ORBYMON_BACKUP_HISTORY` (0 = sem histórico).

A página **Backup** do painel lista os arquivos (não baixa: eles contêm segredos) e a página **Saúde** avisa se o
último backup tiver mais de 36 h.

## Restaurar

```bash
sudo bash scripts/orbymon-restore.sh /var/lib/orbymon/backups/ARQUIVO          # só mostra o conteúdo
sudo bash scripts/orbymon-restore.sh /var/lib/orbymon/backups/ARQUIVO --yes    # restaura tudo
sudo bash scripts/orbymon-restore.sh ARQUIVO --yes --only db                    # etc | db | history | grafana
```

Pausa os timers, guarda a configuração atual em `/etc/orbymon.antes-restore-<data>` (e o banco do Grafana ao lado do
original), restaura e retoma.

**Servidor novo**: instale o OrbyMon (`prepare-ubuntu.sh`), copie o backup e a chave (`/etc/orbymon/backup.key`), restaure
com `--yes` e rode de novo os `setup-*` (bidir, admin, telegram, reputation, filter-rules, baseline, health, customers,
backup) para recriar usuários e permissões do banco e as units do systemd.
