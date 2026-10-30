# Configuracao automatica Grafana OrbyMon

No servidor Ubuntu 24.04 com MariaDB orbymon criado e Grafana instalado:

```bash
cd /opt/orbymon
git pull --ff-only origin main
sudo bash scripts/setup-grafana.sh
```

O instalador cria usuario MariaDB somente SELECT, preserva a senha em
`/etc/orbymon/grafana-db.env` (0600, root), configura fonte MySQL UID
`orbymon-mysql`, instala dashboard UID `orbymon-ddos-overview` e
configura acesso TCP 3000 em 0.0.0.0. Reinicia somente o Grafana;
nao modifica Huawei, NetFlow, nfcapd, timer nem firewall.

O dashboard ja aparece em Dashboards > OrbyMon apos login; nao requer
importacao manual. O primeiro login e feito com as credenciais do Grafana;
mude a senha de admin imediatamente. O arquivo de credenciais nao deve ser
enviado a ninguem. O script pode ser reexecutado e preserva a senha.

Atencao: HTTP/3000 e sem criptografia. Aplique HTTPS via proxy e ACL
na borda/host limitando os IPs da casa/provedor. Nao exponha MariaDB 3306.
Se voce ja tem Grafana configurado, faca backup dos arquivos especificos
de provisionamento antes de executar. Painel de alertas/geomapa ficara vazio
ate ligar detector e GeoIP; metricas de fluxo funcionam imediatamente.
