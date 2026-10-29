# OrbyMon: fase 2 — NetFlow Huawei para MariaDB/Grafana

## Estado
Piloto passivo; NAO altera nfcapd, Huawei, BGP, interfaces nem firewall.
Os contadores NetFlow v9 ja foram expandidos pelo nfdump com sampler 1:2048:
**nao aplicar 2048 novamente**. A hora nfdump e forçada a UTC no subprocesso
para evitar deslocamento de 3h no Ubuntu com America/Bahia.

- Lê somente arquivos nfcapd.20* com pelo menos 45s de idade e ate 1h.
- Consulta o ledger antes de escolher o lote: arquivos ja processados nao ocupam as 20 vagas, permitindo avancar no backlog apos cada execucao.
- Processa ate 20 arquivos pendentes em cada rodada; rollback integral em falha.
- Ledger orby_ingested_files e rollup orby_traffic_minute compartilham a
  mesma transacao, impedindo reimportacao e duplo somatorio.
- Rejeita registros mais de 5min no futuro ou 4h no passado.
- Retencao e geolocalizacao ainda NAO sao automaticas.
- Usa nfdump -o json em memoria: piloto com limite de 32MiB por arquivo binario.
- Atribui volume ao minuto de encerramento do fluxo: estimativa, nao medicao
  exata nem taxa garantida para faturamento. Comparar com SNMP Huawei.

## 1. Instalar Python e banco no Ubuntu 24.04

~~~bash
cd /opt/orbymon
git pull --ff-only origin main
sudo apt-get update
sudo apt-get install -y python3-venv mariadb-server
python3 -m venv .venv
.venv/bin/pip install -e '.[mysql]'
PYTHONPATH=src python3 -m unittest discover -s tests -v
~~~

Criar banco como administrador MariaDB:

~~~sql
CREATE DATABASE IF NOT EXISTS orbymon CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
~~~

~~~bash
sudo mariadb orbymon < sql/schema.sql
~~~

Criar contas distintas: writer com SELECT/INSERT/UPDATE e Grafana com
SELECT somente no schema orbymon. Usar host local 127.0.0.1 e senhas fortes.
Nao colar senhas em chat, repositorio ou shell compartilhado.

## 2. Teste sem tocar no banco

~~~bash
sudo -u orbymon /opt/orbymon/.venv/bin/python -m fmn_filters.ingest_nfcapd --source huawei --dry-run --max-files 3
~~~

Se nao houver arquivos elegiveis, confira mtime e a janela de uma hora.

## 3. EnvironmentFile privado do timer

Criar /etc/orbymon/pipeline.env com:

~~~ini
ORBYMON_DB_HOST=127.0.0.1
ORBYMON_DB_PORT=3306
ORBYMON_DB_NAME=orbymon
ORBYMON_DB_USER=orbymon_writer
ORBYMON_DB_PASSWORD=COLOQUE_SENHA_REAL_AQUI
~~~

~~~bash
sudo chown root:orbymon /etc/orbymon/pipeline.env
sudo chmod 0640 /etc/orbymon/pipeline.env
sudo install -m 0644 deploy/systemd/orbymon-traffic-huawei.service /etc/systemd/system/
sudo install -m 0644 deploy/systemd/orbymon-traffic-huawei.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start orbymon-traffic-huawei.service
sudo journalctl -u orbymon-traffic-huawei.service -n 30 --no-pager
sudo systemctl enable --now orbymon-traffic-huawei.timer
sudo systemctl list-timers orbymon-traffic-huawei.timer
~~~

Para parar apenas o pipeline sem parar nfcapd:
~~~bash
sudo systemctl disable --now orbymon-traffic-huawei.timer
~~~

## 4. Inspecionar rollups

~~~bash
sudo mariadb orbymon -e "SELECT COUNT(*) arquivos, SUM(flow_count) fluxos FROM orby_ingested_files"
sudo mariadb orbymon -e "SELECT bucket_utc, protocol, ROUND(SUM(total_bytes)*8/60000000,2) mbps_est FROM orby_traffic_minute GROUP BY bucket_utc, protocol ORDER BY bucket_utc DESC LIMIT 15"
~~~

A tabela usa UTC. Grafana deve ler o banco via usuario somente SELECT e
o datasource com UID orbymon-mysql. O JSON inicial esta em
grafana/dashboards/orbymon-overview.json. Ainda nao validado em Grafana real.

## Pendencias

NTP permanente Huawei, precisao da amostragem vs SNMP, GeoLite2 offline,
limite de memoria no JSON, retencao/backup, alertas de falha de ingestao,
segmentacao por interface/provedor e detecao DDoS em modo passivo.
