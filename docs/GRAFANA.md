# OrbyMon — MariaDB e Grafana

## Estado

O dashboard JSON v0.2 foi gerado e validado sintaticamente. **Ainda não foi testado em um Grafana/MariaDB real.** Painéis históricos são alimentados por dois tipos distintos de dados:

1. `orby_alerts`: alertas do detector (não significa todo tráfego do ataque). ASN/geo só são atribuídos quando a dimensão de origem participa do agrupamento.
2. `orby_traffic_minute`: contadores de fluxo por ASN, país, protocolo e porta em buckets de 1 minuto, sem armazenar todos os IPs individuais.

Essa separação impede concluir que um IP agregado foi atacado por um único ASN. O painel geográfico usa somente alertas agrupados por `src_ip`, com localização **aproximada da base GeoIP**.

## Requisitos

- Grafana com datasource nativo MySQL (compatível com MariaDB).
- MariaDB com banco **separado** (recomendado) e usuário com permissões somente SELECT, INSERT e UPDATE nas tabelas OrbyMon.
- Python 3.10+ e `pip install -e '.[full]'` em virtualenv.
- GeoLite2-ASN.mmdb e GeoLite2-City.mmdb obtidos na conta MaxMind e atualizados por `geoipupdate` (aceitar licença e cumprir termos de uso).
- Exportador NetFlow/IPFIX configurado em porta UDP isolada e restrito aos roteadores de confiança.

## Banco

```sql
CREATE DATABASE orbymon CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
-- Importar sql/schema.sql no banco orbymon com usuario DBA.
-- Criar um usuário distinto para a aplicação e outro read-only no Grafana.
```

Variáveis de ambiente do processo `orbymon-mysql-sink`:

```bash
export ORBYMON_DB_HOST=127.0.0.1
export ORBYMON_DB_PORT=3306
export ORBYMON_DB_NAME=orbymon
export ORBYMON_DB_USER=orbymon_writer
export ORBYMON_DB_PASSWORD='PREENCHA-EM-UM-ARQUIVO-PRIVADO'
```

**Não coloque senha no repositório, histórico shell ou logs.** Use um EnvironmentFile protegido por permissões do sistema, ou um secret manager. Grafana deve usar usuário de somente leitura (separado do escritor).

## Gravar tráfego resumido por ASN/país

```bash
# Exemplo de um arquivo nfdump já rotacionado:
nfdump -r /var/lib/nfdump/nfcapd.202610281200 -o json |
  python3 -m fmn_filters.enrich_stream --format json \
     --asn-mmdb /var/lib/GeoIP/GeoLite2-ASN.mmdb \
     --city-mmdb /var/lib/GeoIP/GeoLite2-City.mmdb |
  python3 -m fmn_filters.mysql_sink --kind flows
```

Cada arquivo deve ser ingerido **uma única vez**. O sink de flows usa `ON DUPLICATE KEY UPDATE` para agregar; processar o mesmo arquivo duas vezes **duplica as métricas**, portanto configure um checkpoint antes de usar produção. O watcher do detector tem checkpoint próprio; o sink de fluxos **ainda não**.

## Gravar alertas do detector

```bash
python3 -m fmn_filters --rules rules/orbymon-advanced.json \
    --input samples/flows.ndjson --asn-mmdb /var/lib/GeoIP/GeoLite2-ASN.mmdb \
    --city-mmdb /var/lib/GeoIP/GeoLite2-City.mmdb |
  python3 -m fmn_filters.mysql_sink --kind alerts
```

O exemplo poderá gerar zero alertas: é uma demonstração das regras, e não um replay calibrado. O sink de alertas usa hash e `INSERT IGNORE` para prevenir duplicatas do mesmo evento.

## Importar no Grafana

Manual: Grafana → Dashboards → New → Import → carregar `grafana/dashboards/orbymon-overview.json` e selecionar datasource MariaDB com UID `orbymon-mysql`.

Provisionamento (mantenha cópia das configurações existentes):

- `grafana/provisioning/datasources/orbymon-mysql.yml` → `/etc/grafana/provisioning/datasources/`
- `grafana/provisioning/dashboards/orbymon.yml` → `/etc/grafana/provisioning/dashboards/`
- `grafana/dashboards/orbymon-overview.json` → `/var/lib/grafana/dashboards/orbymon/`

As variáveis de ambiente de datasource precisam estar disponíveis **ao serviço Grafana**, usando o leitor de somente leitura. Nunca exporte a senha de escritor para o serviço Grafana. Revise permissão de importação e UID antes do primeiro provisionamento para evitar sobrescrever dashboards existentes.

## Performance e retenção

- Os rollups por ASN/país/porta reduzem cardinalidade, mas **não são equivalentes a captura de pacotes**; a duração de fluxos longos não é distribuída por minuto.
- Escrever linha por linha em MariaDB pode ser custoso com alto volume; migrar para batch/queue com checkpoint e considerar ClickHouse quando o volume justificar.
- Definir política de retenção (ex.: rollups 30 dias, alertas 180 dias), e testar recuperação antes de exclusões.
- Validar a precisão de bytes/pps, amostragem e contagens com telemetria do NE8000.
