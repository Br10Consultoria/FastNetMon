#!/usr/bin/env bash
# ClickHouse para os fluxos (retencao longa e consultas rapidas por IP), ao lado do MariaDB.
#   sudo bash scripts/setup-clickhouse.sh [--ttl-days 30] [--memory-ratio 0.25]
# - instala o clickhouse-server (repositorio oficial, canal LTS) se faltar
# - escuta so em 127.0.0.1; limita a memoria; desliga logs internos que gastam disco
# - cria 3 usuarios locais: administrador (so este script), gravacao (rollup) e leitura (painel, 30 s/2 GB por consulta)
#   O usuario "default" fica bloqueado (senha aleatoria descartada).
# - senhas em /etc/orbymon/clickhouse*.env (lidos pelo systemd como dado, nunca executados)
# - o rollup passa a gravar no ClickHouse a partir da proxima execucao; o painel usa no detalhe dos ataques
# Reexecutar e seguro: mantem as senhas e os dados; so ajusta configuracao e retencao.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Execute com sudo" >&2; exit 1; }
BASE="$(cd "$(dirname "$0")/.." && pwd)"
TTL=30
RATIO=0.25
STATUS=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --status) STATUS=1; shift ;;
    --ttl-days) TTL="${2:-}"; shift 2 ;;
    --memory-ratio) RATIO="${2:-}"; shift 2 ;;
    *) echo "opcao desconhecida: $1" >&2; exit 1 ;;
  esac
done
[[ "$TTL" =~ ^[0-9]+$ ]] && (( TTL >= 1 && TTL <= 3650 )) || { echo "--ttl-days entre 1 e 3650" >&2; exit 1; }
[[ "$RATIO" =~ ^0\.[1-6][0-9]?$ ]] || { echo "--memory-ratio entre 0.1 e 0.6" >&2; exit 1; }
id orbymon >/dev/null && id orbymon-admin >/dev/null || { echo "usuarios orbymon/orbymon-admin ausentes" >&2; exit 1; }

ch_status() {   # le a senha do arquivo como dado (nunca executa o arquivo)
  local p; p=$(sed -n 's/^ORBYMON_CH_PASSWORD=//p' /etc/orbymon/clickhouse-reader.env | head -n 1)
  ORBYMON_CH_URL=http://127.0.0.1:8123 ORBYMON_CH_USER=orbyflow_reader ORBYMON_CH_PASSWORD="$p" \
    ORBYMON_CH_DATABASE=orbyflow PYTHONPATH="$BASE/src" "$BASE/.venv/bin/python" -m fmn_filters.clickhouse --status
  local n; n=$(find /var/lib/orbymon/clickhouse-spool -name '*.tsv.gz' 2>/dev/null | wc -l)
  echo "lotes aguardando no spool: $n"
}
if (( STATUS )); then ch_status; exit; fi

echo "=== CPU ==="
# x86-64-v2 (SSE4.2, POPCNT): minimo. Em VM Proxmox com CPU "kvm64" esses recursos ficam escondidos e o binario morre
# com "Illegal instruction": mude o tipo de CPU da VM para "host" e desligue/ligue.
for flag in sse4_2 popcnt ssse3 sse4_1; do
  grep -qw "$flag" /proc/cpuinfo || { echo "CPU da VM sem $flag: no Proxmox, Hardware > Processadores > Tipo = host," \
    "desligue e ligue a VM e rode de novo." >&2; exit 1; }
done
# ClickHouse 26.6+ exige x86-64-v3 (AVX2). Sem AVX2 (ex.: Xeon E56xx/Westmere) fixa a serie LTS 26.3, a ultima
# compilada para x86-64-v2 (correcoes ate ~marco/2027). Com AVX2 usa o LTS atual.
SERIES=""
if ! grep -qw avx2 /proc/cpuinfo; then
  SERIES="${ORBYFLOW_CH_SERIES:-26.3}"
  echo "CPU sem AVX2: ClickHouse fixado na serie LTS $SERIES (x86-64-v2)"
else
  echo "ok (x86-64-v3)"
fi

echo "=== Pacotes ==="
if [[ ! -f /etc/apt/sources.list.d/clickhouse.list ]]; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q apt-transport-https ca-certificates curl gnupg >/dev/null
  curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' \
    | gpg --dearmor --yes -o /usr/share/keyrings/clickhouse-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg arch=$(dpkg --print-architecture)] https://packages.clickhouse.com/deb lts main" \
    > /etc/apt/sources.list.d/clickhouse.list
fi
PIN=/etc/apt/preferences.d/clickhouse-orbyflow
if [[ -n "$SERIES" ]]; then
  [[ "$SERIES" =~ ^[0-9]+\.[0-9]+$ ]] || { echo "ORBYFLOW_CH_SERIES invalido" >&2; exit 1; }
  printf 'Package: clickhouse-*\nPin: version %s.*\nPin-Priority: 1001\n' "$SERIES" > "$PIN"
else
  rm -f "$PIN"
fi
apt-get update -q >/dev/null
# instalacao anterior que nao roda nesta CPU (ex.: 26.8 sem AVX2): remove antes de instalar a serie certa
if dpkg-query -W -f='${Status}' clickhouse-server 2>/dev/null | grep -q "install" && \
   { ! dpkg-query -W -f='${Status}' clickhouse-server | grep -q "install ok installed" || \
     ! clickhouse-server --version >/dev/null 2>&1; }; then
  echo "removendo instalacao que nao executa nesta CPU"
  DEBIAN_FRONTEND=noninteractive dpkg --purge --force-remove-reinstreq clickhouse-server clickhouse-client \
    clickhouse-common-static >/dev/null 2>&1 || true
fi
if ! command -v clickhouse-server >/dev/null; then
  if [[ -n "$SERIES" ]] && ! apt-cache madison clickhouse-server | awk '{print $3}' | grep -q "^${SERIES}\."; then
    echo "serie $SERIES nao encontrada no repositorio do ClickHouse" >&2; exit 1
  fi
  # senha do "default" vazia na instalacao; logo abaixo ele e bloqueado
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q --allow-downgrades clickhouse-server clickhouse-client >/dev/null
fi
clickhouse-server --version >/dev/null 2>&1 || { echo "clickhouse-server nao executa nesta CPU" >&2; exit 1; }
id clickhouse >/dev/null 2>&1 || { echo "usuario clickhouse nao foi criado pelo pacote" >&2; exit 1; }
clickhouse-server --version 2>/dev/null | head -n 1

echo "=== Configuracao do servidor ==="
install -d -m 0755 /etc/clickhouse-server/config.d /etc/clickhouse-server/users.d
cat > /etc/clickhouse-server/config.d/orbyflow.xml <<XML
<!-- Gerado por scripts/setup-clickhouse.sh (OrbyFlow) -->
<clickhouse>
  <listen_host>127.0.0.1</listen_host>
  <mysql_port remove="1"/>
  <postgresql_port remove="1"/>
  <interserver_http_port remove="1"/>
  <max_server_memory_usage_to_ram_ratio>${RATIO}</max_server_memory_usage_to_ram_ratio>
  <mark_cache_size>268435456</mark_cache_size>
  <uncompressed_cache_size>0</uncompressed_cache_size>
  <logger><level>warning</level><size>100M</size><count>3</count></logger>
  <query_log><ttl>event_date + INTERVAL 7 DAY</ttl></query_log>
  <part_log remove="1"/>
  <trace_log remove="1"/>
  <metric_log remove="1"/>
  <asynchronous_metric_log remove="1"/>
  <text_log remove="1"/>
  <processors_profile_log remove="1"/>
  <query_thread_log remove="1"/>
  <query_views_log remove="1"/>
  <latency_log remove="1"/>
  <error_log remove="1"/>
  <query_metric_log remove="1"/>
</clickhouse>
XML
chmod 0644 /etc/clickhouse-server/config.d/orbyflow.xml

echo "=== Usuarios ==="
read_pass() { [[ -f "$1" ]] && sed -n 's/^ORBYMON_CH_PASSWORD=//p' "$1" | tr -d "\"' " | head -n 1 || true; }
new_pass() { openssl rand -hex 24; }
ADMIN_ENV=/etc/orbymon/clickhouse-admin.env WRITE_ENV=/etc/orbymon/clickhouse.env READ_ENV=/etc/orbymon/clickhouse-reader.env
ADMIN_PASS=$(read_pass "$ADMIN_ENV"); [[ "$ADMIN_PASS" =~ ^[0-9a-f]{48}$ ]] || ADMIN_PASS=$(new_pass)
WRITE_PASS=$(read_pass "$WRITE_ENV"); [[ "$WRITE_PASS" =~ ^[0-9a-f]{48}$ ]] || WRITE_PASS=$(new_pass)
READ_PASS=$(read_pass "$READ_ENV");  [[ "$READ_PASS" =~ ^[0-9a-f]{48}$ ]] || READ_PASS=$(new_pass)
GRAF_ENV=/etc/orbymon/grafana-clickhouse.env
GRAF_PASS=$([[ -f "$GRAF_ENV" ]] && sed -n 's/^ORBYFLOW_CH_GRAFANA_PASSWORD=//p' "$GRAF_ENV" | head -n 1 || true)
[[ "$GRAF_PASS" =~ ^[0-9a-f]{48}$ ]] || GRAF_PASS=$(new_pass)
LOCK_PASS=$(new_pass)                      # bloqueia o "default": ninguem guarda essa senha
sha() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }
write_env() {   # arquivo dono grupo usuario senha
  local tmp; tmp=$(mktemp "$1.XXXXXX")
  printf 'ORBYMON_CH_URL=http://127.0.0.1:8123\nORBYMON_CH_USER=%s\nORBYMON_CH_PASSWORD=%s\nORBYMON_CH_DATABASE=orbyflow\n' "$4" "$5" > "$tmp"
  chown "$2:$3" "$tmp"; chmod "$6" "$tmp"; mv -f "$tmp" "$1"
}
write_env "$ADMIN_ENV" root root orbyflow_admin "$ADMIN_PASS" 0600
write_env "$WRITE_ENV" root orbymon orbyflow_writer "$WRITE_PASS" 0640
write_env "$READ_ENV" root orbymon-admin orbyflow_reader "$READ_PASS" 0640
# a instalacao pode criar um arquivo com a senha do default; o nosso a substitui
[[ -f /etc/clickhouse-server/users.d/default-password.xml ]] && \
  mv -f /etc/clickhouse-server/users.d/default-password.xml /etc/clickhouse-server/users.d/default-password.xml.orbyflow-off
TMPX=$(mktemp /etc/clickhouse-server/users.d/.orbyflow.XXXXXX)
cat > "$TMPX" <<XML
<!-- Gerado por scripts/setup-clickhouse.sh (OrbyFlow). Senhas em /etc/orbymon/clickhouse*.env -->
<clickhouse>
  <profiles>
    <orbyflow_reader>
      <readonly>2</readonly>
      <max_execution_time>30</max_execution_time>
      <max_memory_usage>2000000000</max_memory_usage>
      <max_threads>4</max_threads>
      <max_result_rows>100000</max_result_rows>
      <constraints>
        <max_execution_time><max>60</max></max_execution_time>
        <max_memory_usage><max>2000000000</max></max_memory_usage>
        <max_threads><max>4</max></max_threads>
      </constraints>
    </orbyflow_reader>
    <orbyflow_grafana>
      <readonly>2</readonly>
      <join_use_nulls>1</join_use_nulls>
      <max_execution_time>60</max_execution_time>
      <max_memory_usage>3000000000</max_memory_usage>
      <max_threads>4</max_threads>
      <constraints>
        <max_execution_time><max>120</max></max_execution_time>
        <max_memory_usage><max>3000000000</max></max_memory_usage>
        <max_threads><max>4</max></max_threads>
        <join_use_nulls><readonly/></join_use_nulls>
      </constraints>
    </orbyflow_grafana>
    <orbyflow_writer>
      <max_memory_usage>1500000000</max_memory_usage>
      <max_threads>2</max_threads>
    </orbyflow_writer>
  </profiles>
  <users>
    <default>
      <password remove="1"/>
      <password_sha256_hex>$(sha "$LOCK_PASS")</password_sha256_hex>
      <networks replace="replace"><ip>127.0.0.1</ip></networks>
      <access_management>0</access_management>
    </default>
    <orbyflow_admin>
      <password_sha256_hex>$(sha "$ADMIN_PASS")</password_sha256_hex>
      <networks><ip>127.0.0.1</ip></networks>
      <profile>default</profile><quota>default</quota>
      <grants><query>GRANT ALL ON orbyflow.*</query></grants>
    </orbyflow_admin>
    <orbyflow_writer>
      <password_sha256_hex>$(sha "$WRITE_PASS")</password_sha256_hex>
      <networks><ip>127.0.0.1</ip></networks>
      <profile>orbyflow_writer</profile><quota>default</quota>
      <grants>
        <query>GRANT SELECT, INSERT ON orbyflow.*</query>
        <query>GRANT TRUNCATE ON orbyflow.orby_interface_names</query>
        <query>GRANT TRUNCATE ON orbyflow.orby_country_names</query>
        <query>GRANT TRUNCATE ON orbyflow.orby_net_prefixes</query>
        <query>GRANT TRUNCATE ON orbyflow.orby_asn_group_members</query>
      </grants>
    </orbyflow_writer>
    <orbyflow_grafana>
      <password_sha256_hex>$(sha "$GRAF_PASS")</password_sha256_hex>
      <networks><ip>127.0.0.1</ip></networks>
      <profile>orbyflow_grafana</profile><quota>default</quota>
      <grants><query>GRANT SELECT ON orbyflow.*</query></grants>
    </orbyflow_grafana>
    <orbyflow_reader>
      <password_sha256_hex>$(sha "$READ_PASS")</password_sha256_hex>
      <networks><ip>127.0.0.1</ip></networks>
      <profile>orbyflow_reader</profile><quota>default</quota>
      <grants><query>GRANT SELECT ON orbyflow.*</query></grants>
    </orbyflow_reader>
  </users>
</clickhouse>
XML
chown root:clickhouse "$TMPX"; chmod 0640 "$TMPX"; mv -f "$TMPX" /etc/clickhouse-server/users.d/orbyflow.xml
unset LOCK_PASS

echo "=== Servico ==="
systemctl enable clickhouse-server >/dev/null 2>&1 || true
systemctl restart clickhouse-server
for _ in $(seq 1 60); do
  curl -fs --noproxy '*' http://127.0.0.1:8123/ping >/dev/null 2>&1 && break
  sleep 1
done
curl -fs --noproxy '*' http://127.0.0.1:8123/ping >/dev/null || { echo "ClickHouse nao respondeu; veja journalctl -u clickhouse-server" >&2; exit 1; }

echo "=== Banco e retencao (${TTL} dias) ==="
ORBYMON_CH_URL=http://127.0.0.1:8123 ORBYMON_CH_USER=orbyflow_admin ORBYMON_CH_PASSWORD="$ADMIN_PASS" \
  ORBYMON_CH_DATABASE=orbyflow PYTHONPATH="$BASE/src" "$BASE/.venv/bin/python" -m fmn_filters.clickhouse --init --ttl-days "$TTL"

echo "=== Ligando rollup, pares de IP e painel ==="
install -d -m 0750 -o orbymon -g orbymon /var/lib/orbymon/clickhouse-spool
install -d -m 0755 /etc/systemd/system/orbymon-flow-rollup-huawei.service.d /etc/systemd/system/orbymon-admin.service.d
cat > /etc/systemd/system/orbymon-flow-rollup-huawei.service.d/clickhouse.conf <<'UNIT'
[Service]
EnvironmentFile=-/etc/orbymon/clickhouse.env
ReadWritePaths=-/var/lib/orbymon/clickhouse-spool
UNIT
install -d -m 0755 /etc/systemd/system/orbymon-ip-huawei.service.d
cat > /etc/systemd/system/orbymon-ip-huawei.service.d/clickhouse.conf <<'UNIT'
[Service]
EnvironmentFile=-/etc/orbymon/clickhouse.env
ReadWritePaths=-/var/lib/orbymon/clickhouse-spool
UNIT
cat > /etc/systemd/system/orbymon-admin.service.d/clickhouse.conf <<'UNIT'
[Service]
EnvironmentFile=-/etc/orbymon/clickhouse-reader.env
UNIT
# painel: leitura das bases GeoLite2 para mostrar ASN/pais dos IPs remotos
if [[ -d /var/lib/orbymon/geoip ]] && command -v setfacl >/dev/null; then
  setfacl -m u:orbymon-admin:rx /var/lib/orbymon/geoip
  setfacl -d -m u:orbymon-admin:r /var/lib/orbymon/geoip
  find /var/lib/orbymon/geoip -maxdepth 1 -name '*.mmdb' -exec setfacl -m u:orbymon-admin:r {} +
fi
systemctl daemon-reload
systemctl restart orbymon-admin
echo "rollup e pares de IP gravam no ClickHouse a partir da proxima execucao (1 min)"

echo "=== Grafana (plugin, fonte de dados e dashboards) ==="
GCLI=""
command -v grafana >/dev/null && GCLI="grafana cli"
[[ -z "$GCLI" ]] && command -v grafana-cli >/dev/null && GCLI="grafana-cli"
PLUGIN_OK=0
if [[ -n "$GCLI" ]] && id grafana >/dev/null 2>&1; then
  if ls -d /var/lib/grafana/plugins/*clickhouse* >/dev/null 2>&1; then
    PLUGIN_OK=1
  elif $GCLI --homepath /usr/share/grafana --pluginsDir /var/lib/grafana/plugins plugins install grafana-clickhouse-datasource 2>&1 \
       | grep -v -i deprecat | tail -n 5; then
    ls -d /var/lib/grafana/plugins/*clickhouse* >/dev/null 2>&1 && PLUGIN_OK=1
  fi
  if (( ! PLUGIN_OK )); then
    echo "AVISO: plugin ClickHouse do Grafana nao instalado (veja a mensagem acima); dashboards continuam no MariaDB." >&2
    echo "O ClickHouse ja esta gravando e o painel ja usa; rode este script de novo depois de resolver." >&2
  fi
fi
if (( PLUGIN_OK )); then
  chown -R grafana:grafana /var/lib/grafana/plugins/*clickhouse*
  tmp=$(mktemp "$GRAF_ENV.XXXXXX")
  printf 'ORBYFLOW_CH_GRAFANA_PASSWORD=%s\n' "$GRAF_PASS" > "$tmp"
  chown root:grafana "$tmp"; chmod 0640 "$tmp"; mv -f "$tmp" "$GRAF_ENV"
  install -d -m 0755 /etc/systemd/system/grafana-server.service.d
  cat > /etc/systemd/system/grafana-server.service.d/zz-orbyflow-clickhouse.conf <<'UNIT'
[Service]
EnvironmentFile=-/etc/orbymon/grafana-clickhouse.env
UNIT
  install -d -m 0755 /etc/grafana/provisioning/datasources
  cat > /etc/grafana/provisioning/datasources/orbyflow-clickhouse.yaml <<'YAML'
apiVersion: 1
datasources:
  - name: OrbyFlow ClickHouse
    uid: orbyflow-clickhouse
    type: grafana-clickhouse-datasource
    editable: false
    jsonData:
      host: 127.0.0.1
      port: 9000
      protocol: native
      secure: false
      username: orbyflow_grafana
      defaultDatabase: orbyflow
      dialTimeout: "10"
      queryTimeout: "60"
    secureJsonData:
      password: $ORBYFLOW_CH_GRAFANA_PASSWORD
YAML
  chown root:grafana /etc/grafana/provisioning/datasources/orbyflow-clickhouse.yaml
  chmod 0640 /etc/grafana/provisioning/datasources/orbyflow-clickhouse.yaml
  systemctl daemon-reload
  systemctl restart grafana-server
  bash "$BASE/scripts/deploy-live-dashboards.sh" >/dev/null && echo "dashboards Huawei/IPs/CGNAT/Visao geral no ClickHouse"
elif [[ -z "$GCLI" ]]; then
  echo "Grafana nao encontrado: dashboards nao alterados"
fi

echo "=== Estado ==="
sleep 2
ch_status || true
echo "Pronto. Para conferir depois: sudo bash scripts/setup-clickhouse.sh --status"
