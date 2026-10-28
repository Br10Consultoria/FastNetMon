## OrbyMon v0.3 — Teste rápido de incidentes

**Já publicado:** correlação persistente e deduplicação de alertas, identificação de destino/regra e picos PPS/Mbps/RPS, histórico SQLite e API local autenticada. **33 testes unitários aprovados em laboratório, sem equipamentos reais.**

```bash
git clone https://github.com/Br10Consultoria/FastNetMon.git
cd FastNetMon
bash scripts/test-incidents.sh
```

Manual: [Laboratório e API](docs/TESTING_INCIDENTS.md) · [Posicionamento e limites de cópia](docs/PRODUCT_POSITIONING.md) · [Grafana](docs/GRAFANA.md)

**Limitações:** Sem validação com Huawei NE8000, sem mitigação automática, sem frontend próprio de incidentes, sem isolamento multiusuário de produção e ainda sem sincronização automática do novo SQLite com o Grafana. Use Grafana v0.2 para visualização de alertas/fluxos quando o sink MariaDB estiver configurado e homologado.

---

# OrbyMon 🛡️

**OrbyMon — observabilidade de tráfego e defesa DDoS** (família Orby). Repositório `Br10Consultoria/FastNetMon`. Identidade laranja e azul.

![Marca OrbyMon](assets/orbymon-logo.svg)

**POC v0.2: somente detecção/monitoramento; nenhum bloqueio automático.**

## Adições da v0.2

- ASN de origem/destino, país, nome do ASN e coordenadas GeoLite2 (opcional, offline).
- Filtros ASN, geografia, interface, flags TCP (incluindo exclusão ACK), ICMP, TTL, bytes, duração, NAT e next-hop quando disponíveis.
- Operador `not` aninhado, mais `all_of` e `any_of`.
- Persistência opcional em MariaDB de alertas e agregados por ASN/país/porta.
- Dashboard Grafana com mapa aproximado, top ASNs, países e portas, alertas e tráfego por protocolo.
- Identidade visual original em `assets/` (SVG e PNG).

**Leia antes de usar**: [Filtros](docs/FILTERS.md) · [Grafana/MariaDB](docs/GRAFANA.md) · [Próximas melhorias](docs/NEXT_STEPS.md).

# FastNetMon Combined Filters — v0.1.0 (POC)

**Motor complementar de regras combinadas de deteccao DDoS para provedores de Internet.**

> Estado: **prototipo funcional / ALERT-ONLY / sem mitigacao automatica**. Nao e um fork nem substituto do FastNetMon Community: processa telemetria NetFlow/IPFIX por meio do `nfdump` e, opcionalmente, logs HTTP normalizados. Nao modifique rotas ou producao com base apenas em alertas deste prototipo.

## O que ja funciona

- Regras JSON com `all_of` (AND) e `any_of` (OR), inclusive aninhados.
- CIDR IPv4 e IPv6 de origem/destino, portas de origem/destino, protocolos, flags TCP, exclusoes por rede.
- Agrupamento por IP/porta/protocolo; calculos em janela de tempo: PPS, Mbps, fluxos/s, fontes IP distintas; por logs HTTP: RPS, fontes IP distintas e sufixo `.php`.
- Cooldown por regra/grupo para reduzir alertas repetidos.
- JSON de saida por linha, apropriado para integrar com Zabbix, Grafana, SIEM ou Webhook futuramente.
- Leitura de NDJSON (fluxos normalizados e logs HTTP) e do `nfdump -o json` (array JSON).
- Modo `--watch-dir` que observa arquivos **rotacionados** `nfcapd.*`, guarda o checkpoint em SQLite e executa `nfdump` com timezone UTC.
- Testes `unittest` sem bibliotecas Python de terceiros.

## Escolha do Linux

**Ubuntu Server 24.04 LTS recomendado** pelo suporte e disponibilidade de pacotes. **Debian 12** e alternativa excelente. O FastNetMon Community e o coletor `nfdump` podem residir na mesma VM, mas usam **portas UDP distintas** (exemplo: FastNetMon em 2055 e `nfcapd` em 2056) e o equipamento deve enviar telemetria para ambos. Nao pressuponha que todo roteador permite multiplos targets/exporters.

## Instalacao local para testes (Ubuntu 24.04 / Debian 12)

```bash
sudo apt-get update
sudo apt-get install -y python3 nfdump git
# Opcional, dentro do projeto: sudo bash scripts/prepare-ubuntu.sh
# Dentro do projeto:
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m fmn_filters --rules rules/example-rules.json --validate
```

Em um checkout Git:

```bash
git clone https://github.com/SEU-USUARIO/fastnetmon-combined-filters.git
cd fastnetmon-combined-filters
```

**O repositório remoto precisa existir antes desse `git clone`.** No primeiro uso, extraia o ZIP do projeto, se ainda nao o publicou no GitHub.

### Demonstracao que gera dois alertas

```bash
PYTHONPATH=src python3 -m fmn_filters \
  --rules rules/demo-rules.json \
  --input samples/flows.ndjson \
  --input samples/http.ndjson
```

Deve emitir alertas `DNS-demo` e `PHP-demo`, ambos com `"action":"alert_only"`. IPs `198.51.100.0/24`, `203.0.113.0/24`, `192.0.2.0/24` e `2001:db8::/32` sao enderecos reservados de exemplo. **Substitua pelos prefixos reais antes de monitorar**.

## Coletando dados de verdade (piloto)

### 1. FastNetMon Community

Instale separadamente o FastNetMon Community seguindo as instrucoes oficiais do projeto. Este prototipo **nao instala nem modifica** o daemon `fastnetmon`, seus gatilhos ou os anuncios BGP.

### 2. nfcapd para uma segunda exportacao NetFlow/IPFIX

O comando abaixo coleta NetFlow/IPFIX em UDP 2056 e gira os arquivos a cada 10s. Execute em uma maquina de **laboratorio** e depois configure `systemd`, politica de firewall e retencao de arquivos.

```bash
sudo mkdir -p /var/lib/nfdump
sudo nfcapd -D -w /var/lib/nfdump -p 2056 -t 10
```

Configure o roteador/exportador para enviar **NetFlow v9/IPFIX** ao IP deste servidor na porta UDP 2056. O FastNetMon Community recebera o seu feed separado (por exemplo em UDP 2055). **Apenas pacotes UDP 2056 provenientes dos IPs exportadores autorizados devem passar pelo firewall**. Se o dispositivo nao tiver 2 destinos de exportacao, sera necessario reavaliar a arquitetura (replicador, analisador proprio ou fonte alternativa).

> `nfcapd -t 10` nao significa deteccao em 10s: o timeout de exportacao do roteador e o intervalo de rotacao influenciam a latencia. Para ataques muito rapidos, o FastNetMon continua sendo o sensor principal. O adaptador de arquivos e para prova de conceito; nao foi testado em trafego de operadora.

### 3. Monitorando arquivos rotacionados (POC)

```bash
PYTHONPATH=src python3 -m fmn_filters \
  --rules rules/example-rules.json \
  --watch-dir /var/lib/nfdump \
  --state-db ./state/processed.db \
  --poll-seconds 3
```

Para um teste unitario de um arquivo exportado:

```bash
TZ=UTC nfdump -r /var/lib/nfdump/nfcapd.AAAAmmddHHMMSS -o json > flows.json
PYTHONPATH=src python3 -m fmn_filters \
  --rules rules/example-rules.json \
  --input flows.json --format json --assume-utc
```

**Seguranca/limitacoes**: `--watch-dir` guarda o JSON retornado pelo `nfdump` em memoria; nao e adequado ainda para arquivos enormes ou throughput muito alto. Use um usuario sem privilegios, com acesso de leitura ao diretorio do `nfcapd` e escrita apenas ao SQLite de estado. Nao rode o analisador como root em producao. Adapte permissao de grupo/ACL e arquivos rotacionados com cuidado. Em producao, sera necessario streaming, limites de recursos e tratamento de atrasos/fluxos duplicados.

## Regras combinadas

Leia `rules/example-rules.json`: DNS consulta, DNS resposta/amplificacao, SYN TCP, UDP por destino e flood de PHP. A maioria das condicoes dentro de um `match` sao **AND**; listas `src_cidrs`, `dst_cidrs`, `src_ports`, `dst_ports` sao alternativas dentro de cada campo. `all_of` combina subfiltros com AND; `any_of` com OR.

```json
{
  "name": "Exemplo-DNS",
  "kind": "flow",
  "match": {
    "protocols": ["udp"],
    "dst_ports": [53],
    "dst_cidrs": ["198.51.100.0/24"],
    "exclude_src_cidrs": ["192.0.2.0/24"]
  },
  "group_by": ["dst_ip", "dst_port"],
  "window_seconds": 10,
  "cooldown_seconds": 60,
  "thresholds": {"min_pps": 20000, "min_unique_sources": 15}
}
```

Todos os campos em `thresholds` devem atingir o minimo (AND). A contagem de fontes distintas e **limitada a 10.000 por bucket** no prototipo; taxas e fluxos sao estimados por distribuicao uniforme dos contadores por duracao do fluxo. `flows_per_sec` **nao representa o numero real de conexoes por segundo quando ha amostragem**. A escala dos bytes/pacotes do `nfdump` depende da taxa de amostragem aplicada pelo coletor/exportador. Nao aplique outra multiplicacao sem validar a telemetria.

## PHP / HTTP (nao vem do NetFlow!)

NetFlow/IPFIX nao revela caminhos `.php`, URL nem camada HTTP dentro de TLS/HTTPS. Use logs de acesso do Nginx/Apache/WAF. Formato JSON NDJSON sugerido para Nginx (ajuste para a sua versao/configuracao):

```nginx
log_format fmn_json escape=json
    '{"kind":"http","timestamp":"$time_iso8601",'
    '"src_ip":"$remote_addr","dst_ip":"$server_addr",'
    '"dst_port":$server_port,"method":"$request_method",'
    '"path":"$uri","status":$status,"bytes":$body_bytes_sent}';
access_log /var/log/nginx/fmn_access.json fmn_json;
```

```bash
tail -n 0 -F /var/log/nginx/fmn_access.json | \
  PYTHONPATH=src python3 -m fmn_filters \
  --rules rules/example-rules.json --input -
```

Se estiver atras de reverse proxy/CDN, configure a recuperacao de IP real **apenas de proxies confiaveis**; caso contrario a origem sera o proxy, nao o cliente. O filtro `.php` e pelo caminho; **nao identifica por si so exploracao de vulnerabilidade**. O componente HTTP funciona isoladamente neste marco; correlacionar eventos HTTP+NetFlow em uma mesma regra esta no backlog.

## Limites conhecidos — v0.1.0

- **Nao existe motor de mitigacao, FlowSpec, BGP/RTBH, webhook nem dashboard** nesta versao. Evita bloqueios falsos em clientes de provedores.
- O processamento de `nfdump` e **pós-rotacao**, nao packet-by-packet. A acuracia e latencia dependem do timeout do roteador, tipo de exportacao, amostragem e possiveis registros perdidos.
- Não ha deteccao DNS L7 (QNAME, QTYPE, NXDOMAIN, EDNS); os exemplos de DNS usam porta 53 e volume, **nao confirmam reflexao, spoofing ou amplificacao**.
- Não ha detector HTTP request/response por conexao, fingerprint TLS, payload ou detecção de bot. Regras PHP so operam com logs web.
- Arquivos antigos sao ignorados em `--watch-dir` (padrao: 15 minutos), evitando tempestades de alertas historicos. Nao existe checkpoint transacional de entrega de alertas e pode haver repeticao em falha.
- Nao ha correlacao interfontes no mesmo gatilho, e o estado dos contadores nao e restaurado depois de reinicio (apenas arquivos lidos). Evite usar como unico sensor.
- Nao oferece suporte de desempenho validado para multi-Gbps; eh preciso benchmark e analise da carga em ambiente de laboratorio.

## Planos de desenvolvimento

Leia [`docs/ROADMAP.md`](docs/ROADMAP.md). Ordem proposta: sensor/coletores em streaming; testes com exportadores reais MikroTik/Huawei/Juniper/Cisco; evidencia e historico; perfil por cliente; correlacao HTTP+NetFlow; dashboard; integracao Zabbix/Grafana; **so depois** mitigacao supervisionada com protecoes, auditoria e rollback.

## Publicar no GitHub depois de criar o repositorio vazio

Depois de criar manualmente `Br10Consultoria/fastnetmon-combined-filters` **sem inicializar README/licenca**, no diretorio extraido do ZIP:

```bash
git init -b main
git add .
git commit -m "feat: detector de regras combinadas DDoS v0.1.0"
git remote add origin https://github.com/Br10Consultoria/fastnetmon-combined-filters.git
git push -u origin main
```

E preciso ter credenciais do GitHub configuradas para `git push`. Nao salve tokens em scripts e nao suba arquivos `*.db`, capturas reais ou dados pessoais de clientes ao repositório.

## Licenca

MIT para o codigo novo deste repositorio. **FastNetMon Community e um projeto independente sob GPL-2.0.** Nenhum codigo do FastNetMon foi copiado para este projeto.
