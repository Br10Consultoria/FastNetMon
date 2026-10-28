# OrbyMon — laboratório de incidentes (v0.3 POC)

Esta entrega acrescenta **correlação e persistência de alertas** ao OrbyMon sem enviar qualquer configuração a roteadores. O objetivo é começar testes de ponta a ponta antes de um piloto com NetFlow/IPFIX real.

## Dependências

Ubuntu Server 24.04 LTS ou Debian 12; Python 3.10+; Git. O laboratório de incidentes usa apenas a biblioteca padrão do Python e SQLite. Grafana/MariaDB são opcionais e continuam conforme `docs/GRAFANA.md`.

## Teste imediato, sem rede e sem root

```bash
# Após clonar https://github.com/Br10Consultoria/FastNetMon.git
cd FastNetMon
bash scripts/test-incidents.sh
```

A rotina testa o código, gera alertas de DNS e PHP com dados de exemplo, grava os incidentes e lista o resultado. Usa banco temporário, descartado quando termina. É **um laboratório com telemetria simulada**: não comprova compatibilidade Huawei/MikroTik nem desempenho em tráfego real.

## Persistência local e replay

```bash
mkdir -p state
PYTHONPATH=src python3 -m fmn_filters --rules rules/demo-rules.json --input samples/flows.ndjson --input samples/http.ndjson |
  PYTHONPATH=src python3 -m fmn_filters.incidents --input - --db state/incidents.sqlite3 --tenant isp-teste
PYTHONPATH=src python3 -m fmn_filters.incidents --list --db state/incidents.sqlite3 --tenant isp-teste
```

Executar o mesmo replay novamente não duplica eventos já persistidos. `--quiet-seconds` controla a correlação de alertas de uma mesma regra/destino. O encerramento é manual nesta fase: `--resolve ID` marca um incidente como resolvido, **não bloqueia nenhuma conexão**. Incidentes que ficam sem alertas não são auto-resolvidos nesta versão.

## API local, protegida por token

```bash
# Defina um token aleatório e privado no ambiente (não grave no Git)
export ORBYMON_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
PYTHONPATH=src python3 -m fmn_filters.incidents --serve --db state/incidents.sqlite3 --tenant isp-teste
```

Em outro terminal, com o mesmo token disponível no ambiente:

```bash
curl -fsS http://127.0.0.1:8765/healthz
curl -fsS -H "Authorization: Bearer $ORBYMON_API_TOKEN" http://127.0.0.1:8765/api/v1/incidents
curl -fsS -H "Authorization: Bearer $ORBYMON_API_TOKEN" 'http://127.0.0.1:8765/api/v1/incidents?status=open&limit=10'
curl -fsS -H "Authorization: Bearer $ORBYMON_API_TOKEN" http://127.0.0.1:8765/metrics
```

A API só escuta em **127.0.0.1**, usa HTTP sem TLS (adequado apenas ao mesmo host) e não possui autorização multiusuário. **Não publique a porta 8765 na internet**. A segmentação `--tenant` é por processo, não é isolamento robusto de produção. Se for necessária exposição remota, realizar primeiro revisão de autenticação, RBAC e proxy com TLS.

## Fontes reais e Grafana

O coletor `nfcapd` e o sink MariaDB existentes no repositório permitem fazer validações de ingestão, mas o sink de fluxos ainda precisa de checkpoint para evitar dupla contagem. O novo armazenamento de incidentes SQLite **não é automaticamente sincronizado com o datasource MariaDB do Grafana**. A visualização atual do Grafana usa as tabelas `orby_alerts` e `orby_traffic_minute`, mantidas pelo pipeline v0.2. A integração de incidentes com Grafana será uma próxima entrega.

## Critérios de avanço ao piloto

1. Verificar o formato real exportado pelo Huawei NE8000 ou MikroTik (NetFlow v9/IPFIX; sampling, ASN, interfaces e direção).
2. Conferir diferenças dos contadores com o roteador e FastNetMon Community.
3. Medir atraso e perdas, sobreposição de fontes, CPU, RAM, disco e taxas de registros por segundo.
4. Ajustar baselines e falsos positivos com tráfego autorizado e anonimização adequada.
5. Não configurar RTBH, FlowSpec ou mitigação automática antes da homologação.
