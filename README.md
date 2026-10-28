# FastNetMon — Combined DDoS Filters (Community)

**Versão 0.1.0 — prova de conceito, somente alertas.** Motor complementar de detecção DDoS para provedores. **Não é um fork nem uma substituição do FastNetMon Community.** Este projeto recebe registros de fluxo NetFlow/IPFIX de um coletor `nfdump` e logs HTTP normalizados, executa regras combinadas e gera alertas JSON. **Não executa bloqueio, RTBH, FlowSpec ou outras alterações em roteadores.**

## Filtros disponíveis

- Regras `all_of` (AND) e `any_of` (OR), incluindo grupos aninhados.
- Redes CIDR IPv4/IPv6, origem/destino, portas TCP/UDP, protocolo, flags TCP e exclusões.
- Janelas por destino/IP/porta/protocolo com limites de PPS, Mbps, fluxos/s e fontes únicas.
- DNS flood, resposta DNS suspeita, SYN flood, UDP flood e HTTP/PHP por logs Nginx/Apache/WAF.
- Cooldown de alertas; saída NDJSON pronta para futuras integrações com Zabbix/Grafana.

**Importante:** NetFlow/IPFIX não identifica URLs `.php` em tráfego HTTPS. Para filtros PHP é obrigatório ingerir logs HTTP do servidor/reverse proxy. O projeto ainda **não correlaciona HTTP e NetFlow numa única regra**. As regras de DNS por porta/volume não comprovam, isoladamente, amplificação ou falsificação do IP de origem.

## SO recomendado

Ubuntu Server 24.04 LTS, com Python >=3.10 e `nfdump`. Debian 12 também é opção. Mantenha o FastNetMon Community como sensor independente e configure fluxos para o coletor desta aplicação; não suponha que todos os roteadores enviem a mais de um exportador.

## Início rápido

```bash
sudo apt update && sudo apt install -y python3 nfdump git
git clone https://github.com/Br10Consultoria/FastNetMon.git
cd FastNetMon
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m fmn_filters --rules rules/example-rules.json --validate
PYTHONPATH=src python3 -m fmn_filters --rules rules/demo-rules.json --input samples/flows.ndjson --input samples/http.ndjson
```

O último comando deve gerar dois alertas simulados, `DNS-demo` e `PHP-demo`. IPs `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32` são **apenas exemplos**; não monitore produção com esses prefixos.

## Recepção NetFlow/IPFIX (laboratório)

```bash
sudo mkdir -p /var/lib/nfdump
sudo nfcapd -D -w /var/lib/nfdump -p 2056 -t 10
PYTHONPATH=src python3 -m fmn_filters --rules rules/example-rules.json --watch-dir /var/lib/nfdump --state-db ./state/processed.db --poll-seconds 3
```

Configure o exportador para enviar fluxos NetFlow v9/IPFIX para UDP 2056 e autorize **somente** os IPs de exportadores confiáveis no firewall. O FastNetMon pode usar UDP 2055 separadamente. O `--watch-dir` processa **arquivos rotacionados** e tem latência maior que um detector em streaming. **Não execute como root em produção.**

## HTTP/PHP

Exemplo para Nginx (ajuste ao ambiente):

```nginx
log_format fmn_json escape=json
    '{"kind":"http","timestamp":"$time_iso8601",'
    '"src_ip":"$remote_addr","dst_ip":"$server_addr",'
    '"dst_port":$server_port,"method":"$request_method",'
    '"path":"$uri","status":$status,"bytes":$body_bytes_sent}';
access_log /var/log/nginx/fmn_access.json fmn_json;
```

```bash
tail -n 0 -F /var/log/nginx/fmn_access.json | PYTHONPATH=src python3 -m fmn_filters --rules rules/example-rules.json --input -
```

## Segurança e limites

Prova de conceito **alert-only**, não validada em rede multi-Gbps. Sensível a exportação atrasada, amostragem e arquivos de fluxo grandes; contagens de fontes distintas têm limite; não analisa conteúdo DNS L7; não interpreta URLs HTTPS sem logs; estado das janelas não persiste após reinício. Não use como único detector nem ative mitigação automática antes de testes de falsos positivos.

Consulte `docs/ARCHITECTURE.md` e `docs/ROADMAP.md`.

## Licença

MIT para código original deste repositório, independente do FastNetMon Community (GPL-2.0). Nenhum código FastNetMon foi incorporado.
