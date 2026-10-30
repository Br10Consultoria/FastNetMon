# OrbyMon Fase 3 - deteccao PASSIVA de anomalias DDoS

Sem qualquer comando no Huawei, Mikrotik, firewall, CGNAT, PPPoE,
FlowSpec ou RTBH. Alertas representam sinais de anomalia, nao ataques provados.

## Redes protegidas
- 45.238.170.0/23
- 187.87.201.0/24

As redes fornecidas ja constam do arquivo inicial de regras.
Limites ilustrativos conservadores: calibrar usando o trafego real e SNMP.

## Instalacao automatica

Requer fase 2 ja funcional (orby_ip_pairs_minute com dados):

    cd /opt/orbymon
    git pull --ff-only origin main
    PYTHONPATH=src python3 -m unittest discover -s tests -q
    sudo bash scripts/setup-ddos-passive.sh

Instala tabelas orby_ddos_rule_state e orby_ddos_checks, timer separado
orbymon-ddos-huawei.timer e dashboard Grafana. Reutiliza orby_alerts.
Ao reinstalar, preserva /etc/orbymon/ddos-rules.json ja existente.

## Filtros combinados

Suporta AND/all_of, OR/any_of, NOT/not, src/dst CIDR, origem ASN, pais,
protocolo, porta destino, interfaces entrada/saida e exclusoes.
Exemplo conceitual de AND UDP e (DNS ou NTP) e NOT rede confiavel:

    "match": {
      "all_of": [
        {"protocols": ["udp"]},
        {"any_of": [{"dst_ports": [53]}, {"dst_ports": [123]}]},
        {"not": {"src_cidrs": ["198.51.100.0/24"]}}
      ]
    }

198.51.100.0/24 e apenas rede reservada de documentacao, nao sua rede.
Todas as regras sao limitadas aos dois blocos reais protegidos.

O motor de filtros original suporta outros campos (SYN/ACK, TTL,
ICMP detalhado, NAT, next-hop, HTTP/PHP); a F3 baseada no MariaDB agregado
NAO aceita esses campos ainda: exige NetFlow bruto ou logs L7.

## Operacao

Todos os tres minimos (PPS, Mbps, fontes distintas) devem ser atingidos
em dois minutos consecutivos. Janela e examinada com atraso de quatro
minutos por causa de exportacao NetFlow. ifIndex entrada e saida sao separados,
nao somados; contagens do nfdump ja consideram sampler 1:2048.

    sudo systemctl is-active orbymon-ddos-huawei.timer
    sudo journalctl -u orbymon-ddos-huawei.service -n 30 --no-pager
    sudo mariadb orbymon -e "SELECT * FROM orby_ddos_checks"
    sudo mariadb orbymon -e "SELECT event_time,rule_name,dst_ip,dst_port,pps,mbps,unique_sources FROM orby_alerts WHERE rule_name LIKE 'OrbyMon F3:%' ORDER BY event_time DESC LIMIT 25"

Dashboard: "OrbyMon | Fase 3 - Sinais DDoS passivos", pasta OrbyMon.

Para parar SOMENTE detector:
    sudo systemctl disable --now orbymon-ddos-huawei.timer

## Limitacoes de seguranca e confiabilidade

- Nenhum bloqueio ou alteracao de roteamento.
- Limiares inicialmente NAO calibrados; comparar taxas com SNMP.
- Bucket igual ao minuto final do fluxo, sem redistribuir trafego entre minutos.
- PPS, Mbps e contagem de origens estimados a partir de NetFlow amostrado.
- DDoS curto, volume baixo ou poucas origens podem nao gerar alerta.
- Se volume superar max_query_rows, falha sem produzir resultado parcial.
- Reinicios longos podem perder janelas historicas; catch-up e futuro.
- Ausencia de campos para payload HTTPS, DNS QNAME e TCP flags no rollup.
