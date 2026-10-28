# OrbyMon — piloto Huawei NE8000 primeiro

**Fase atual: somente Huawei NetEngine 8000.** Este guia é a etapa 1 do [manual geral](INSTALL_PILOT.md). O MikroTik **não deve ser ativado nesta fase**. A coleta de fluxos funciona mesmo sem ataque DDoS. Todo o piloto é somente leitura da telemetria; sem RTBH/FlowSpec, sem mudanças de rota, sem bloqueio automático.

## 1. Preparar o Ubuntu Server 24.04 LTS

VM inicial recomendada (não dimensionamento definitivo): 4 vCPU, 8 GB RAM e SSD de 100 GB. O tráfego exportado é telemetria, não todo o tráfego de clientes. O uso de disco depende de fluxos/s e da rotação.

```bash
sudo apt update && sudo apt install -y git python3
cd /opt
sudo git clone https://github.com/Br10Consultoria/FastNetMon.git orbymon
cd /opt/orbymon
bash scripts/test-incidents.sh
sudo bash scripts/bootstrap-pilot.sh
```

O bootstrap cria o coletor Huawei (2056) **e também prepara o futuro perfil MikroTik (2057), porém nenhum deles é iniciado automaticamente.**

Antes de iniciar, ajuste o firewall da VM e da rede de forma a permitir UDP 2056 **somente do IP exportador definido no Huawei**. Não habilite UFW sem confirmar que SSH administrativo está permitido. O UDP de exportação NetFlow não é autenticado.

```bash
sudo systemctl enable --now orbymon-nfcapd@huawei.service
sudo systemctl --no-pager status orbymon-nfcapd@huawei.service
sudo ss -lunp | grep ':2056'
sudo systemctl is-enabled orbymon-nfcapd@mikrotik.service
```

**Não execute** `systemctl enable --now orbymon-nfcapd@mikrotik.service` nesta fase.

## 2. Diagnóstico sem alterações no Huawei

**Somente comandos de leitura** no Huawei; enviar as saídas removendo IPs de gestão e credenciais:

```text
display version
display current-configuration | include netstream
display interface brief
display ip routing-table IP_DO_SERVIDOR_ORBYMON
```

Registrar: interface física/subinterface por onde queremos observar tráfego, VLAN se aplicável, origem da exportação, VRF/VPN-instance se usada, NetStream já configurado, formato (v9/IPFIX), sampling e direção. Escolher uma única interface de trânsito inicialmente, preferencialmente apenas inbound, para não duplicar fluxos nas duas direções. **Não aplicar configurações de NetStream genéricas sem confirmar sintaxe do VRP/placa e situação existente.**

NetStream dos NetEngine pode usar exportação NetFlow v9 ou IPFIX; timeouts, slot e sampling dependem do VRP e do módulo. Antes da mudança, gerar comparação de tráfego e CPU e salvar backup da configuração. Não alterar diretamente interfaces críticas de PPPoE/CGNAT sem avaliar impacto no equipamento.

## 3. Recepção no servidor

Depois de configurar o Huawei para exportar à porta UDP 2056:

```bash
sudo tcpdump -ni any -c 20 'udp port 2056'
sudo journalctl -u orbymon-nfcapd@huawei.service -n 60 --no-pager
sudo ls -lh /var/lib/orbymon/flows/huawei/
cd /opt/orbymon
sudo bash scripts/inspect-pilot.sh huawei
```

Se não aparecer nada no primeiro instante: o roteador só exporta fluxos após atingirem tempo ativo/inativo e o `nfcapd` grava arquivos **rotacionados** (atualmente a cada 30 s). Confirmar acesso, origem UDP, firewall, rotas e timestamps. Arquivo vazio não comprova recepção.

Para examinar um arquivo rotacionado específico:

```bash
sudo nfdump -r /var/lib/orbymon/flows/huawei/nfcapd.AAAAmmddHHMMss -o json
```

Não compartilhar dados de IP de clientes publicamente.

## 4. O que medir antes de habilitar Mikrotik

1. Tráfego **normal**: IPs mais frequentes, portas, protocolos, distribuição por destino, PPS, bytes e fluxos.
2. Amostragem: se o exportador informa sampling corretamente e se `nfdump` já escalou os contadores. **Não multiplicar taxa duas vezes.**
3. Capacidade e carga do NE8000: CPU, forwarding, número de fluxos, uso de banda no link, perdas.
4. Diferença de totais com SNMP/interfaces (NetFlow não é contador exato).
5. Campos disponíveis no fluxo real: ASN, interface ingress, BGP next-hop, TCP flags e NAT. Não assumir que todos estarão presentes.
6. Disco da VM: `df -h /var/lib/orbymon` e `sudo du -sh /var/lib/orbymon/flows/huawei/`. **Não existe limpeza automática no bootstrap**. Definir retenção após medir o volume e antes de deixar serviço sem supervisão.
7. Alertas OrbyMon apenas após substituir prefixos de documentação em `rules/example-rules.json` por endereços reais de teste, revisando exceções.

**O Grafana contínuo ainda requer um pipeline de agregação idempotente**: os coletores gravam todos os fluxos e o `nfdump` permite ver tráfego normal mesmo sem ataque, mas a nova camada de incidentes e as métricas MariaDB ainda não estão totalmente integradas ao coletor contínuo.

## 5. Próxima fase

Apenas após verificar o Huawei e calibrar os limiares, habilitaremos o MikroTik UDP 2057, com cuidado com FastPath/hardware offload e possível duplicidade dos mesmos fluxos atravessando dois equipamentos.
