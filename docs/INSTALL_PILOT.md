# OrbyMon — instalação de piloto NetFlow/IPFIX em servidor novo

**Status em 28/10/2026:** coleta de tráfego normal/atípico com `nfcapd` e consulta com `nfdump` pronta para **piloto passivo** em Ubuntu 24.04 LTS (recomendado) ou Debian 12/13 (validar versões). O motor de alertas OrbyMon é uma prova de conceito; correlação de incidentes e dashboards não estão totalmente integrados ao coletor em modo contínuo. Não há bloqueios automáticos.

## 1. Servidor e dimensionamento inicial

- Ubuntu Server 24.04 LTS mínimo, ou Debian com `nfdump` 1.7.x; acesso SSH administrativo.
- **Ponto de partida para piloto leve:** 4 vCPU, 8 GB RAM e SSD de 100 GB ou maior. Não é dimensionamento validado: armazenamento depende de *flows/s*, amostragem, timeout de exportação, quantidade de interfaces e retenção. Monitore CPU, RAM, disco e perdas.
- IP do servidor alcançável pelos dois exportadores, NTP/UTC preferencialmente ativo.
- **Portas de recepção:** Huawei: UDP **2056**, MikroTik: UDP **2057**. Isso evita misturar os fluxos dos fabricantes e torna mais fácil validar os formatos.
- Se FastNetMon Community também for utilizado, mantenha serviço/configuração separados e não reutilize uma porta já ocupada.

## 2. Instalar e preparar a coleta

```bash
sudo apt update
sudo apt install -y git python3
sudo mkdir -p /opt
cd /opt
sudo git clone https://github.com/Br10Consultoria/FastNetMon.git orbymon
cd /opt/orbymon

bash scripts/test-incidents.sh           # testes simulados (sem roteador)
sudo bash scripts/bootstrap-pilot.sh     # instala nfdump/tcpdump e prepara systemd
```

O bootstrap cria o usuário restrito `orbymon`, dois diretórios de coleta, dois arquivos de configuração e o serviço template do systemd. **Não inicia nada, não mexe no firewall, nem instala/modifica FastNetMon Community.** É seguro revisar a configuração antes de ativar os serviços.

Cheque as portas nos arquivos:

```bash
sudo cat /etc/orbymon/huawei.env
sudo cat /etc/orbymon/mikrotik.env
```

Devem constar `ORBYMON_PORT=2056` e `ORBYMON_PORT=2057`. Se os valores já existiam, o bootstrap os preservou.

### Segurança da rede

Restrinja UDP 2056 exclusivamente ao **IP real de origem** do Huawei e UDP 2057 exclusivamente ao IP de origem do MikroTik no firewall de borda e no host. Se já utiliza UFW, crie regras específicas:

```bash
sudo ufw allow from IP_ORIGEM_HUAWEI to any port 2056 proto udp
sudo ufw allow from IP_ORIGEM_MIKROTIK to any port 2057 proto udp
```

**Não habilite o UFW às cegas nem substitua regras existentes**; proteja primeiro o acesso SSH. Para locais diferentes, prefira VPN/rede de gerenciamento e evite publicar o coletor aberto na Internet. O `nfcapd` não autentica exportadores.

## 3. Iniciar os dois coletores

```bash
sudo systemctl enable --now orbymon-nfcapd@huawei.service
sudo systemctl enable --now orbymon-nfcapd@mikrotik.service

sudo systemctl --no-pager status orbymon-nfcapd@huawei.service
sudo systemctl --no-pager status orbymon-nfcapd@mikrotik.service

sudo ss -lunp | grep -E ':(2056|2057) '
```

Cada processo grava arquivos **a cada 30 segundos** (rotação), em:

- `/var/lib/orbymon/flows/huawei/nfcapd.YYYYMMDDhhmmss`
- `/var/lib/orbymon/flows/mikrotik/nfcapd.YYYYMMDDhhmmss`

Sem exportação, o coletor pode girar arquivos vazios; isso não comprova recebimento. O diretório só é acessível ao usuário/grupo `orbymon` e à administração do sistema.

## 4. Exportar do MikroTik RouterOS v7

**Primeiro observe o estado atual, sem sobrescrever o que estiver configurado:**

```routeros
/ip traffic-flow print detail
/ip traffic-flow target print detail
```

Depois, para um piloto com interface escolhida e medição do impacto na CPU (substitua os valores e confirme as opções do equipamento):

```routeros
/ip traffic-flow set enabled=yes interfaces=ether1 active-flow-timeout=1m inactive-flow-timeout=15s
/ip traffic-flow target add dst-address=IP_SERVIDOR_ORBYMON port=2057 version=9
/ip traffic-flow monitor duration=3
```

Não habilite indiscriminadamente `interfaces=all` em roteador carregado. Revise targets preexistentes antes de adicionar outro. O Traffic Flow do MikroTik **não observa o tráfego HW-offloaded**; se o cliente ou serviço utiliza hardware offload, a contagem pode não representar o tráfego total. Consulte o [manual oficial MikroTik](https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/traffic-flow/).

## 5. Exportar do Huawei NetEngine 8000

**Não aplique uma configuração genérica às cegas no NE8000**. NetStream depende do VRP, licença, interfaces/subinterfaces, modo de amostragem e direção de exportação. Comece com comandos apenas de consulta:

```text
display version
display current-configuration | include netstream
display interface brief
```

Confirme se NetStream já está ativo e exportando para outro coletor; não o desligue. Depois escolha uma **única interface/subinterface de trânsito para o piloto**, com sampling moderado e NetFlow v9/IPFIX compatível com seu VRP. Utilize **UDP 2056** no destino. Verifique o impacto no forwarding/control-plane e compare contadores com SNMP/rotas de tráfego, lembrando que amostragem requer interpretação adequada. Precisamos dos trechos de `display current-configuration` e identificação da interface para gerar comandos exatos para seu NE8000 (V800R021C10).

Não configure BGP, FlowSpec ou RTBH nesta fase.

## 6. Verificar recepção, mesmo sem ataque

```bash
sudo tcpdump -ni any -c 15 'udp port 2056 or udp port 2057'
sudo journalctl -u orbymon-nfcapd@huawei.service -n 40 --no-pager
sudo journalctl -u orbymon-nfcapd@mikrotik.service -n 40 --no-pager
sudo ls -lh /var/lib/orbymon/flows/huawei/
sudo ls -lh /var/lib/orbymon/flows/mikrotik/
```

Após 30–90 segundos, com tráfego real roteado pelos equipamentos:

```bash
cd /opt/orbymon
sudo bash scripts/inspect-pilot.sh huawei
sudo bash scripts/inspect-pilot.sh mikrotik
```

Isso mostra **independentemente de haver ataques**: resumo do volume, IPs de origem/destino, portas mais utilizadas e protocolos. A consulta lê o último arquivo *rotacionado* de cada origem. Para investigação detalhada, utilize `sudo nfdump -r /CAMINHO/DO/ARQUIVO -o json`.

**Atenção:** se os dados vêm de Huawei e MikroTik e representam as mesmas conexões em pontos diferentes da rede, **não some os dois valores** como se fossem tráfego independente.

## 7. Detecção OrbyMon (opcional após validar a coleta)

As regras atuais no repositório trazem prefixos **reservados para documentação**, não os prefixos do provedor. Antes de usar em produção, copie e personalize as regras e exceções:

```bash
cd /opt/orbymon
sudo cp rules/example-rules.json /etc/orbymon/pilot-rules.json
sudo nano /etc/orbymon/pilot-rules.json
PYTHONPATH=src python3 -m fmn_filters --rules /etc/orbymon/pilot-rules.json --validate
```

Para observar os arquivos do Huawei em modo de alerta, **somente após personalizar as regras**, em terminal supervisionado:

```bash
cd /opt/orbymon
sudo -u orbymon env PYTHONPATH=/opt/orbymon/src python3 -m fmn_filters \
  --rules /etc/orbymon/pilot-rules.json \
  --watch-dir /var/lib/orbymon/flows/huawei \
  --state-db /var/lib/orbymon/state/huawei.db \
  --poll-seconds 5
```

`--watch-dir` lê arquivos finalizados; **não detecta pacotes em tempo real**. Usar um banco SQLite de checkpoint por fonte. O watcher apenas emite alertas JSON na saída; não popula automaticamente os painéis MariaDB ou o SQLite de incidentes. A integração contínua ainda está pendente.

## 8. Grafana, geolocalização e ASN

A v0.2 inclui arquivos SQL e um dashboard em `grafana/`, mas o pipeline de **todo o tráfego normal** para MariaDB ainda precisa de processamento contínuo idempotente. O sink atual pode duplicar os totais se um mesmo arquivo for reprocessado. **Não apresente o Grafana como pronto em tempo real nesta fase.** Primeiro confirme os fluxos via `nfdump`; depois habilitaremos a ingestão agregada por fabricante, com checkpoint e retenção. Para ASN/país, configure bases GeoLite2 licenciadas e atualizadas; nem todos os exportadores fornecem os mesmos campos.

## 9. Cuidado com disco e retenção

**O instalador não configura exclusão automática de arquivos brutos.** Enquanto durar o piloto, monitore frequentemente:

```bash
df -h /var/lib/orbymon
sudo du -sh /var/lib/orbymon/flows/*/
sudo find /var/lib/orbymon/flows -type f -name 'nfcapd.[0-9]*' -mtime +2 -print
```

A última linha **apenas lista** arquivos antigos. Defina backup, retenção e política de descarte antes de deixar o serviço ativo por muitos dias. Não apague dados sem revisar a janela de investigação desejada.

## 10. Critérios de aceite do piloto

1. Dois serviços ativos, sem abrir UDP a exportadores desconhecidos.
2. Pacotes UDP chegando nas portas corretas e arquivos gravados sem erros.
3. `nfdump` apresenta pelo menos um IP origem/destino, protocolo e volumes de tráfego legítimo.
4. Verificar se IPs, interfaces e ASN estão presentes nos templates realmente exportados.
5. Comparar Mbps/PPS e amostragem com contadores dos roteadores.
6. Acompanhar CPU, RAM, volume de arquivos e perda de exportação.
7. Somente após validar os pontos anteriores, configurar regra de alerta e avançar para Grafana.

**Nenhuma modificação automática de tráfego, rotas ou BGP está presente nesta implantação.**
