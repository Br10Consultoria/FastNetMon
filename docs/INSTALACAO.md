# Instalação automática (servidor novo)

Um comando instala o OrbyFlow completo num **Ubuntu 22.04 ou 24.04** limpo: MariaDB, Python, coletor NetFlow,
Grafana, detecção, painel web, reputação, alarmes, saúde, backup, portas do CGNAT e ClickHouse.

```bash
sudo apt update && sudo apt install -y git
cd /opt && sudo git clone https://github.com/Br10Consultoria/FastNetMon.git orbymon
cd /opt/orbymon
sudo bash scripts/install.sh --public-host IP_OU_DOMINIO_DO_SERVIDOR --a10-ip IP_DO_A10
```

Leva de 10 a 20 minutos. No fim aparece a lista de serviços (todos `active`) e o que falta configurar.

## Opções

| Opção | O que faz |
|---|---|
| `--public-host H` | IP ou domínio usado no certificado HTTPS do Grafana (padrão: primeiro IP da máquina) |
| `--admin-user NOME` | primeiro usuário do painel (padrão `admin`) |
| `--a10-ip IP` | o receptor do log NAT escuta direto na TCP/5514 e aceita só esse IP |
| `--mikrotik` | liga também o coletor NetFlow do MikroTik (UDP/2057) |
| `--sem-clickhouse` | não instala o ClickHouse (dashboards e detalhe ficam no MariaDB) |
| `--sem-grafana` | não instala o Grafana |
| `--sem-geoip` | não pergunta a licença MaxMind |
| `--nao-perguntar` | sem perguntas (pula o GeoIP se a licença não estiver em `/etc/GeoIP.conf`) |

Requisitos: 4 GB de RAM (recomendado 16 GB), 20 GB livres, repositório em `/opt/orbymon`, acesso à internet
(pacotes do Ubuntu, Grafana, ClickHouse e PyPI).

## O que ele faz, em ordem

1. Pacotes do sistema (nfdump, MariaDB, Python, ferramentas de rede).
2. Usuário `orbymon`, diretórios e coletor NetFlow do Huawei (UDP/2056).
3. Ambiente Python em `/opt/orbymon/.venv`.
4. Banco `orbymon`, usuário do pipeline com senha gerada (`/etc/orbymon/pipeline.env`, 0640).
5. Ajuste do MariaDB à RAM.
6. Grafana com HTTPS (porta 3000) e dashboards.
7. Pares de IP, nomes de interface e GeoIP (pede a licença MaxMind; Enter pula).
8. Perfil CGNAT e detecção bidirecional; receptor do log NAT do A10.
9. Painel web (porta 8443) e o primeiro usuário, com **senha gerada** em `/root/orbyflow-painel-acesso.txt`
   (troca obrigatória e cadastro do 2FA no primeiro acesso).
10. Backup diário cifrado (`/etc/orbymon/backup.key`: guarde uma cópia fora do servidor).
11. Reputação, alarmes por filtro (modelos desligados), clientes, linha de base, mitigação **em simulação** e saúde.
12. Tabelas agregadas e uso de portas do CGNAT.
13. ClickHouse (escolhe a versão certa para a CPU) e dashboards de tráfego nele.
14. Verificação dos serviços e resumo.

O log completo fica em `/var/log/orbyflow-install.log`. Se uma etapa falhar, o instalador diz qual; corrija e
rode de novo: as etapas prontas são preservadas (senhas, configuração e dados não são recriados).

## Depois da instalação

1. **Painel → Rede:** blocos do provedor, pools CGNAT, rede privada e ASN. A instalação vem com um exemplo:
   ajuste antes de confiar nos alertas.
2. **Roteador:** exportar NetStream/NetFlow para o servidor na UDP/2056 (MikroTik: 2057).
3. **A10:** log NAT para o servidor na TCP/5514.
4. **Painel → Telegram** e **E-mail/Webhook:** avisos.
5. **Painel → Clientes:** integração com o ERP. **Mitigação:** BGP (fica em simulação até você validar).
6. **Firewall** (o instalador não altera): 2056/udp só do roteador, 5514/tcp só do A10, 8443 e 3000/tcp só da
   rede de gerência.
7. Depois de 1 dia com tráfego: **Regras → aplicar a proposta de calibração**; com 3 dias, ligar o limite
   dinâmico em **Base**; ligar os alarmes por filtro com `sudo bash scripts/test-alarms.sh 60` como guia.

## Atualizar

```bash
cd /opt/orbymon && sudo git pull && sudo bash scripts/install.sh --public-host IP_OU_DOMINIO
```
Rodar o instalador de novo aplica as novidades sem perder configuração.
