# Etapa 2 — reputação e denúncias de abuso

Duas ferramentas para quando chegam e-mails de **ataques originados dentro da rede**:

1. **Investigar** (painel, porta 8443): transforma uma denúncia (IP público + horário + porta) no
   **assinante** (IP privado 100.64.x) usando o log NAT do A10.
2. **Reputação**: verifica de hora em hora se algum IP do provedor entrou em listas públicas de
   bloqueio e, para IP de pool CGNAT, aponta o assinante provável pelos fluxos de saída.

## Instalar

```bash
cd /opt/orbymon && sudo git pull
sudo bash scripts/setup-admin.sh        # atualiza o painel (paginas novas)
sudo bash scripts/setup-reputation.sh   # tabelas, timer, primeira verificacao e dashboard
```

## Investigar uma denúncia

Abra **Investigar** e cole o e-mail inteiro, ou preencha os campos:

| Campo | Por quê |
|---|---|
| IP denunciado | IP público do pool (ou dedicado) citado na denúncia |
| Data e hora + **fuso** | o fuso da denúncia; `+0100`, `Z`, `UTC` no texto já são considerados |
| **Porta de origem** | com ela o resultado é exato: no CGNAT ~32 assinantes dividem cada IP público |
| Porta atacada | 22 (SSH), 25 (SMTP)... restringe ao protocolo certo |

Resultado:

- **confiança alta**: o log NAT mostra um único assinante com aquela porta pública naquele instante;
- **média**: a porta foi reutilizada perto do horário (confira o fuso) ou só os fluxos apontam alguém;
- **baixa**: sem porta, a lista de todos que usaram o IP no horário.

Só com o IP (sem horário) a página mostra o **histórico de 7 dias**: ataques, listas, portas de saída
e, para pool, os assinantes atrás do IP. Use para atender o cliente ou para confirmar suspeita.

Formatos reconhecidos no e-mail: logs do fail2ban/sshd (`from IP port N`), iptables (`SRC= SPT= DPT=`),
Apache (`[30/Oct/2026:14:56:10 +0100]`), X-ARF (`Source:`/`Source-Port:`), ISO 8601, `30/10/2026 14:05`.

Pelo terminal:

```bash
sudo -u orbymon env $(grep -v '^#' /etc/orbymon/pipeline.env | xargs) PYTHONPATH=/opt/orbymon/src \
  /opt/orbymon/.venv/bin/python -m fmn_filters.abuse_lookup \
  --ip 45.238.170.70 --time "2026-10-30 14:05:00" --tz America/Sao_Paulo --port 51234 --remote-port 22
# ou: --email denuncia.txt --tz UTC
```

### Limites

- O log NAT fica **15 dias** (`retention.env`). Denúncias mais antigas não têm como ser resolvidas
  pelo OrbyMon. O **Marco Civil da Internet (Lei 12.965/2014, art. 13)** obriga o provedor de conexão a
  guardar registros de conexão por **1 ano**; com CGNAT isso inclui IP público + **porta** + horário.
  Use `ORBYMON_ARCHIVE_CMD` em `/etc/orbymon/retention-archive.conf` para enviar os logs NAT a um
  armazenamento antes de apagar (consulte o jurídico sobre a sua obrigação).
- Fluxos (NetFlow 1:2048) ficam 2 dias e não veem ataques pequenos (poucas tentativas de senha). O log
  NAT do A10 não é amostrado: ele é a prova.
- O resultado é o IP privado do assinante. O login PPPoE/cliente vem do RADIUS/BRAS para aquele IP e
  horário.

## Reputação

Fontes (de hora em hora, pelo GitHub do projeto FireHOL e do IPsum): blocklist.de (SSH, e-mail, IMAP,
web, login web, bots, FTP, SIP, persistentes), BruteForceBlocker, CINS Army, GreenSnow, Emerging Threats,
DShield, Spamhaus DROP, FireHOL níveis 1–3 e abusers 30d, Sblam, StopForumSpam, BotScout, Project Honey
Pot, blocklist.net.ua e IPsum (quantas listas citam o IP).

A cada 6 h (ajustável): DNSBLs **Spamhaus ZEN, SpamCop, Barracuda, UCEPROTECT-1, PSBL** para cada IPv4
dos blocos, e **AbuseIPDB** se você cadastrar uma chave gratuita no painel. A Spamhaus só responde a
resolvedores DNS próprios (não 8.8.8.8/1.1.1.1); o setup avisa se for o caso. PBL (faixa residencial)
é ignorada: não é abuso.

Para cada IP listado:

- **pool CGNAT**: o OrbyMon procura nos fluxos de saída das últimas 48 h quem falou com as portas
  típicas da lista (SSH → 22, e-mail → 25/465/587, web → 80/443...) e quem tem ataque originado
  detectado. Esse é o **provável responsável**;
- **IP dedicado**: o responsável é o próprio cliente; aparecem as portas de saída usadas.

Avisos no Telegram (mesmo grupo dos ataques): quando um IP entra em lista (com o provável responsável) e
quando sai de todas. Falha de uma fonte nunca remove listagens antigas.

Dashboard **OrbyMon | Reputação e ataques originados**: IPs listados, quem mais originou ataques,
ataques por hora/tipo, **saída suspeita** (clientes falando com dezenas de destinos em portas de SSH,
Telnet, SMTP, SMB, RDP, SQL, SIP e Winbox), histórico e situação das fontes.

### Registro recomendado (gratuito)

- **Shadowserver** (https://www.shadowserver.org/what-we-do/network-reporting/): relatórios diários
  por ASN de dispositivos infectados, abertos ou comprometidos — a fonte que mais gera denúncias.
- **Spamhaus** / **AbuseIPDB**: consultas ilimitadas por DNS próprio / chave gratuita.
- Contato de abuso correto no **registro.br/LACNIC** (`abuse-c`), para os e-mails chegarem a quem age.
