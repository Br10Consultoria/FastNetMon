# Painel web de administração

Página própria do OrbyMon para configurar cada instalação (provedor, ASNs, blocos, pools CGNAT,
bordas, regras, Telegram e retenção) sem editar arquivos no terminal. Roda em **HTTPS na porta
8443** (configurável), separada do Grafana (3000), com **usuário + senha + 2FA (TOTP)** obrigatório.

## Instalação

```bash
cd /opt/orbymon && sudo git pull
sudo bash scripts/setup-admin.sh                 # porta 8443; pede o nome do 1º usuário e a senha
sudo bash scripts/setup-admin.sh --port 9443     # outra porta
sudo bash scripts/setup-admin.sh --bind 10.0.0.5 # escutar só no IP de gerência
```

Abra `https://IP-DO-SERVIDOR:8443`. O certificado é autoassinado: confira a impressão digital
SHA-256 que o script mostra (ou troque `cert.pem`/`key.pem` em `/etc/orbymon/admin-tls/` por um
certificado seu e rode `systemctl restart orbymon-admin`).

No primeiro acesso o usuário cadastra o 2FA lendo o QR code com Google Authenticator, Microsoft
Authenticator, Authy, 1Password etc. Usuários criados pelo painel recebem senha provisória e trocam
no primeiro acesso.

Libere a porta somente para a rede de gerência:

```bash
sudo ufw allow from 10.0.0.0/24 to any port 8443 proto tcp
```

## Páginas

| Página | O que altera | Quando vale |
|---|---|---|
| Status | — (serviços, últimos minutos recebidos, eventos recentes, disco) | — |
| Rede | nome do provedor, ASNs, blocos IPv4/IPv6, rede privada pré-NAT, infraestrutura, IPs do A10, pools CGNAT | rollup/detector no próximo minuto; receptor NAT em até 60 s, sem reiniciar |
| Bordas | ifIndex de borda (observação) e nomes das interfaces | próximo minuto; nomes aparecem no Grafana |
| Regras | regras ligadas/desligadas, severidade, minutos seguidos, limites por escopo; aplicar a proposta de calibração (só pps e Mbps) | próximo minuto |
| Telegram | token (mascarado), chats, severidade mínima, lembrete, encerramento, URL do Grafana, nome do site; teste e descoberta de chats | próxima verificação (30 s) |
| Retenção | dias de logs NAT e de arquivos nfcapd | próxima hora |
| Usuários | criar, desativar, refazer 2FA, excluir | imediato |
| Auditoria | quem alterou o quê, de qual IP, com valores antes/depois | — |

Toda gravação valida a configuração inteira (como os serviços fazem) antes de escrever; se algo
estiver errado, nada muda. Cada alteração guarda um backup em `/var/lib/orbymon/admin/backups/`.

## Segurança

- Senhas com scrypt (mínimo 12 caracteres); 2FA TOTP (RFC 6238) obrigatório, com bloqueio de
  reuso do mesmo código; bloqueio por 15 min após 5 erros no usuário ou 20 no IP.
- Cookie `Secure`/`HttpOnly`/`SameSite=Strict`, token CSRF em todo formulário, sessão expira com
  30 min sem uso, CSP sem JavaScript, HSTS, `X-Frame-Options: DENY`.
- Serviço `orbymon-admin` com usuário próprio sem shell, sem capabilities, sistema de arquivos
  somente leitura exceto `/etc/orbymon/managed` e `/var/lib/orbymon/admin`.
- Usuário MariaDB `orbymon_admin`: leitura do banco; escrita só nas tabelas do painel e nos nomes
  de interface; a auditoria só aceita inclusão.
- Os arquivos editáveis ficam em `/etc/orbymon/managed/` com links nos caminhos de sempre
  (`/etc/orbymon/bidir.json`, `cgnat-profiles.json`, `telegram.env`, `retention.env`). Eles são
  lidos **como dados** pelos serviços — nunca carregados como ambiente nem executados — para que o
  painel não consiga influenciar processos de outros usuários (ex.: `LD_PRELOAD`).
- O comando de envio à nuvem roda como root e por isso **não** é editável pelo painel: fica em
  `/etc/orbymon/retention-archive.conf` (dono root, modo 0600), ex.:
  `ORBYMON_ARCHIVE_CMD=rclone copy {} remoto:orbymon/`.
- O painel não lê `pipeline.env` nem as credenciais do pipeline (não pertence ao grupo `orbymon`).

## Terminal (recuperação)

```bash
ADM="sudo -u orbymon-admin env $(sudo sed -e "s/'//g" -e '/^#/d' /etc/orbymon/admin.env | xargs) PYTHONPATH=/opt/orbymon/src /opt/orbymon/.venv/bin/python -m fmn_filters.admin.cli"
$ADM list
$ADM create-user maria
$ADM set-password maria      # troca obrigatória no próximo acesso
$ADM reset-2fa maria         # perdeu o celular: novo QR code no próximo acesso
$ADM unlock maria            # limpa o bloqueio por tentativas
journalctl -u orbymon-admin -n 50 --no-pager
```

Para desfazer uma alteração, copie o backup desejado de `/var/lib/orbymon/admin/backups/` sobre o
arquivo em `/etc/orbymon/managed/`.
