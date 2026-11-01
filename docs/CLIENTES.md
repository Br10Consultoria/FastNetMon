# Clientes e RADIUS

Identifica quem está por trás de um IP nos avisos do Telegram (detector e alarmes por filtro) e na página
**Investigar**:

- **Clientes dedicados**: cadastro no painel (página **Clientes**) com nome, código no sistema de gestão,
  contato e IPs/prefixos. O prefixo mais específico vence.
- **Assinantes PPPoE** (inclusive os 100.64.x do CGNAT): login, MAC e NAS consultados no **RADIUS** no horário do
  evento.

```bash
sudo bash scripts/setup-customers.sh     # tabelas, permissões e /etc/orbymon/radius.env (editável no painel)
```

## RADIUS

Somente leitura, na tabela de contabilidade padrão do FreeRADIUS (`radacct`) em MySQL/MariaDB — usada por IXC,
MK-Auth, SGP e outros. Colunas: `username`, `framedipaddress`, `acctstarttime`, `acctstoptime`,
`callingstationid`, `nasipaddress`.

No servidor do RADIUS, crie um usuário só com leitura e libere o acesso a partir do OrbyMon:

```sql
CREATE USER 'orbymon_ro'@'IP_DO_ORBYMON' IDENTIFIED BY 'senha-forte';
GRANT SELECT ON radius.radacct TO 'orbymon_ro'@'IP_DO_ORBYMON';
```

Depois preencha servidor, banco, tabela, usuário, senha e o **fuso das datas gravadas no radacct** na página
Clientes e use **Consultar** para conferir um IP e horário. A senha nunca volta para a página (campo vazio = manter).

- A consulta usa o índice de `framedipaddress` do esquema padrão; tempo limite de 3 s para conectar e 5 s para ler.
- Se o RADIUS estiver fora, os avisos saem normalmente, só sem o login.
- O login aparece como “Identificação: login joao123 · MAC …” no aviso, ao lado do assinante no top dos alarmes por
  filtro e na tabela de assinantes da investigação (e no texto pronto para resposta da denúncia).
