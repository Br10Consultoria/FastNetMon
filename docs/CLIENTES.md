# Clientes e identificação do assinante

Identifica quem está por trás de um IP nos avisos do Telegram (detector e alarmes por filtro) e na página
**Investigar**:

- **Clientes dedicados**: cadastro no painel (página **Clientes**) com nome, código no ERP, contato e IPs/prefixos.
  O prefixo mais específico vence.
- **Assinantes PPPoE** (inclusive os 100.64.x do CGNAT): **login** (e MAC) de quem tinha o IP **no horário** do
  evento ou da denúncia. Nunca a senha.

```bash
sudo bash scripts/setup-customers.sh     # tabelas, permissões, driver PostgreSQL e /etc/orbymon/radius.env
```

O caminho de uma denúncia: IP público + porta + horário → log NAT do A10 → 100.64.x.x → **login no ERP**.

## Fontes de identificação (qualquer ERP)

Escolha no painel. Todas são somente leitura; se a fonte estiver fora do ar, os avisos saem normalmente, só sem o
login. Use **Testar sem salvar** com um IP e horário conhecidos antes de salvar.

| Fonte | Quando usar |
|---|---|
| **API HTTP/JSON do ERP** (recomendado) | IXC, SGP, MK-Auth, sistema próprio… Só precisa de um token de API com permissão de consulta; o banco do ERP não fica exposto. |
| radacct do FreeRADIUS (MySQL/MariaDB ou PostgreSQL) | Acesso direto à tabela de contabilidade padrão (`username`, `framedipaddress`, `acctstarttime`, `acctstoptime`, `callingstationid`). |
| Consulta SQL própria (MySQL/MariaDB ou PostgreSQL) | O ERP guarda as sessões em outra tabela: escreva o `SELECT` com `{ip}` e `{quando}` devolvendo login, início, fim[, MAC[, NAS]]. |

**Importante:** a fonte precisa responder o **histórico** de conexões do IP (quem estava com ele num horário), não só
quem está conectado agora — senão funciona para os avisos em tempo real, mas não para denúncias que chegam dias depois.

### API HTTP/JSON

- **URL** e, para POST, **corpo JSON** com marcadores: `{ip}`, `{quando}` (data e hora local no fuso escolhido),
  `{data}`, `{quando_iso}` (UTC), `{epoch}`. Na URL os valores são codificados; no corpo, escapados para JSON.
- **Cabeçalhos de autenticação**, um por linha (`Authorization: Bearer …`, `Authorization: Basic …`, ou o que o ERP
  pedir). Guardados só para escrita: nunca voltam para a página nem para a auditoria.
- **Mapeamento da resposta**: caminho da lista (ex.: `registros`; vazio = raiz ou objeto único) e dos campos de
  login, início, fim e MAC (aninhados com ponto: `dados.cliente.login`; índice com número: `itens.0`).
- Datas aceitas: `2026-11-01 08:30:00`, ISO com ou sem fuso, `01/11/2026 08:30`, epoch em segundos ou milissegundos;
  sem fuso, vale o fuso configurado. Sessões fora do horário pedido são descartadas; a mais recente vence.
- O teste mostra a **resposta crua** (até 4000 caracteres) para conferir os nomes dos campos.
- Opção para aceitar certificado autoassinado do ERP (deixe desligada se o certificado for válido).

### Banco de dados

Crie um usuário só com leitura e libere o acesso a partir do OrbyMon, por exemplo (MySQL/MariaDB):

```sql
CREATE USER 'orbymon_ro'@'IP_DO_ORBYMON' IDENTIFIED BY 'senha-forte';
GRANT SELECT ON radius.radacct TO 'orbymon_ro'@'IP_DO_ORBYMON';
```

As consultas rodam em transação somente leitura e são desfeitas ao final; tempo limite de 3–5 s.
