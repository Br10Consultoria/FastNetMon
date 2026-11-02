# ClickHouse (fluxos com retenção longa)

O MariaDB guarda cadastro, eventos de ataque, alarmes, configuração e o detalhado de fluxos dos últimos ~2 dias.
O **ClickHouse** guarda as mesmas linhas de fluxo por minuto (origem, destino, portas, protocolo, IP privado do
assinante) por **30 dias** (configurável), em formato colunar: consultar um IP num dia inteiro leva segundos e
usa pouca memória.

Quem usa:

- **Painel → Ataques → detalhe**: conversas origem → destino, portas, minuto a minuto. Usa o ClickHouse quando ele
  cobre o período; senão cai no MariaDB (2 dias).
- **Painel → Ataques, filtro "IP remoto"**: com o ClickHouse, procura o IP remoto em **todos** os fluxos (sem ele,
  só entre os principais IPs de cada ataque).

## Instalação

```bash
cd /opt/orbymon && sudo git pull
sudo bash scripts/setup-clickhouse.sh                 # 30 dias, até 25% da RAM
sudo bash scripts/setup-clickhouse.sh --ttl-days 60   # mudar a retenção depois (não reescreve o que já existe)
sudo bash scripts/setup-clickhouse.sh --status        # linhas, período, tamanho e lotes pendentes
```

O script:

1. instala o `clickhouse-server` do repositório oficial (canal LTS), se faltar;
2. escuta **só em 127.0.0.1**, limita a memória (`--memory-ratio`, padrão 0.25) e desliga logs internos que só
   gastam disco;
3. cria três usuários locais — `orbyflow_admin` (só o script), `orbyflow_writer` (rollup, gravação) e
   `orbyflow_reader` (painel, só leitura, 30 s e 2 GB por consulta). O usuário `default` fica bloqueado;
4. guarda as senhas em `/etc/orbymon/clickhouse-admin.env` (0600 root), `clickhouse.env` (0640 root:orbymon) e
   `clickhouse-reader.env` (0640 root:orbymon-admin). O systemd lê esses arquivos como dados; nunca são executados;
5. liga o rollup e o painel por *drop-ins* do systemd e dá ao painel leitura das bases GeoLite2 (ASN/país).

Não há cópia do histórico: o ClickHouse começa vazio e, depois de 2 dias, já cobre tudo o que o MariaDB tinha.
Enquanto isso, o painel usa o MariaDB para os períodos mais antigos.

## Segurança e falhas

- O rollup grava primeiro no MariaDB (como antes) e depois no ClickHouse. Se o ClickHouse estiver fora, o lote vai
  para `/var/lib/orbymon/clickhouse-spool` e é reenviado na próxima execução, com o mesmo token — o ClickHouse
  descarta repetições. O spool é limitado a 2 GB (descarta os mais antigos).
- A página **Saúde** avisa quando há lotes parados no spool (ClickHouse fora há mais de 3 min).
- Consultas do painel usam parâmetros do próprio ClickHouse (`{nome:Tipo}`), sem montar SQL com texto digitado.

## Memória e disco

Com 16 GB de RAM: MariaDB ~6,5 GB de cache, ClickHouse até ~4 GB, resto para o sistema, Grafana e o receptor NAT.
O ClickHouse comprime bem esse tipo de dado (tipicamente 5–10× menos que o MariaDB para as mesmas linhas). Confira o
tamanho real com `--status` depois de alguns dias.

## Remover

```bash
sudo rm /etc/systemd/system/orbymon-flow-rollup-huawei.service.d/clickhouse.conf \
        /etc/systemd/system/orbymon-admin.service.d/clickhouse.conf
sudo systemctl daemon-reload && sudo systemctl restart orbymon-admin
sudo systemctl disable --now clickhouse-server
```
