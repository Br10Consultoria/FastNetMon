# OrbyMon - CGNAT A10: pools publicos reais e rede interna

## Topologia informada

Router Huawei NE8000: quatro rotas estaticas para next-hop 10.100.10.10,
que terminam no equipamento A10 (configuracao cgnv6/LSN). O A10 usa
class-list CL_CGN1 -> 100.64.64.0/19 lsn-lid 1, pool-group NAT-Group.

| A10 pool | CIDR publico | max-users-per-ip |
|---|---|---|
| NAT-POOL-08 | 45.238.170.64/26 | 32 |
| NAT-POOL-09 | 45.238.171.64/26 | 32 |
| NAT-POOL-10 | 45.238.170.128/26 | 32 |
| NAT-POOL-11 | 45.238.171.128/26 | 32 |

Total: quatro /26, 256 enderecos do pool, 8192 atribuicoes *teoricas*
(256 x 32), nao usuarios atualmente conectados. O /19 interno tem
8192 enderecos, tambem nao equivale ao numero de assinantes ativos.

Esses pools sao SUBFAIXAS da rede publica protegida 45.238.170.0/23.
O bloco 187.87.201.0/24 continua protegido no detector passivo da F3,
mas NAO e automaticamente classificado como CGNAT.

## Atualizar classificacao local sem perder personalizacoes

    cd /opt/orbymon
    git pull --ff-only origin main
    PYTHONPATH=src python3 -m unittest discover -s tests -q
    sudo bash scripts/setup-cgnat-baseline.sh

O instalador faz backup do perfil JSON existente (se alterar), preenche
somente os 4 pools conhecidos, rede interna /19 e metadados do A10.
Preserva classificacoes existentes dedicado/infraestrutura e parametros
de lookback/limites de linhas. Se encontrar pools preexistentes
divergentes ou conflito com dedicado/infra, ERRA com mensagem de
revisao manual e NAO sobrescreve perfis.
Para ver arquivo configurado:

    sudo python3 -m json.tool /etc/orbymon/cgnat-profiles.json

## Resultado

O relatorio read-only inclui:
- Baseline P95 e pico por IP publico, protocolo, lado (src/dst), ifIndex e
  direcao da exportacao (ja existia).
- Novo baseline P95 e pico por POOL (NAT-POOL-08..11), mantendo
  separacao de direcoes e interfaces. Nao soma o mesmo pacote visto duas vezes.
- Capacidade teorica por pool, sem fingir saber uso real.
- Declaracao de 100.64.64.0/19 como rede interna do A10.
- Dashboard OrbyMon CGNAT atualizado: visoes por POOL e observacoes de rede
  privada quando houver exportacao desses fluxos no Huawei.

    sudo systemctl start orbymon-cgnat-report.service
    sudo journalctl -u orbymon-cgnat-report.service -n 180 --no-pager

A consulta analisa os ultimos 60 minutos por padrao; contadores
do NetFlow amostrado 1:2048 sao estimados e agrupados no minuto final.
Ausencia de fluxos para 100.64.64.0/19 nao prova que o NAT esteja
desativado: o Huawei pode observar a posicao pos-NAT do fluxo.

## Limitacoes de identificacao dos assinantes

Um IP publico pode corresponder a ate 32 usuarios conforme configurado,
mas NAO ha correlacao por assinante no rollup do OrbyMon.
Precisaremos de eventos/logs de mapeamento do A10 contendo
IP privado:porta -> IP publico:porta, protocolo e horarios, alem da
ligacao PPPoE/RADIUS com o assinante. A Fase 2 NAO registra portas de
origem, de modo que nao pode reconstruir traducoes com precisao.
Nao ativar consultas ou alteracoes no A10 sem validacao de riscos.

A fase 3 continua PASSIVA e NAO muda automaticamente thresholds ou
regras em funcao deste perfil.
