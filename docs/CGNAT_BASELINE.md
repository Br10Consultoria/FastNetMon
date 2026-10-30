# OrbyMon - Fase 4: diagnostico CGNAT e baseline observada

Os blocos protegidos sao 45.238.170.0/23 e 187.87.201.0/24.
Nao sabemos ainda quais enderecos desses blocos sao compartilhados
pelo equipamento de CGNAT; o instalador NAO classifica nenhum como
CGNAT ate receber a informacao real de pools.

## Instalar (somente leitura)

    cd /opt/orbymon
    git pull --ff-only origin main
    PYTHONPATH=src python3 -m unittest discover -s tests -q
    sudo bash scripts/setup-cgnat-baseline.sh

Instala e importa automaticamente o dashboard
"OrbyMon | CGNAT - Redes Publicas e Baseline" na pasta OrbyMon.
Nao cria novas tabelas, nao muda alertas, thresholds, exportacao, CGNAT,
Huawei, Mikrotik, firewall ou SSH.

Relatorio em JSON no journal:

    sudo systemctl start orbymon-cgnat-report.service
    sudo journalctl -u orbymon-cgnat-report.service -n 120 --no-pager

## Cadastrar os pools REAIS quando disponiveis

Edite /etc/orbymon/cgnat-profiles.json. Campos:
- protected_cidrs: blocos publicos protegidos.
- cgnat_pools: faixas publicas REALMENTE compartilhadas (vazio por padrao).
- dedicated_public_cidrs: IPs/faixas dedicados a clientes.
- infrastructure_public_cidrs: IPs/faixas de infraestrutura.
- lookback_hours: janela 1-72h; inicie 1h para evitar sobrecarga.
- settle_minutes: aguardar consolidação de NetFlow.
- min_samples: minimo de minutos observados para considerar p95 utilizavel.
- max_rows: aborta sem apresentar amostra parcial quando excedido.

Pools devem ser CIDR valido totalmente contido nos blocos protegidos;
subfaixas com papeis diferentes nao podem se sobrepor.
Nao presumir qual bloco/host e CGNAT com base na contagem de conexoes.

O sistema separa os IPs publicos **vistos como origem** dos **vistos
como destino**. Isso NAO significa upload/download nem indica se o
observador esta antes ou depois do CGNAT.
Os indices input_if,output_if,direction sao preservados como emitidos.

O relatorio entrega p95 e pico de Mbps/PPS por IP publico, interface,
direcao e protocolo, com numero de minutos observados. Se houver poucas
observacoes, baseline_confiavel=false; p95 nao sera adequado a calibracao.
A agregacao usa apenas minutos que tiveram fluxos: minutos sem amostra
NAO devem ser considerados trafego zero.

## Consideracoes sobre assinantes / NAT

Um unico IP publico compartilhado representa varios assinantes.
NetFlow pos-NAT nao identifica automaticamente IP privado, portas
traduzidas nem cliente PPPoE. Para correlacao real, sera preciso um
export de logs de NAT contendo IP/porta privado, IP/porta publico,
protocolo e timestamps confiaveis (e modelo de atribuicao de clientes).
Nao adivinhar assinante a partir do IP publico ou ASN.

A tabela da fase 2 agrega portas de destino, nao guarda portas de origem;
portanto nao pode reconstruir mapeamentos NAT historicos. Em alguns
cenarios NAT logging tambem nao informa destino; seu formato deve ser
inspecionado e a retencao/privacidade revisada antes da integracao.

A fase 3 continua PASSIVA com seus limites atuais. A F4 apenas fornece
referencias para calibração posterior, sem alterar automaticamente
limiares nem confirmar DDoS.
