# Geradores antigos (não usar para atualizar os dashboards)

Os dashboards oficiais agora vêm do export do Grafana validado em produção:
`grafana/exports/*.v2.json` → `python3 grafana/import_v2.py` → `grafana/dashboards/*.json`.

Estes scripts geravam versões anteriores e sobrescreveriam os ajustes feitos no Grafana.
`orbyflow-ddos-passive.json` é o painel da F3 (desativada); só é instalado por `setup-ddos-passive.sh`.
