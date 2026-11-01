# Saúde do sistema

`orbymon-health.timer` verifica a cada 2 minutos e grava o resultado na tabela `orby_health` (página **Saúde** do
painel). Um problema confirmado em 2 verificações seguidas vai para o Telegram; a volta ao normal também; item
crítico que continua é lembrado a cada 2 horas.

```bash
sudo bash scripts/setup-health.sh
journalctl -u orbymon-health -n 20 --no-pager
```

| Item | Atenção | Crítico |
|---|---|---|
| Coleta NetStream (último arquivo do nfcapd) | 2 min | 5 min |
| Rollup dos fluxos (último minuto em `orby_flow_minute`) | 5 min | 15 min |
| Detector bidirecional (última execução) | 3 min | 10 min |
| Log NAT do A10 (último minuto) | 5 min | 15 min |
| Fluxos de pool com assinante identificado (1 h) | < 50% | — |
| Alarmes por filtro com erro ou sem avaliar há 10 min | qualquer | — |
| Eventos sem aviso no Telegram há 10+ min | qualquer | — |
| Retenção do rollup (dado mais antigo além da retenção + 12 h) | sim | — |
| Disco (`/`, `/var/lib/orbymon`, `/var/log/orbymon`, `/var/lib/mysql`) | 85% | 93% |
| Serviços `orbymon-*` com falha | — | qualquer |
| Tempo de execução dos timers de 1 min (rollup: 30 s) | 45 s (40 s) | 90 s |

O tempo de execução é o principal sinal de **desempenho**: se o detector ou o rollup passam a levar quase o
intervalo do timer, os dados atrasam e o alarme sai tarde. A página também mostra o tamanho do banco e as maiores
tabelas.
