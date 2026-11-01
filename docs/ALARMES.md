# Alarmes por filtro

Um alarme mede um filtro nfdump **a cada minuto** e abre um **incidente** quando as condições se mantêm.
Serve para o que a detecção por IP não pega bem: tipos de tráfego específicos (amplificação DNS, SYN sem ACK,
SMTP saindo dos pools, SSH para fora), em qualquer sentido.

## Instalação

```bash
cd /opt/orbymon && sudo git pull
sudo bash scripts/setup-filter-rules.sh   # tabelas, 6 modelos (desligados), permissões, timer de 1 min
sudo systemctl restart orbymon-admin
```

Depois, no painel, página **Alarmes**: abra um modelo, clique **Testar** (mede os últimos 30–120 min com os
arquivos reais do nfcapd, sem gravar nada), ajuste os valores até casar só o que interessa e marque **Ligado**.

## Como um alarme é definido

| Campo | O que faz |
|---|---|
| Filtro | Sintaxe nfdump com os atalhos da rede (`@dst_rede`, `@src_pools`, `@assinantes`...). Dá para trazer um filtro salvo da Análise. |
| Condições | Até 4, combinadas por E/OU. Medidas: Mbps, pacotes/s, fluxos por minuto, bytes por pacote. |
| Comparação | `>`, `≥`, `<`, `≤` com valor fixo, ou **acima/abaixo da média** em %, sobre uma janela de 2–120 min do próprio filtro. |
| Minutos seguidos | Quantos minutos casando antes de abrir o incidente (evita picos isolados). |
| Encerrar após | Minutos sem casar até encerrar. Entre o último minuto que casou e o encerramento o incidente fica **resfriando**. |
| Relatório | Top destinos, origens, portas, protocolos ou fluxos completos no momento da abertura. |

“Acima da média” em **%**: 200 = três vezes a média. A média só vale com pelo menos metade da janela de
histórico e nunca dispara sobre média zero. Combine sempre com um piso fixo (E), por exemplo
`Mbps > 20` **E** `Mbps 300% acima da média de 15 min`, para não alarmar sobre tráfego quase nulo.

Os valores são extrapolados pela amostragem configurada (1:2048 no NE8000), como no restante do sistema.

## Ciclo do incidente

1. **aberto** — atingiu os minutos seguidos. Gera aviso no Telegram e um evento em `orby_attack_events`
   (`detection='filter'`, regra “Filtro: nome”), junto com os demais eventos de ataque.
2. **resfriando** — parou de casar, mas ainda dentro do tempo de encerramento. Se voltar a casar, segue o mesmo incidente.
3. **encerrado** — passou o tempo sem casar. Aviso de encerramento com duração e pico.

Enquanto aberto, um lembrete sai a cada `ORBYMON_NOTIFY_REMINDER_MIN` (telegram.env).

O aviso traz: condição, valores do minuto, top N com escopo/pool e, para IP de pool CGNAT, os assinantes
(`100.64.x.x`) vistos no log NAT naquele minuto. Esses dados só vão para o chat privado configurado.

## Operação

- Timer: `orbymon-filter-rules.timer` (segundo :20 de cada minuto). Se o servidor ficar parado, recupera até 15 min.
- Logs: `journalctl -u orbymon-filter-rules -n 30 --no-pager`.
- Filtro inválido não derruba os outros: o erro aparece na lista de alarmes.
- Histórico minuto a minuto por alarme fica `retention_days` (padrão 7); incidentes encerrados, 90 dias.
- Cada execução tem limite de tempo; com muitos alarmes ligados e janelas grandes, prefira filtros específicos.

## Permissões

- Pipeline (`ORBYMON_DB_USER`): lê `orby_filter_rules`, grava estado, amostras e incidentes.
- Painel (`orbymon_admin`): edita só `orby_filter_rules` (auditoria: `alarme_salvo`, `alarme_ligado`, `alarme_excluido`).
