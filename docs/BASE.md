# Linha de base, limite dinâmico e exceções (etapa 2)

Objetivo: **menos falso positivo e mais sensibilidade fora do pico**, sem afrouxar a detecção.

## Instalação

```bash
cd /opt/orbymon && sudo git pull
sudo bash scripts/setup-baseline.sh      # tabelas, permissões, timer dos ASNs, primeira linha de base
sudo systemctl restart orbymon-admin
```

## Linha de base por hora

A calibração diária (`orbymon-calibrate`, 05:17) já media o p99,9 de cada regra e tipo de IP no dia inteiro. Agora
também grava, em `orby_baseline`, o p99,9 e a mediana **por hora local**, separando **dias úteis** e **fim de
semana**. Cada dia novo entra numa média móvel (peso mínimo de 20% — reflete aproximadamente as últimas 5 semanas);
rodar a calibração de novo no mesmo dia não pesa em dobro.

Minutos de entidades com ataque registrado continuam fora da medida, assim como o tráfego coberto por exceções.

## Limite dinâmico (página **Base** do painel)

Desligado por padrão. Ligado, em cada minuto o detector usa:

```
limite = min(limite fixo da regra, max(p99,9 da hora × fator, limite fixo × piso))
```

- **Nunca fica acima do limite fixo** calibrado: o dinâmico só deixa a detecção mais sensível nas horas calmas
  (ex.: de madrugada um flood de 15 mil pps num IP dedicado já alarma, em vez de precisar de 50 mil).
- **Piso** (padrão 25% do fixo) evita que uma hora quase sem tráfego vire alarme por qualquer coisa.
- **Dias de histórico** (padrão 3): até a hora ter esse número de dias medidos, vale o fixo.
- Critérios estruturais (IPs remotos, proporção SYN, porta 0) não mudam.
- O alerta no Telegram mostra “Limite usado: … (dinâmico da hora)” quando foi o dinâmico que disparou.

A página mostra, por regra e tipo de IP, o limite de cada hora (barras), o fixo (contorno) e o p99,9 medido
(traço vermelho), e a lista de **quem mais dispararia** com os limites atuais — com atalho para dar a esse IP um
limite próprio.

Sugestão de uso: deixe a base acumular 3–7 dias, confira os gráficos e ligue. Acompanhe os alarmes da madrugada nos
primeiros dias; se houver ruído, suba o fator (2 → 3) ou o piso.

## Exceções (página **Exceções**)

| Lado | Ação | Exemplo |
|---|---|---|
| remoto | ignorar | QUIC/UDP 443 de Google/Meta chegando aos clientes e disparando “IN UDP volumetrico” |
| local | ignorar | DNS recursivo ou servidor de e-mail do próprio provedor nas regras de saída |
| local | multiplicar | servidor de cliente com tráfego alto legítimo: limite ×3 só para ele |

- Cada exceção vale para **um sentido** (recebido, originado ou ambos) e **uma regra** ou todas. Prefira o mais
  específico: ignorar um ASN inteiro também esconde ataques com origem forjada naquelas faixas.
- **ASN**: os prefixos anunciados vêm do RIPEstat na hora do cadastro e são renovados todo dia
  (`orbymon-exceptions.timer`, 04:41). Se a consulta falhar, a lista anterior é mantida. Grupos prontos: Google,
  Meta, Cloudflare, Akamai, Netflix, Amazon, Microsoft, Apple.
- **Validade** opcional em dias (exceção temporária para um evento, migração, teste de carga).
- Redes mais amplas que /8 (IPv4) ou /19 (IPv6) são recusadas.
- Valem no detector bidirecional e na calibração (a calibração aplica as exceções do lado local; as do lado remoto
  só no detector, porque o agregado da calibração não guarda o IP remoto).
- Tudo fica na auditoria (`excecao_salva`, `excecao_excluida`).

## Alarmes por filtro: “acima do habitual”

Nova comparação nos alarmes por filtro: **acima/abaixo do habitual**, que compara o minuto com o **mesmo horário
(±10 min) dos N dias anteriores** do próprio filtro (N de 1 a 28). Exige histórico: o alarme precisa estar ligado
há pelo menos metade de N dias (a retenção das amostras é ajustada automaticamente para N+1 dias). Exemplo:
`Mbps 200% acima do habitual (7 dias)` **E** `Mbps > 20`.

## Tempo de detecção e o *active timeout* do NetStream

Todas as avaliações são por minuto (rollup a cada 30 s, detector a cada minuto, alarmes por filtro a cada minuto) e
o alarme sai após os minutos seguidos configurados — tipicamente 2 a 4 minutos depois do início.

O que pode atrasar muito mais é o **active timeout** da exportação: um fluxo que não termina (um flood contínuo)
só é exportado quando esse tempo vence, e até lá não aparece em minuto nenhum; quando aparece, cai todo de uma vez
num minuto só. Recomendação: **active timeout de 1 minuto** (inactive 15–30 s) no NE8000.

No VRP do NE8000 isso é configurado com `ip netstream timeout active` (minutos) e `ip netstream timeout inactive`
(segundos) — **confira a sintaxe e o escopo (global ou por slot) no manual da sua versão** antes de aplicar, e
verifique com `display current-configuration | include netstream`. Exportar com timeout menor aumenta o número de
registros exportados; acompanhe a carga do nfcapd e do rollup no primeiro dia.
