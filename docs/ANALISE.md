# Análise avançada (filtros nfdump)

Página **Análise** do painel (porta 8443). Consulta os arquivos de fluxo guardados (15 dias) com a
sintaxe de filtro do nfdump — a mesma usada nos manuais de mercado — e mostra totais, gráfico e o top
pedido: IPs, portas, protocolos, AS, interfaces, conversas ou fluxos individuais.

## Atalhos da sua rede

Montados a partir da página Rede, servem para qualquer provedor:

| Atalho | Vira |
|---|---|
| `@rede` / `@src_rede` / `@dst_rede` | blocos públicos IPv4 e IPv6 |
| `@pools` / `@src_pools` / `@dst_pools` | pools CGNAT |
| `@assinantes` / `@src_assinantes` / `@dst_assinantes` | rede privada pré-NAT (100.64...) |
| `@infra` (e `@src_infra`, `@dst_infra`) | infraestrutura |

## Exemplos

```
@dst_rede and proto udp and src port 53                       amplificação DNS recebida
@src_pools and proto tcp and dst port 22 and flags S and not flags A   força bruta SSH saindo do CGNAT
@dst_rede and (proto tcp or proto udp) and port 0             porta 0 / fragmentos
dst ip 45.238.170.70 and dst port in [53 123 1900]           um alvo, várias portas
in if 334 and bytes > 1M                                      fluxos grandes entrando pela interface 334
src as 15169 and proto udp                                    UDP vindo do AS 15169
```

Operadores: `and`, `or`, `not`, parênteses; listas `in [a b c]`; comparações `> >= < <= =` com sufixos
`k`, `M`, `G` em bytes/pacotes; `duration` em milissegundos; `flags S A F R P U`; `icmp-type`/`icmp-code`;
`in if`/`out if`; `src as`/`dst as`; `net`, `ip`, `port` com `src`/`dst`.

Não disponível aqui: `geo` (o nfdump precisa de uma base própria) e campos de NAT (`nat ip`, `nat port`)
— o Huawei não exporta NAT; para CGNAT use **Investigar**, que lê o log do A10. Nos fluxos individuais
de IP de pool, o link **quem é?** abre a investigação com IP, porta e horário já preenchidos.

## Filtros salvos

O painel traz modelos prontos (Recebido, Originado, CGNAT). Cada usuário pode salvar os seus; os
modelos são atualizados a cada instalação e não podem ser excluídos.

## Limites

- até 24 h por consulta (6 h em fluxos individuais); uma consulta por vez, com tempo máximo de 45 s;
- valores com a amostragem 1:2048 já expandida pelo nfdump (estimativa);
- toda consulta fica na Auditoria.
