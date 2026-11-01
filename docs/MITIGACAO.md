# Mitigação por blackhole (RTBH)

O OrbyFlow anuncia o IP atacado (/32 ou /128) ao NE8000 por uma sessão BGP (GoBGP no servidor) com
**next-hop de descarte** e **community de blackhole**; o roteador descarta o tráfego para esse IP. Quando o ataque
termina, o anúncio é retirado. Só tráfego **recebido** dispara.

> Blackhole derruba **todo** o tráfego do IP (inclusive o legítimo): protege o resto da rede, não o cliente atacado.
> Por isso começa em simulação, passa por validação e aprovação manual, e só vai para automático com a calibração
> estável.

## Modos

| Modo | O que faz | Precisa de calibração? |
|---|---|---|
| desligada | nada; bloqueios ativos são retirados | — |
| **simulação** (padrão) | registra e avisa o que bloquearia, sem anunciar | não |
| aprovação manual | propõe; um operador aprova no painel (página **Mitigação**); só então anuncia | não (você decide caso a caso) |
| automática | anuncia sozinho quando o ataque passa do gatilho | **sim**: só com calibração e linha de base estáveis |

## Travas de segurança

- Só IPs dos blocos do provedor; **nunca** infraestrutura (roteador, servidores) nem rede privada (100.64.x).
- IP de **pool CGNAT** só com "permitir bloquear IP de pool" (derruba os ~32 assinantes do IP).
- Lista **Nunca bloquear** (DNS, servidores, clientes VIP…).
- Gatilho: severidade mínima (padrão crítica) **e** Mbps ou pps mínimos (padrão 1000 Mbps / 300 mil pps).
- **Máximo de bloqueios simultâneos** (padrão 10).
- Duração mínima (30 min) e retirada só depois de N minutos sem ataque (15).
- Proposta sem decisão expira (20 min).
- **Reconciliação** a cada 30 s: anúncio que existe no GoBGP sem pedido ativo é retirado; pedido ativo que sumiu
  (GoBGP reiniciou) é reanunciado.
- O GoBGP não aceita nada do roteador (import reject) e não escuta a porta 179 (só conecta). A API dele fica em
  127.0.0.1.
- Tudo auditado; avisos no Telegram/e-mail/webhook (proposto, anunciado, retirado, falhou).

## Instalação

```bash
cd /opt/orbymon && sudo git pull
sudo bash scripts/setup-mitigation.sh                     # simulação, sem BGP
# com a sessão BGP (iBGP no exemplo; ASN de 4 bytes):
sudo bash scripts/setup-mitigation.sh --neighbor <IP_DO_NE8000> --peer-as 262687 --local-as 262687 \
     --router-id 187.87.201.198 [--password <SENHA_MD5>]
```

## Lado do NE8000 (indicativo — confira a sintaxe da sua versão do VRP)

Ideia: aceitar do servidor **somente /32 dos seus blocos com a community de blackhole**, trocar o next-hop para uma
rota estática para NULL0 e **não anunciar nada** para o servidor.

```
ip route-static 192.0.2.1 255.255.255.255 NULL0 description ORBYFLOW-RTBH
ipv6 route-static 100:: 64 NULL0 description ORBYFLOW-RTBH

ip ip-prefix ORBYFLOW-RTBH-V4 index 10 permit 187.87.201.0 24 greater-equal 32 less-equal 32
ip ip-prefix ORBYFLOW-RTBH-V4 index 20 permit 45.238.170.0 23 greater-equal 32 less-equal 32
ip community-filter basic ORBYFLOW-BH permit 65535:666

route-policy ORBYFLOW-IN permit node 10
 if-match ip-prefix ORBYFLOW-RTBH-V4
 if-match community-filter ORBYFLOW-BH
 apply ip-address next-hop 192.0.2.1
route-policy ORBYFLOW-IN deny node 100
route-policy ORBYFLOW-OUT deny node 10

bgp 262687
 peer <IP_DO_SERVIDOR> as-number 262687
 peer <IP_DO_SERVIDOR> description ORBYFLOW-RTBH
 peer <IP_DO_SERVIDOR> password cipher <SENHA_MD5>
 ipv4-family unicast
  peer <IP_DO_SERVIDOR> enable
  peer <IP_DO_SERVIDOR> route-policy ORBYFLOW-IN import
  peer <IP_DO_SERVIDOR> route-policy ORBYFLOW-OUT export
  peer <IP_DO_SERVIDOR> route-limit 200
```

(Equivalente para `ipv6-family unicast` com um ip-prefix IPv6 do 2804:4fa8::/32, se for usar /128.)

Para levar o blackhole à **operadora de trânsito** (descartar antes do seu link), use a community de blackhole que
ela documenta (muitas aceitam RFC 7999 `65535:666`) numa política de exportação para ela — e desmarque NO_EXPORT só
nesse caso. Isso é específico de cada operadora: valide com ela.

ASN de 4 bytes (262687) não cabe numa community padrão: para communities próprias use **large community**
(`262687:0:666`), aceita no campo Communities do painel.

## Roteiro de validação (antes de produção)

1. **Simulação** por alguns dias: confira na página Mitigação e nos avisos quais IPs seriam bloqueados. Ajuste
   gatilho, lista "Nunca bloquear" e exceções até não haver nada que você não bloquearia.
2. **Sessão BGP**: rode o setup com `--neighbor`, configure o NE8000 e confira
   `gobgp -u 127.0.0.1 -p 50051 neighbor` (estado `Establ`) e no roteador `display bgp peer`. O roteador não deve
   anunciar nada para o servidor (`gobgp global rib` vazio antes do teste).
3. Na página Mitigação, marque **BGP ligado** (modo ainda simulação) e salve.
4. **Teste de validação** com um IP **sem cliente** dos seus blocos (2–5 min). O anúncio leva NO_ADVERTISE (o
   roteador instala, mas não repassa). Confira no NE8000:
   - `display bgp routing-table <IP>` → recebido do servidor, community de blackhole, next-hop 192.0.2.1;
   - `display ip routing-table <IP>` → saída NULL0;
   - de fora, `ping <IP>` não responde (se o IP respondia antes).
   Depois do prazo o anúncio sai sozinho; confira que a rota sumiu.
5. **Aprovação manual** por algumas semanas: aprove só o que fizer sentido.
6. **Automático**: só com calibração e linha de base estáveis (o painel pede confirmação explícita).

## Operação

- Painel → **Mitigação**: modo, estado do BGP, pedidos em andamento (aprovar, rejeitar, retirar), bloqueio manual,
  teste de validação e histórico.
- `journalctl -u orbymon-mitigation -n 30` (controlador, a cada 30 s) · `journalctl -u orbymon-gobgpd -n 30`.
- **Emergência — retirar tudo**: modo **desligada** no painel (sai em até 30 s) ou
  `sudo systemctl stop orbymon-gobgpd` (a sessão cai e o roteador remove todas as rotas recebidas).
- A página **Saúde** avisa se o controlador parar ou a sessão BGP cair com o BGP ligado.
