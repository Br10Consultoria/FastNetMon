-- Filtros salvos da Analise avancada (sintaxe nfdump + atalhos @rede, @pools, @assinantes...).
SET NAMES utf8mb4;
CREATE TABLE IF NOT EXISTS orby_saved_filters (
 id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 name VARCHAR(80) NOT NULL UNIQUE,
 expr TEXT NOT NULL,
 description VARCHAR(300) NOT NULL DEFAULT '',
 category VARCHAR(40) NOT NULL DEFAULT 'Meus filtros',
 builtin TINYINT(1) NOT NULL DEFAULT 0,
 created_by VARCHAR(40) NOT NULL DEFAULT '',
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Modelos prontos (atualizados a cada instalacao; os criados pelos usuarios nao sao tocados).
INSERT INTO orby_saved_filters (name,expr,description,category,builtin) VALUES
('Recebido: tudo para a minha rede','@dst_rede','Todo o tráfego que chega aos blocos do provedor.','Recebido',1),
('Recebido: SYN sem resposta (SYN flood/varredura)','@dst_rede and proto tcp and flags S and not flags AFRPU','Pacotes só com SYN contra a rede: flood ou varredura de portas.','Recebido',1),
('Recebido: porta 0 e fragmentos','@dst_rede and (proto tcp or proto udp) and port 0','Porta 0 real ou fragmentos de amplificação UDP.','Recebido',1),
('Recebido: amplificação DNS','@dst_rede and proto udp and src port 53','Respostas DNS chegando — volume alto sem consulta é reflexão.','Recebido',1),
('Recebido: amplificação NTP/SSDP/CLDAP/SNMP/chargen','@dst_rede and proto udp and src port in [123 1900 389 161 19 3702 11211 10001]','Portas clássicas de reflexão/amplificação UDP.','Recebido',1),
('Recebido: ICMP','@dst_rede and (proto icmp or proto 58)','Ping flood e ICMP em geral contra a rede.','Recebido',1),
('Recebido: GRE/ESP/túneis','@dst_rede and (proto gre or proto esp or proto ah or proto 115 or proto 4 or proto 41)','Protocolos de túnel (também usados em floods GRE).','Recebido',1),
('Recebido: acesso a Winbox/RDP/SSH/Telnet','@dst_rede and proto tcp and dst port in [8291 3389 22 23 2323] and flags S and not flags A','Tentativas de conexão em serviços de gerência expostos.','Recebido',1),
('Originado: SSH para fora (força bruta)','@src_rede and proto tcp and dst port 22 and flags S and not flags A','Clientes abrindo SSH para muitos destinos — origem típica de denúncias.','Originado',1),
('Originado: e-mail (spam)','@src_rede and proto tcp and dst port in [25 465 587]','SMTP saindo de assinantes: spam ou máquina infectada.','Originado',1),
('Originado: Telnet/IoT (botnet)','@src_rede and proto tcp and dst port in [23 2323 7547 5555]','Varredura de botnets de IoT (Mirai e similares).','Originado',1),
('Originado: SMB/RDP/SQL','@src_rede and proto tcp and dst port in [445 3389 1433 3306 5900]','Propagação de worms e força bruta em serviços Windows/banco.','Originado',1),
('Originado: SIP (fraude VoIP)','@src_rede and proto udp and dst port in [5060 5061]','Varredura/fraude SIP a partir da rede.','Originado',1),
('Originado: UDP de alto volume','@src_rede and proto udp and not dst port in [53 123 443 3478 4500 500]','UDP saindo fora de DNS/NTP/QUIC/VPN: possível flood originado.','Originado',1),
('Originado: SYN para fora','@src_rede and proto tcp and flags S and not flags AFRPU','Pacotes só com SYN saindo: SYN flood ou varredura originada.','Originado',1),
('CGNAT: tráfego dos pools','@pools','Tudo que entra e sai pelos IPs públicos dos pools CGNAT.','CGNAT',1),
('CGNAT: rede privada vista na borda','@assinantes','IPs 100.64 na borda (call center/roteamento interno ou vazamento).','CGNAT',1)
ON DUPLICATE KEY UPDATE expr=VALUES(expr),description=VALUES(description),category=VALUES(category),builtin=1;
