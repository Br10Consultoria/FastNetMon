-- Alarmes por filtro (nfdump): definicao (painel), estado e series (avaliador), incidentes.
SET NAMES utf8mb4;
CREATE TABLE IF NOT EXISTS orby_filter_rules (
 id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 name VARCHAR(80) NOT NULL UNIQUE,
 enabled TINYINT(1) NOT NULL DEFAULT 0,
 severity VARCHAR(10) NOT NULL DEFAULT 'high',
 direction VARCHAR(3) CHARACTER SET ascii NOT NULL DEFAULT 'in',
 expr TEXT NOT NULL,
 definition JSON NOT NULL,
 builtin TINYINT(1) NOT NULL DEFAULT 0,
 updated_by VARCHAR(40) NOT NULL DEFAULT '',
 updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS orby_filter_rule_state (
 rule_id INT UNSIGNED NOT NULL PRIMARY KEY,
 last_bucket DATETIME NULL,
 streak INT UNSIGNED NOT NULL DEFAULT 0,
 status VARCHAR(10) CHARACTER SET ascii NOT NULL DEFAULT 'normal',
 last_bps DOUBLE NOT NULL DEFAULT 0,
 last_pps DOUBLE NOT NULL DEFAULT 0,
 last_flows DOUBLE NOT NULL DEFAULT 0,
 last_error VARCHAR(300) NOT NULL DEFAULT '',
 updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS orby_filter_rule_samples (
 rule_id INT UNSIGNED NOT NULL,
 bucket_utc DATETIME NOT NULL,
 bps DOUBLE NOT NULL DEFAULT 0,
 pps DOUBLE NOT NULL DEFAULT 0,
 flows DOUBLE NOT NULL DEFAULT 0,
 bpp DOUBLE NOT NULL DEFAULT 0,
 matched TINYINT(1) NOT NULL DEFAULT 0,
 PRIMARY KEY (rule_id, bucket_utc),
 INDEX ix_frs_bucket (bucket_utc)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS orby_filter_incidents (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 rule_id INT UNSIGNED NOT NULL,
 rule_name VARCHAR(80) NOT NULL,
 severity VARCHAR(10) NOT NULL,
 status VARCHAR(10) CHARACTER SET ascii NOT NULL,
 started_at DATETIME NOT NULL,
 last_match_at DATETIME NOT NULL,
 resolved_at DATETIME NULL,
 peak_bps DOUBLE NOT NULL DEFAULT 0,
 peak_pps DOUBLE NOT NULL DEFAULT 0,
 peak_flows DOUBLE NOT NULL DEFAULT 0,
 matches INT UNSIGNED NOT NULL DEFAULT 0,
 top JSON NOT NULL,
 notified_open DATETIME NULL,
 notified_reminder DATETIME NULL,
 notified_close DATETIME NULL,
 INDEX ix_fi_rule (rule_id, status),
 INDEX ix_fi_time (started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Modelos (desligados: ligue depois de conferir com "Testar" no painel).
INSERT INTO orby_filter_rules (name,enabled,severity,direction,expr,definition,builtin) VALUES
('Amplificação DNS recebida',0,'high','in','@dst_rede and proto udp and src port 53',
 '{"logic":"and","conditions":[{"metric":"mbps","op":"gt","value":300}],"consecutive":2,"resolve_after":5,"report":{"agg":"dstip","top":5},"notify":true,"retention_days":7}',1),
('SYN flood recebido',0,'high','in','@dst_rede and proto tcp and flags S and not flags AFRPU',
 '{"logic":"and","conditions":[{"metric":"pps","op":"gt","value":50000}],"consecutive":2,"resolve_after":5,"report":{"agg":"dstip","top":5},"notify":true,"retention_days":7}',1),
('UDP recebido acima do normal',0,'warning','in','@dst_rede and proto udp',
 '{"logic":"and","conditions":[{"metric":"mbps","op":"above_avg","value":200,"window":15},{"metric":"mbps","op":"gt","value":500}],"consecutive":2,"resolve_after":5,"report":{"agg":"dstip","top":5},"notify":true,"retention_days":7}',1),
('SSH saindo dos pools (força bruta)',0,'high','out','@src_pools and proto tcp and dst port 22 and flags S and not flags A',
 '{"logic":"and","conditions":[{"metric":"flows","op":"gt","value":300}],"consecutive":3,"resolve_after":10,"report":{"agg":"srcip","top":5},"notify":true,"retention_days":7}',1),
('Spam saindo da rede (SMTP)',0,'high','out','@src_rede and proto tcp and dst port in [25 465 587]',
 '{"logic":"and","conditions":[{"metric":"flows","op":"above_avg","value":300,"window":30},{"metric":"flows","op":"gt","value":100}],"consecutive":3,"resolve_after":15,"report":{"agg":"srcip","top":5},"notify":true,"retention_days":7}',1),
('Flood originado (UDP para fora)',0,'critical','out','@src_rede and proto udp and not dst port in [53 123 443 3478 4500 500]',
 '{"logic":"and","conditions":[{"metric":"mbps","op":"gt","value":200}],"consecutive":2,"resolve_after":5,"report":{"agg":"srcip","top":5},"notify":true,"retention_days":7}',1),
('Amplificação NTP/SSDP/memcached/CLDAP recebida',0,'high','in','@dst_rede and proto udp and src port in [123 1900 11211 389 19 161 3702 10001 37810]',
 '{"logic":"and","conditions":[{"metric":"mbps","op":"gt","value":200}],"consecutive":2,"resolve_after":5,"report":{"agg":"dstip","top":5},"notify":true,"retention_days":7}',1),
('Fragmentos UDP recebidos (porta 0)',0,'high','in','@dst_rede and proto udp and src port 0 and dst port 0',
 '{"logic":"and","conditions":[{"metric":"mbps","op":"gt","value":300}],"consecutive":2,"resolve_after":5,"report":{"agg":"dstip","top":5},"notify":true,"retention_days":7}',1),
('ICMP flood recebido',0,'warning','in','@dst_rede and proto icmp',
 '{"logic":"and","conditions":[{"metric":"pps","op":"gt","value":30000}],"consecutive":2,"resolve_after":5,"report":{"agg":"dstip","top":5},"notify":true,"retention_days":7}',1),
('TCP RST flood recebido',0,'warning','in','@dst_rede and proto tcp and flags R',
 '{"logic":"and","conditions":[{"metric":"pps","op":"gt","value":30000}],"consecutive":2,"resolve_after":5,"report":{"agg":"dstip","top":5},"notify":true,"retention_days":7}',1),
('IP recebendo acima do habitual',0,'warning','in','@dst_rede',
 '{"logic":"and","conditions":[{"metric":"mbps","op":"above_usual","value":300,"window":7},{"metric":"mbps","op":"gt","value":500}],"consecutive":3,"resolve_after":10,"report":{"agg":"dstip","top":5},"notify":true,"retention_days":7}',1),
('Cliente como refletor DNS (resolver aberto)',0,'high','out','@src_rede and proto udp and src port 53',
 '{"logic":"and","conditions":[{"metric":"mbps","op":"gt","value":50}],"consecutive":3,"resolve_after":10,"report":{"agg":"srcip","top":5},"notify":true,"retention_days":7}',1),
('Cliente como refletor NTP/SSDP/memcached',0,'high','out','@src_rede and proto udp and src port in [123 1900 11211 389 19 161 3702 10001 37810]',
 '{"logic":"and","conditions":[{"metric":"mbps","op":"gt","value":20}],"consecutive":3,"resolve_after":10,"report":{"agg":"srcip","top":5},"notify":true,"retention_days":7}',1),
('Varredura Telnet/IoT saindo (Mirai)',0,'high','out','@src_rede and proto tcp and dst port in [23 2323] and flags S and not flags A',
 '{"logic":"and","conditions":[{"metric":"pps","op":"gt","value":500}],"consecutive":3,"resolve_after":10,"report":{"agg":"srcip","top":5},"notify":true,"retention_days":7}',1),
('Varredura RDP/SMB saindo (worm/força bruta)',0,'high','out','@src_rede and proto tcp and dst port in [3389 445] and flags S and not flags A',
 '{"logic":"and","conditions":[{"metric":"pps","op":"gt","value":500}],"consecutive":3,"resolve_after":10,"report":{"agg":"srcip","top":5},"notify":true,"retention_days":7}',1),
('SYN flood originado',0,'critical','out','@src_rede and proto tcp and flags S and not flags A',
 '{"logic":"and","conditions":[{"metric":"pps","op":"gt","value":20000}],"consecutive":2,"resolve_after":5,"report":{"agg":"srcip","top":5},"notify":true,"retention_days":7}',1),
('Fragmentos/porta 0 originados',0,'high','out','@src_rede and proto udp and dst port 0',
 '{"logic":"and","conditions":[{"metric":"mbps","op":"gt","value":50}],"consecutive":2,"resolve_after":5,"report":{"agg":"srcip","top":5},"notify":true,"retention_days":7}',1),
('Pool CGNAT: SYN saindo acima do normal',0,'warning','out','@src_pools and proto tcp and flags S and not flags A',
 '{"logic":"and","conditions":[{"metric":"pps","op":"above_avg","value":300,"window":15},{"metric":"pps","op":"gt","value":5000}],"consecutive":3,"resolve_after":10,"report":{"agg":"srcip","top":5},"notify":true,"retention_days":7}',1)
ON DUPLICATE KEY UPDATE builtin=1;
