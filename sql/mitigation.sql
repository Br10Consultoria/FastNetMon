-- Mitigacao por blackhole (RTBH): cada linha e um pedido de bloqueio de um IP /32 ou /128.
--   status: simulated (modo simulacao, nada anunciado) | proposed (aguarda aprovacao) | approved (sera anunciado)
--           | active (anunciado) | withdrawing (retirada pedida) | ended | rejected | expired | failed
CREATE TABLE IF NOT EXISTS orby_mitigations (
 id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 ip VARCHAR(45) CHARACTER SET ascii NOT NULL,
 prefix VARCHAR(49) CHARACTER SET ascii NOT NULL,
 status VARCHAR(12) CHARACTER SET ascii NOT NULL,
 origin VARCHAR(8) CHARACTER SET ascii NOT NULL,          -- auto | manual | test
 rule_name VARCHAR(120) NOT NULL DEFAULT '',
 reason VARCHAR(300) NOT NULL DEFAULT '',
 peak_mbps DOUBLE NOT NULL DEFAULT 0,
 peak_pps DOUBLE NOT NULL DEFAULT 0,
 duration_min INT UNSIGNED NOT NULL DEFAULT 30,
 created_at DATETIME NOT NULL,
 requested_by VARCHAR(64) NOT NULL DEFAULT '',
 decided_by VARCHAR(64) NOT NULL DEFAULT '',
 decided_at DATETIME NULL,
 announced_at DATETIME NULL,
 last_seen_at DATETIME NULL,
 expires_at DATETIME NULL,
 ended_at DATETIME NULL,
 error VARCHAR(300) NOT NULL DEFAULT '',
 notified_status VARCHAR(12) CHARACTER SET ascii NOT NULL DEFAULT '',
 INDEX ix_mitigation_status (status, ip),
 INDEX ix_mitigation_ip (ip, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Estado do controlador (ultima execucao, sessao BGP, prefixos anunciados) para o painel e a saude.
CREATE TABLE IF NOT EXISTS orby_mitigation_status (
 name VARCHAR(32) CHARACTER SET ascii NOT NULL PRIMARY KEY,
 value VARCHAR(500) NOT NULL,
 updated_at DATETIME NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
