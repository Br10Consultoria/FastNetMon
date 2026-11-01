-- Etapa 2: excecoes (CIDR/ASN) e linha de base por hora do dia.

-- Excecao: IP/rede ou ASN inteiro, do lado remoto (internet) ou local (nossa rede).
--   action ignore   -> o trafego nao conta para as regras (detector e calibracao)
--   action multiply -> a entidade local tem limite x factor (perfil proprio)
CREATE TABLE IF NOT EXISTS orby_exceptions (
 id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 kind VARCHAR(8) CHARACTER SET ascii NOT NULL,          -- cidr | asn
 value VARCHAR(64) CHARACTER SET ascii NOT NULL,        -- 8.8.8.0/24 | 15169
 side VARCHAR(8) CHARACTER SET ascii NOT NULL,          -- remote | local
 direction VARCHAR(4) CHARACTER SET ascii NOT NULL DEFAULT 'any',   -- in | out | any
 rule_name VARCHAR(100) NOT NULL DEFAULT '',            -- '' = todas as regras
 action VARCHAR(8) CHARACTER SET ascii NOT NULL DEFAULT 'ignore',   -- ignore | multiply
 factor DOUBLE NOT NULL DEFAULT 1,
 note VARCHAR(200) NOT NULL DEFAULT '',
 expires_at DATETIME NULL,
 prefixes INT UNSIGNED NOT NULL DEFAULT 0,
 synced_at DATETIME NULL,
 sync_error VARCHAR(255) NOT NULL DEFAULT '',
 created_by VARCHAR(64) NOT NULL DEFAULT '',
 updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
 UNIQUE KEY uq_exception (kind,value,side,direction,rule_name,action)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Prefixos anunciados por um ASN de excecao (RIPEstat), renovados todo dia.
CREATE TABLE IF NOT EXISTS orby_exception_prefixes (
 exception_id INT UNSIGNED NOT NULL,
 cidr VARCHAR(49) CHARACTER SET ascii NOT NULL,
 PRIMARY KEY(exception_id,cidr)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Linha de base por (regra, escopo, tipo de dia, hora local): p99,9 e mediana do sinal por entidade/minuto,
-- media movel entre dias. Gravada pela calibracao diaria; lida pelo detector quando o limite dinamico esta ligado.
CREATE TABLE IF NOT EXISTS orby_baseline (
 rule_name VARCHAR(100) NOT NULL,
 scope VARCHAR(16) CHARACTER SET ascii NOT NULL,
 daytype VARCHAR(3) CHARACTER SET ascii NOT NULL,        -- wkd (seg-sex) | wke (sab, dom)
 hour TINYINT UNSIGNED NOT NULL,
 metric VARCHAR(16) CHARACTER SET ascii NOT NULL,       -- min_pps | min_mbps
 p99_9 DOUBLE NOT NULL,
 p50 DOUBLE NOT NULL,
 samples INT UNSIGNED NOT NULL,
 days SMALLINT UNSIGNED NOT NULL DEFAULT 1,
 last_day DATE NOT NULL,
 updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
 PRIMARY KEY(rule_name,scope,daytype,hour,metric)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
