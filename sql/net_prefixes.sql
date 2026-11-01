-- Blocos do provedor para os dashboards (independente de provedor): preenchida a partir da
-- configuracao por `python -m fmn_filters.net_prefixes` (setup e pagina Rede do painel).
SET NAMES utf8mb4;
CREATE TABLE IF NOT EXISTS orby_net_prefixes (
 kind VARCHAR(12) CHARACTER SET ascii NOT NULL,
 cidr VARCHAR(49) CHARACTER SET ascii NOT NULL,
 name VARCHAR(64) NOT NULL DEFAULT '',
 v_start BIGINT UNSIGNED NOT NULL,
 v_end BIGINT UNSIGNED NOT NULL,
 PRIMARY KEY (kind, cidr),
 INDEX ix_np_range (kind, v_start, v_end)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
