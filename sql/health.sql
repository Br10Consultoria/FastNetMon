-- Saude do OrbyMon (gravada pelo orbymon-health a cada 2 min; lida pelo painel).
CREATE TABLE IF NOT EXISTS orby_health (
 check_key VARCHAR(64) CHARACTER SET ascii NOT NULL PRIMARY KEY,
 label VARCHAR(100) NOT NULL,
 status VARCHAR(8) CHARACTER SET ascii NOT NULL,         -- ok | warn | crit | unknown
 value VARCHAR(200) NOT NULL DEFAULT '',
 detail VARCHAR(500) NOT NULL DEFAULT '',
 since DATETIME NOT NULL,
 bad_runs INT UNSIGNED NOT NULL DEFAULT 0,
 notified_status VARCHAR(8) CHARACTER SET ascii NOT NULL DEFAULT 'ok',
 notified_at DATETIME NULL,
 updated_at DATETIME NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
