-- Etapa 2: IPs do provedor em listas publicas de bloqueio e responsavel provavel (CGNAT).
SET NAMES utf8mb4;
CREATE TABLE IF NOT EXISTS orby_reputation_listings (
 entry VARCHAR(49) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 source VARCHAR(40) CHARACTER SET ascii NOT NULL,
 source_label VARCHAR(80) NOT NULL,
 category VARCHAR(200) NOT NULL,
 scope VARCHAR(16) CHARACTER SET ascii NOT NULL DEFAULT '',
 pool VARCHAR(64) NOT NULL DEFAULT '',
 first_seen DATETIME NOT NULL,
 last_seen DATETIME NOT NULL,
 removed_at DATETIME NULL,
 removal_hint VARCHAR(300) NOT NULL DEFAULT '',
 detail JSON NOT NULL,
 notified_at DATETIME NULL,
 removed_notified TINYINT(1) NOT NULL DEFAULT 0,
 PRIMARY KEY (entry, source),
 INDEX ix_rep_active (removed_at, entry),
 INDEX ix_rep_notify (notified_at, removed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS orby_reputation_sources (
 source VARCHAR(40) CHARACTER SET ascii NOT NULL PRIMARY KEY,
 last_run DATETIME NOT NULL,
 last_ok DATETIME NULL,
 entries INT UNSIGNED NOT NULL DEFAULT 0,
 matched INT UNSIGNED NOT NULL DEFAULT 0,
 status VARCHAR(10) NOT NULL,
 error VARCHAR(500) NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
