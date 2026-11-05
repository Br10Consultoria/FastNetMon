-- Analise automatica dos ataques detectados (fmn_filters.attack_analysis): vetor, origens, carpet bombing.
SET NAMES utf8mb4;
CREATE TABLE IF NOT EXISTS orby_attack_analysis (
 event_id CHAR(64) NOT NULL PRIMARY KEY,
 event_time DATETIME NOT NULL,
 direction VARCHAR(3) NOT NULL,
 local_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 subscriber_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
 rule_name VARCHAR(100) NOT NULL,
 vector VARCHAR(160) NOT NULL,
 main_vector VARCHAR(80) NOT NULL,
 summary VARCHAR(255) NOT NULL DEFAULT '',
 remote_ips INT UNSIGNED NOT NULL DEFAULT 0,
 top_asn BIGINT UNSIGNED NOT NULL DEFAULT 0,
 top_asn_name VARCHAR(80) NOT NULL DEFAULT '',
 top_country CHAR(2) NOT NULL DEFAULT '',
 bytes_per_packet INT UNSIGNED NOT NULL DEFAULT 0,
 fragment_share DOUBLE NOT NULL DEFAULT 0,
 block_ips_hit SMALLINT UNSIGNED NOT NULL DEFAULT 0,
 details JSON NOT NULL,
 analyzed_at DATETIME NOT NULL,
 notified_at DATETIME NULL,
 INDEX ix_analysis_time (event_time),
 INDEX ix_analysis_target (local_ip, direction, rule_name, notified_at),
 INDEX ix_analysis_vector (main_vector, event_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
