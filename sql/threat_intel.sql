-- C2 e botnets: clientes conversando com IPs de listas publicas de ameacas (fmn_filters.threat_intel).
SET NAMES utf8mb4;
CREATE TABLE IF NOT EXISTS orby_threat_hits (
 cpe_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,     -- assinante (CGNAT) ou IP do cliente
 remote_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,  -- IP listado
 protocol VARCHAR(12) CHARACTER SET ascii NOT NULL,
 remote_port SMALLINT UNSIGNED NOT NULL DEFAULT 0,
 public_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
 scope VARCHAR(16) NOT NULL DEFAULT '',
 pool VARCHAR(64) NOT NULL DEFAULT '',
 category VARCHAR(12) NOT NULL,                                          -- bot | reputacao
 sources VARCHAR(255) NOT NULL DEFAULT '',
 listed_port SMALLINT UNSIGNED NOT NULL DEFAULT 0,
 malware VARCHAR(120) NOT NULL DEFAULT '',
 first_seen DATETIME NOT NULL,
 last_seen DATETIME NOT NULL,
 flows BIGINT UNSIGNED NOT NULL DEFAULT 0,
 packets DOUBLE NOT NULL DEFAULT 0,
 bytes DOUBLE NOT NULL DEFAULT 0,
 PRIMARY KEY (cpe_ip, remote_ip, protocol, remote_port),
 INDEX ix_threat_last (last_seen),
 INDEX ix_threat_cat_last (category, last_seen),
 INDEX ix_threat_remote (remote_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS orby_threat_sources (
 name VARCHAR(32) NOT NULL PRIMARY KEY,
 label VARCHAR(80) NOT NULL,
 category VARCHAR(12) NOT NULL,
 last_run DATETIME NULL,
 last_ok DATETIME NULL,
 entries INT UNSIGNED NOT NULL DEFAULT 0,
 status VARCHAR(8) NOT NULL DEFAULT '',
 error VARCHAR(255) NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
