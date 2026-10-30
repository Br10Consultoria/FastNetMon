-- Fase 3: alertas passivos sao gravados em orby_alerts.
CREATE TABLE IF NOT EXISTS orby_ddos_rule_state (
 source VARCHAR(32) NOT NULL,
 rule_name VARCHAR(100) NOT NULL,
 dst_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 protocol VARCHAR(20) NOT NULL,
 dst_port SMALLINT UNSIGNED NOT NULL DEFAULT 0,
 input_if INT UNSIGNED NOT NULL DEFAULT 0,
 output_if INT UNSIGNED NOT NULL DEFAULT 0,
 netflow_direction SMALLINT NOT NULL DEFAULT -1,
 last_alert_utc DATETIME NULL,
 PRIMARY KEY(source,rule_name,dst_ip,protocol,dst_port,input_if,output_if,netflow_direction)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS orby_ddos_checks (
 source VARCHAR(32) NOT NULL PRIMARY KEY,
 last_checked_at DATETIME NOT NULL,
 latest_bucket_utc DATETIME NOT NULL,
 status VARCHAR(20) NOT NULL,
 signals INT UNSIGNED NOT NULL DEFAULT 0,
 alerts INT UNSIGNED NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
