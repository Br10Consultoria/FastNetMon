-- Execute dentro de um banco MariaDB/MySQL já criado para o OrbyMon.
-- Os usuários da aplicação devem ter somente INSERT/UPDATE/SELECT neste schema.
CREATE TABLE IF NOT EXISTS orby_alerts (
    alert_id CHAR(64) NOT NULL PRIMARY KEY,
    event_time DATETIME(6) NOT NULL,
    rule_name VARCHAR(160) NOT NULL,
    severity VARCHAR(30) NOT NULL,
    attack_kind VARCHAR(20) NOT NULL,
    src_ip VARCHAR(45) NULL,
    dst_ip VARCHAR(45) NULL,
    src_asn BIGINT UNSIGNED NULL,
    src_asn_name VARCHAR(255) NULL,
    src_country CHAR(2) NULL,
    dst_asn BIGINT UNSIGNED NULL,
    dst_asn_name VARCHAR(255) NULL,
    dst_country CHAR(2) NULL,
    src_latitude DECIMAL(9,6) NULL,
    src_longitude DECIMAL(9,6) NULL,
    dst_port INT UNSIGNED NULL,
    protocol VARCHAR(20) NULL,
    pps DOUBLE NOT NULL DEFAULT 0,
    mbps DOUBLE NOT NULL DEFAULT 0,
    unique_sources INT UNSIGNED NOT NULL DEFAULT 0,
    rps DOUBLE NOT NULL DEFAULT 0,
    group_data JSON NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX ix_alert_time (event_time),
    INDEX ix_alert_country_time (src_country, event_time),
    INDEX ix_alert_asn_time (src_asn, event_time),
    INDEX ix_alert_dst_time (dst_ip, event_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS orby_traffic_minute (
    bucket_utc DATETIME NOT NULL,
    src_asn BIGINT UNSIGNED NOT NULL DEFAULT 0,
    src_asn_name VARCHAR(255) NOT NULL DEFAULT '',
    src_country CHAR(2) NOT NULL DEFAULT '',
    dst_asn BIGINT UNSIGNED NOT NULL DEFAULT 0,
    dst_country CHAR(2) NOT NULL DEFAULT '',
    protocol VARCHAR(20) NOT NULL,
    dst_port INT UNSIGNED NOT NULL DEFAULT 0,
    total_packets DOUBLE NOT NULL DEFAULT 0,
    total_bytes DOUBLE NOT NULL DEFAULT 0,
    flow_records BIGINT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_utc, src_asn, src_country, dst_asn, dst_country, protocol, dst_port),
    INDEX ix_traffic_asn_time (src_asn, bucket_utc),
    INDEX ix_traffic_country_time (src_country, bucket_utc),
    INDEX ix_traffic_port_time (dst_port, bucket_utc)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
