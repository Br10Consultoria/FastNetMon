-- Observed Huawei ifIndex names verified by operator / SNMP read-only.
-- Never guess names for an index or assume 0 corresponds to a physical port.
CREATE TABLE IF NOT EXISTS orby_interface_names (
 source VARCHAR(32) NOT NULL,
 if_index BIGINT UNSIGNED NOT NULL,
 if_name VARCHAR(128) NOT NULL,
 updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
 PRIMARY KEY (source,if_index)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
