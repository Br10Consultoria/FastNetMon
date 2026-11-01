-- F4 - deteccao bidirecional CGNAT-aware. Tabelas independentes das fases 1-3.

-- Rollup por minuto: direcao (in = internet->nossa rede, out = nossa rede->internet),
-- escopo do IP local, IP privado do assinante (quando conhecido) e portas de servico.
-- Portas efemeras sao gravadas como 0 (cardinalidade controlada); o IP privado e
-- resolvido pelo log NAT do A10 antes de zerar a porta.
CREATE TABLE IF NOT EXISTS orby_flow_minute (
 source VARCHAR(16) CHARACTER SET ascii NOT NULL,
 bucket_utc DATETIME NOT NULL,
 direction VARCHAR(3) CHARACTER SET ascii NOT NULL,
 scope VARCHAR(16) CHARACTER SET ascii NOT NULL,
 pool VARCHAR(64) NOT NULL DEFAULT '',
 local_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 subscriber_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
 remote_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 protocol VARCHAR(12) CHARACTER SET ascii NOT NULL,
 local_port SMALLINT UNSIGNED NOT NULL DEFAULT 0,
 remote_port SMALLINT UNSIGNED NOT NULL DEFAULT 0,
 input_if INT UNSIGNED NOT NULL DEFAULT 0,
 output_if INT UNSIGNED NOT NULL DEFAULT 0,
 packets DOUBLE NOT NULL DEFAULT 0,
 bytes DOUBLE NOT NULL DEFAULT 0,
 syn_packets DOUBLE NOT NULL DEFAULT 0,
 zero_port_packets DOUBLE NOT NULL DEFAULT 0,
 flows BIGINT UNSIGNED NOT NULL DEFAULT 0,
 PRIMARY KEY(source,bucket_utc,direction,scope,local_ip,subscriber_ip,remote_ip,
             protocol,local_port,remote_port,input_if,output_if),
 INDEX ix_flow_sub_time(subscriber_ip,bucket_utc),
 INDEX ix_flow_local_time(local_ip,bucket_utc),
 INDEX ix_flow_bucket(bucket_utc,direction,scope)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Migracao para instalacoes anteriores (idempotente no MariaDB).
ALTER TABLE orby_flow_minute ADD COLUMN IF NOT EXISTS zero_port_packets DOUBLE NOT NULL DEFAULT 0 AFTER syn_packets;

CREATE TABLE IF NOT EXISTS orby_flow_ingested_files (
 source VARCHAR(32) NOT NULL,
 file_name VARCHAR(255) NOT NULL,
 file_size BIGINT UNSIGNED NOT NULL,
 file_mtime_ns BIGINT UNSIGNED NOT NULL,
 flow_count BIGINT UNSIGNED NOT NULL,
 nat_resolved BIGINT UNSIGNED NOT NULL DEFAULT 0,
 nat_unresolved BIGINT UNSIGNED NOT NULL DEFAULT 0,
 ingested_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(source,file_name),
 INDEX ix_flow_ingested_at(ingested_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Metricas NAO amostradas vindas do log do A10 (receptor a10_nat).
CREATE TABLE IF NOT EXISTS orby_nat_user_minute (
 bucket_utc DATETIME NOT NULL,
 inside_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 allocs INT UNSIGNED NOT NULL DEFAULT 0,
 frees INT UNSIGNED NOT NULL DEFAULT 0,
 active_ports INT UNSIGNED NOT NULL DEFAULT 0,
 PRIMARY KEY(bucket_utc,inside_ip),
 INDEX ix_nat_user_ip_time(inside_ip,bucket_utc)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Eventos de ataque detectados (entrada e saida), prontos para consulta por IP.
CREATE TABLE IF NOT EXISTS orby_attack_events (
 event_id CHAR(64) NOT NULL PRIMARY KEY,
 event_time DATETIME NOT NULL,
 rule_name VARCHAR(100) NOT NULL,
 severity VARCHAR(16) NOT NULL,
 detection VARCHAR(8) NOT NULL,
 direction VARCHAR(3) NOT NULL,
 scope VARCHAR(16) NOT NULL,
 pool VARCHAR(64) NOT NULL DEFAULT '',
 local_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 subscriber_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
 protocol VARCHAR(12) NOT NULL DEFAULT '',
 local_port SMALLINT UNSIGNED NOT NULL DEFAULT 0,
 remote_port SMALLINT UNSIGNED NOT NULL DEFAULT 0,
 pps DOUBLE NOT NULL DEFAULT 0,
 mbps DOUBLE NOT NULL DEFAULT 0,
 remote_ips INT UNSIGNED NOT NULL DEFAULT 0,
 syn_ratio DOUBLE NOT NULL DEFAULT 0,
 input_if INT UNSIGNED NOT NULL DEFAULT 0,
 output_if INT UNSIGNED NOT NULL DEFAULT 0,
 details JSON NOT NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 INDEX ix_attack_time(event_time),
 INDEX ix_attack_sub_time(subscriber_ip,event_time),
 INDEX ix_attack_local_time(local_ip,event_time),
 INDEX ix_attack_dir_time(direction,event_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS orby_bidir_rule_state (
 source VARCHAR(32) NOT NULL,
 rule_name VARCHAR(100) NOT NULL,
 direction VARCHAR(3) NOT NULL,
 scope VARCHAR(16) NOT NULL,
 entity VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 protocol VARCHAR(12) NOT NULL DEFAULT '',
 local_port SMALLINT UNSIGNED NOT NULL DEFAULT 0,
 remote_port SMALLINT UNSIGNED NOT NULL DEFAULT 0,
 last_alert_utc DATETIME NULL,
 PRIMARY KEY(source,rule_name,direction,scope,entity,protocol,local_port,remote_port)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS orby_bidir_checks (
 source VARCHAR(32) NOT NULL PRIMARY KEY,
 last_checked_at DATETIME NOT NULL,
 latest_bucket_utc DATETIME NOT NULL,
 status VARCHAR(20) NOT NULL,
 signals INT UNSIGNED NOT NULL DEFAULT 0,
 alerts INT UNSIGNED NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Notificacoes (Telegram): marca de evento ja processado e incidentes abertos/encerrados.
ALTER TABLE orby_attack_events ADD COLUMN IF NOT EXISTS notified_at DATETIME NULL;
ALTER TABLE orby_attack_events ADD INDEX IF NOT EXISTS ix_attack_notify (notified_at, event_time);
CREATE TABLE IF NOT EXISTS orby_notify_incidents (
 incident_key CHAR(64) NOT NULL PRIMARY KEY,
 rule_name VARCHAR(100) NOT NULL,
 severity VARCHAR(16) NOT NULL,
 direction VARCHAR(3) NOT NULL,
 scope VARCHAR(16) NOT NULL,
 pool VARCHAR(64) NOT NULL DEFAULT '',
 local_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 subscriber_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
 protocol VARCHAR(12) NOT NULL DEFAULT '',
 first_seen DATETIME NOT NULL,
 last_seen DATETIME NOT NULL,
 events INT UNSIGNED NOT NULL DEFAULT 0,
 peak_bps DOUBLE NOT NULL DEFAULT 0,
 peak_pps DOUBLE NOT NULL DEFAULT 0,
 last_sent DATETIME NULL,
 closed_at DATETIME NULL,
 INDEX ix_notify_open (closed_at, last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
