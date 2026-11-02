-- Agregados do rollup para os dashboards: evitam varrer orby_flow_minute (uma linha por par local x remoto x
-- portas x interfaces) em periodos longos. Mantidos pelo orbymon-flow-rollup no mesmo commit de cada arquivo.

-- Totais por minuto, sentido, tipo de IP, protocolo e interface de borda (pequena: guarda 90 dias).
CREATE TABLE IF NOT EXISTS orby_flow_agg_minute (
 source VARCHAR(16) CHARACTER SET ascii NOT NULL,
 bucket_utc DATETIME NOT NULL,
 direction VARCHAR(3) CHARACTER SET ascii NOT NULL,
 scope VARCHAR(16) CHARACTER SET ascii NOT NULL,
 protocol VARCHAR(12) CHARACTER SET ascii NOT NULL,
 edge_if INT UNSIGNED NOT NULL DEFAULT 0,               -- entrada (recebido) ou saida (originado)
 packets DOUBLE NOT NULL DEFAULT 0, bytes DOUBLE NOT NULL DEFAULT 0,
 syn_packets DOUBLE NOT NULL DEFAULT 0, zero_port_packets DOUBLE NOT NULL DEFAULT 0,
 flows BIGINT UNSIGNED NOT NULL DEFAULT 0,
 PRIMARY KEY(source,bucket_utc,direction,scope,protocol,edge_if)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Por minuto e IP da rede (publico/pool e assinante): rankings de pico e CGNAT (guarda 4 dias).
CREATE TABLE IF NOT EXISTS orby_flow_ip_minute (
 source VARCHAR(16) CHARACTER SET ascii NOT NULL,
 bucket_utc DATETIME NOT NULL,
 direction VARCHAR(3) CHARACTER SET ascii NOT NULL,
 scope VARCHAR(16) CHARACTER SET ascii NOT NULL,
 local_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 subscriber_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
 pool VARCHAR(64) NOT NULL DEFAULT '',
 packets DOUBLE NOT NULL DEFAULT 0, bytes DOUBLE NOT NULL DEFAULT 0, flows BIGINT UNSIGNED NOT NULL DEFAULT 0,
 remotes INT UNSIGNED NOT NULL DEFAULT 0,               -- IPs remotos distintos (maior entre os arquivos do minuto)
 PRIMARY KEY(source,bucket_utc,direction,scope,local_ip,subscriber_ip),
 INDEX ix_ipmin_local (local_ip,bucket_utc),
 INDEX ix_ipmin_sub (subscriber_ip,bucket_utc)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Por 5 minutos, protocolo e portas de servico (pequena: guarda 30 dias).
CREATE TABLE IF NOT EXISTS orby_flow_port_5m (
 source VARCHAR(16) CHARACTER SET ascii NOT NULL,
 bucket_utc DATETIME NOT NULL,
 direction VARCHAR(3) CHARACTER SET ascii NOT NULL,
 protocol VARCHAR(12) CHARACTER SET ascii NOT NULL,
 local_port SMALLINT UNSIGNED NOT NULL DEFAULT 0, remote_port SMALLINT UNSIGNED NOT NULL DEFAULT 0,
 packets DOUBLE NOT NULL DEFAULT 0, bytes DOUBLE NOT NULL DEFAULT 0,
 zero_port_packets DOUBLE NOT NULL DEFAULT 0, flows BIGINT UNSIGNED NOT NULL DEFAULT 0,
 PRIMARY KEY(source,bucket_utc,direction,protocol,local_port,remote_port)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Por 5 minutos e IP remoto (quem ataca ou e atacado; guarda 4 dias).
CREATE TABLE IF NOT EXISTS orby_flow_remote_5m (
 source VARCHAR(16) CHARACTER SET ascii NOT NULL,
 bucket_utc DATETIME NOT NULL,
 direction VARCHAR(3) CHARACTER SET ascii NOT NULL,
 protocol VARCHAR(12) CHARACTER SET ascii NOT NULL,
 remote_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 packets DOUBLE NOT NULL DEFAULT 0, bytes DOUBLE NOT NULL DEFAULT 0, flows BIGINT UNSIGNED NOT NULL DEFAULT 0,
 locals INT UNSIGNED NOT NULL DEFAULT 0,                -- IPs nossos envolvidos (maior entre os arquivos)
 PRIMARY KEY(source,bucket_utc,direction,protocol,remote_ip),
 INDEX ix_rem5_ip (remote_ip,bucket_utc)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
