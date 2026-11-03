-- Uso de portas por IP publico do pool CGNAT, por minuto (foto da tabela NAT do receptor A10).
-- Uma linha por IP publico com portas em uso; capacidade = portas disponiveis por protocolo (padrao 64512).
-- Retencao: 7 dias (o proprio receptor limpa). Usada pelo dashboard "CGNAT - Portas" e pela pagina Saude.
CREATE TABLE IF NOT EXISTS orby_nat_public_minute (
 bucket_utc DATETIME NOT NULL,
 public_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 pool VARCHAR(64) NOT NULL DEFAULT '',
 tcp_ports INT UNSIGNED NOT NULL DEFAULT 0,
 udp_ports INT UNSIGNED NOT NULL DEFAULT 0,
 other_ports INT UNSIGNED NOT NULL DEFAULT 0,
 subscribers SMALLINT UNSIGNED NOT NULL DEFAULT 0,
 allocs INT UNSIGNED NOT NULL DEFAULT 0,
 capacity INT UNSIGNED NOT NULL DEFAULT 64512,
 PRIMARY KEY (bucket_utc, public_ip),
 INDEX ix_natpub_ip_time (public_ip, bucket_utc),
 INDEX ix_natpub_pool_time (pool, bucket_utc)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Assinantes com muitas portas abertas (>= 1000) a cada minuto: IP publico que estao usando, portas TCP/UDP e quanto
-- da capacidade daquele IP publico ocupam sozinhos (sem cota por assinante no A10, um so pode esgotar o IP).
CREATE TABLE IF NOT EXISTS orby_nat_heavy_minute (
 bucket_utc DATETIME NOT NULL,
 inside_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 public_ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 pool VARCHAR(64) NOT NULL DEFAULT '',
 tcp_ports INT UNSIGNED NOT NULL DEFAULT 0,
 udp_ports INT UNSIGNED NOT NULL DEFAULT 0,
 other_ports INT UNSIGNED NOT NULL DEFAULT 0,
 share_pct DECIMAL(6,2) NOT NULL DEFAULT 0,
 PRIMARY KEY (bucket_utc, inside_ip),
 INDEX ix_natheavy_ip_time (inside_ip, bucket_utc),
 INDEX ix_natheavy_pub_time (public_ip, bucket_utc)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
