-- Etapa 3: clientes com prefixos dedicados (identificacao nos avisos e na investigacao).
CREATE TABLE IF NOT EXISTS orby_customers (
 id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 name VARCHAR(120) NOT NULL,
 code VARCHAR(40) NOT NULL DEFAULT '',            -- codigo do cliente no sistema de gestao
 contact VARCHAR(200) NOT NULL DEFAULT '',
 note VARCHAR(300) NOT NULL DEFAULT '',
 updated_by VARCHAR(64) NOT NULL DEFAULT '',
 updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
 UNIQUE KEY uq_customer_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS orby_customer_prefixes (
 customer_id INT UNSIGNED NOT NULL,
 cidr VARCHAR(49) CHARACTER SET ascii NOT NULL,
 PRIMARY KEY(customer_id,cidr),
 INDEX ix_customer_cidr (cidr)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
