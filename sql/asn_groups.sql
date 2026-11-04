-- Grupos de ASN/CDN ("favoritos") para o dashboard de trafego por grupo. Editaveis no painel (Grupos de ASN).
-- Membros: ASNs (15169 ou AS15169) e blocos IPv4 (ex.: caches de CDN dentro da operadora de transito).
SET NAMES utf8mb4;
CREATE TABLE IF NOT EXISTS orby_asn_groups (
 id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 name VARCHAR(64) NOT NULL UNIQUE,
 members TEXT NOT NULL,
 sort SMALLINT NOT NULL DEFAULT 100,
 builtin TINYINT(1) NOT NULL DEFAULT 0,
 updated_by VARCHAR(40) NOT NULL DEFAULT '',
 updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- gerada a partir de orby_asn_groups (fmn_filters.asn_groups); os blocos vao para orby_net_prefixes (kind='group')
CREATE TABLE IF NOT EXISTS orby_asn_group_members (
 asn BIGINT UNSIGNED NOT NULL PRIMARY KEY,
 name VARCHAR(64) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- modelos iniciais (so na primeira instalacao: INSERT IGNORE nao sobrescreve o que o usuario editou)
INSERT IGNORE INTO orby_asn_groups (name,members,sort,builtin) VALUES
('Google / YouTube','15169 36040 396982 19527 43515 36384',10,1),
('Meta (Facebook, Instagram, WhatsApp)','32934 63293 54115',20,1),
('Netflix','2906 40027 55095',30,1),
('TikTok / ByteDance','396986 138699',40,1),
('Amazon','16509 14618 8987',50,1),
('Akamai','20940 16625 12222 33905 32787 35994 21342',60,1),
('Cloudflare','13335 209242',70,1),
('Microsoft','8075 8068 12076',80,1),
('Apple','714 6185',90,1),
('Fastly','54113',100,1),
('Valve (Steam)','32590',110,1),
('Twitch','46489',120,1),
('Telegram','62041 62014 59930 44907 211157',130,1),
('CDN77','60068',140,1);
