"""Acesso ao MariaDB do painel (usuario proprio: le tudo, escreve so as tabelas do painel)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os

USER_FIELDS = ("id", "username", "pw_hash", "totp_secret", "totp_enabled", "totp_last_step",
               "must_change_password", "disabled", "created_at", "last_login")


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)


def connect():
    import pymysql
    env = os.environ
    for name in ("ORBYMON_ADMIN_DB_USER", "ORBYMON_ADMIN_DB_PASSWORD"):
        if not env.get(name):
            raise RuntimeError("variavel ausente: " + name)
    return pymysql.connect(host=env.get("ORBYMON_ADMIN_DB_HOST", "127.0.0.1"),
                           port=int(env.get("ORBYMON_ADMIN_DB_PORT", "3306")),
                           user=env["ORBYMON_ADMIN_DB_USER"], password=env["ORBYMON_ADMIN_DB_PASSWORD"],
                           database=env.get("ORBYMON_ADMIN_DB_NAME", "orbymon"), charset="utf8mb4",
                           autocommit=True, connect_timeout=5, read_timeout=30, write_timeout=30,
                           init_command="SET time_zone = '+00:00'")


class Store:
    def __init__(self, conn_factory=connect):
        self.conn_factory = conn_factory

    def _q(self, sql, params=(), one=False, fetch=True):
        db = self.conn_factory()
        try:
            with db.cursor() as cur:
                cur.execute(sql, params)
                if not fetch:
                    return cur.rowcount
                return cur.fetchone() if one else cur.fetchall()
        finally:
            db.close()

    # ---------- usuarios
    def user(self, username=None, uid=None):
        col, val = ("username", username) if username is not None else ("id", uid)
        row = self._q("SELECT " + ",".join(USER_FIELDS) + " FROM orby_admin_users WHERE " + col + "=%s",
                      (val,), one=True)
        return dict(zip(USER_FIELDS, row)) if row else None

    def users(self):
        return [dict(zip(USER_FIELDS, r)) for r in
                self._q("SELECT " + ",".join(USER_FIELDS) + " FROM orby_admin_users ORDER BY username")]

    def create_user(self, username, pw_hash, must_change=True):
        self._q("INSERT INTO orby_admin_users (username,pw_hash,must_change_password) VALUES (%s,%s,%s)",
                (username, pw_hash, int(must_change)), fetch=False)

    def set_password(self, uid, pw_hash, must_change=False):
        self._q("UPDATE orby_admin_users SET pw_hash=%s,must_change_password=%s WHERE id=%s",
                (pw_hash, int(must_change), uid), fetch=False)

    def set_totp(self, uid, secret, enabled):
        self._q("UPDATE orby_admin_users SET totp_secret=%s,totp_enabled=%s,totp_last_step=-1 WHERE id=%s",
                (secret, int(enabled), uid), fetch=False)

    def use_totp_step(self, uid, step):
        """Grava o passo usado; so aceita se for maior que o ultimo (sem reuso, mesmo entre processos)."""
        return self._q("UPDATE orby_admin_users SET totp_last_step=%s,last_login=%s WHERE id=%s AND totp_last_step<%s",
                       (step, utcnow(), uid, step), fetch=False) == 1

    def set_disabled(self, uid, disabled):
        self._q("UPDATE orby_admin_users SET disabled=%s WHERE id=%s", (int(disabled), uid), fetch=False)

    def delete_user(self, uid):
        self._q("DELETE FROM orby_admin_users WHERE id=%s", (uid,), fetch=False)

    # ---------- tentativas de login
    def fail(self, ip, username):
        self._q("INSERT INTO orby_admin_login_fail (ts,ip,username) VALUES (%s,%s,%s)",
                (utcnow(), ip, username[:40]), fetch=False)

    def fails(self, ip, username, minutes=15):
        since = utcnow() - timedelta(minutes=minutes)
        by_ip = self._q("SELECT COUNT(*) FROM orby_admin_login_fail WHERE ip=%s AND ts>=%s", (ip, since), one=True)[0]
        by_user = self._q("SELECT COUNT(*) FROM orby_admin_login_fail WHERE username=%s AND ts>=%s",
                          (username[:40], since), one=True)[0]
        return by_ip, by_user

    def clear_fails(self, username):
        self._q("DELETE FROM orby_admin_login_fail WHERE username=%s OR ts < %s",
                (username[:40], utcnow() - timedelta(days=7)), fetch=False)

    # ---------- auditoria
    def audit(self, username, ip, action, detail=""):
        self._q("INSERT INTO orby_admin_audit (ts,username,ip,action,detail) VALUES (%s,%s,%s,%s,%s)",
                (utcnow(), username, ip, action, detail[:20000]), fetch=False)

    def audit_list(self, limit=200):
        return self._q("SELECT ts,username,ip,action,detail FROM orby_admin_audit ORDER BY id DESC LIMIT %s", (limit,))

    # ---------- interfaces
    def interfaces(self):
        return self._q("SELECT if_index,if_name FROM orby_interface_names WHERE source='huawei' ORDER BY if_index")

    def seen_interfaces(self):
        """ifIndex vistos nos ultimos 60 min (entrada ou saida) com volume, para ajudar a escolher as bordas."""
        return self._q("""SELECT ifx,SUM(b) FROM (
SELECT input_if AS ifx,SUM(total_bytes) AS b FROM orby_ip_pairs_minute WHERE source='huawei'
 AND bucket_utc>=UTC_TIMESTAMP()-INTERVAL 60 MINUTE AND input_if>0 GROUP BY input_if
UNION ALL SELECT output_if,SUM(total_bytes) FROM orby_ip_pairs_minute WHERE source='huawei'
 AND bucket_utc>=UTC_TIMESTAMP()-INTERVAL 60 MINUTE AND output_if>0 GROUP BY output_if) t GROUP BY ifx""")

    def upsert_interface(self, if_index, name):
        self._q("""INSERT INTO orby_interface_names (source,if_index,if_name) VALUES ('huawei',%s,%s)
ON DUPLICATE KEY UPDATE if_name=VALUES(if_name)""", (if_index, name), fetch=False)

    def delete_interface(self, if_index):
        self._q("DELETE FROM orby_interface_names WHERE source='huawei' AND if_index=%s", (if_index,), fetch=False)

    # ---------- saude
    def health(self):
        out = {}
        for key, sql in (
                ("ultimo_fluxo_fase2", "SELECT MAX(bucket_utc) FROM orby_ip_pairs_minute WHERE source='huawei'"),
                ("ultimo_rollup_f4", "SELECT MAX(bucket_utc) FROM orby_flow_minute WHERE source='huawei'"),
                ("ultimo_detector", "SELECT last_checked_at FROM orby_bidir_checks WHERE source='huawei'"),
                ("ultimo_nat", "SELECT MAX(bucket_utc) FROM orby_nat_user_minute"),
                ("eventos_24h", "SELECT COUNT(*) FROM orby_attack_events WHERE event_time>=UTC_TIMESTAMP()-INTERVAL 1 DAY"),
                ("incidentes_abertos", "SELECT COUNT(*) FROM orby_notify_incidents WHERE closed_at IS NULL")):
            try:
                row = self._q(sql, one=True)
                out[key] = row[0] if row else None
            except Exception:
                out[key] = None
        return out

    def recent_events(self, limit=15):
        return self._q("""SELECT event_time,rule_name,severity,direction,local_ip,subscriber_ip,pps,mbps
FROM orby_attack_events ORDER BY event_time DESC LIMIT %s""", (limit,))

    # ---------- reputacao e investigacao (etapa 2)
    def reputation_listings(self, active=True, days=7):
        cond = "removed_at IS NULL" if active else "removed_at IS NOT NULL AND removed_at>=UTC_TIMESTAMP()-INTERVAL %s DAY"
        try:
            rows = self._q("SELECT entry,source_label,category,scope,pool,first_seen,last_seen,removed_at,removal_hint,detail "
                           "FROM orby_reputation_listings WHERE " + cond + " ORDER BY entry,source_label LIMIT 500",
                           () if active else (days,))
        except Exception:
            return []
        keys = ("entry", "lista", "categoria", "scope", "pool", "desde", "visto", "saiu", "remocao", "detail")
        return [dict(zip(keys, r)) for r in rows]

    def reputation_sources(self):
        try:
            return self._q("SELECT source,last_run,last_ok,entries,matched,status,error FROM orby_reputation_sources "
                           "ORDER BY status DESC,source")
        except Exception:
            return []

    def with_connection(self, fn):
        """Executa fn(conexao) e fecha (para as consultas da investigacao)."""
        db = self.conn_factory()
        try:
            return fn(db)
        finally:
            db.close()
