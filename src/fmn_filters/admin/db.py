"""Acesso ao MariaDB do painel (usuario proprio: le tudo, escreve so as tabelas do painel)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
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

    # ---------- mitigacao
    MIT_KEYS = ("id", "ip", "prefix", "status", "origin", "rule_name", "reason", "peak_mbps", "peak_pps", "duration_min",
                "created_at", "requested_by", "decided_by", "decided_at", "announced_at", "last_seen_at", "expires_at",
                "ended_at", "error")

    def mitigations(self, limit=80):
        try:
            rows = self._q("SELECT " + ",".join(self.MIT_KEYS) + " FROM orby_mitigations ORDER BY "
                           "FIELD(status,'simulated','withdrawing','active','approved','proposed') DESC, id DESC LIMIT %s",
                           (limit,))
        except Exception:
            return None
        return [dict(zip(self.MIT_KEYS, r)) for r in rows]

    def mitigation_status(self):
        try:
            return {r[0]: (r[1], r[2]) for r in self._q("SELECT name,value,updated_at FROM orby_mitigation_status")}
        except Exception:
            return {}

    def mitigation_create(self, ip, prefix, status, origin, reason, duration, user):
        return self._q("INSERT INTO orby_mitigations (ip,prefix,status,origin,reason,duration_min,created_at,last_seen_at,"
                       "expires_at,requested_by,decided_by,decided_at) VALUES (%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP(),"
                       "UTC_TIMESTAMP(),UTC_TIMESTAMP()+INTERVAL %s MINUTE,%s,%s,UTC_TIMESTAMP())",
                       (ip, prefix, status, origin, reason[:300], duration, duration, user, user), fetch=False)

    def mitigation_decide(self, mid, from_status, to_status, user):
        """Muda o estado so se ainda estiver no estado esperado (dois operadores ao mesmo tempo)."""
        ended = ", ended_at=UTC_TIMESTAMP()" if to_status in ("rejected", "ended") else ""
        return self._q("UPDATE orby_mitigations SET status=%s,decided_by=%s,decided_at=UTC_TIMESTAMP()" + ended +
                       " WHERE id=%s AND status=%s", (to_status, user, mid, from_status), fetch=False)

    # ---------- clientes
    def customers(self):
        try:
            rows = self._q("SELECT c.id,c.name,c.code,c.contact,c.note,c.updated_by,c.updated_at,"
                           "GROUP_CONCAT(p.cidr ORDER BY p.cidr SEPARATOR ' ') FROM orby_customers c LEFT JOIN "
                           "orby_customer_prefixes p ON p.customer_id=c.id GROUP BY c.id ORDER BY c.name")
        except Exception:
            return None
        keys = ("id", "name", "code", "contact", "note", "updated_by", "updated_at", "prefixes")
        return [dict(zip(keys, r), prefixes=(r[7] or "").split()) for r in rows]

    def save_customer(self, cid, c, user):
        db = self.conn_factory()
        try:
            with db.cursor() as cur:
                if cid:
                    cur.execute("UPDATE orby_customers SET name=%s,code=%s,contact=%s,note=%s,updated_by=%s WHERE id=%s",
                                (c["name"], c["code"], c["contact"], c["note"], user, cid))
                else:
                    cur.execute("INSERT INTO orby_customers (name,code,contact,note,updated_by) VALUES (%s,%s,%s,%s,%s)",
                                (c["name"], c["code"], c["contact"], c["note"], user))
                    cid = cur.lastrowid
                cur.execute("DELETE FROM orby_customer_prefixes WHERE customer_id=%s", (cid,))
                for cidr in c["prefixes"]:
                    cur.execute("INSERT INTO orby_customer_prefixes (customer_id,cidr) VALUES (%s,%s)", (cid, cidr))
            db.commit()
            return cid
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def delete_customer(self, cid):
        db = self.conn_factory()
        try:
            with db.cursor() as cur:
                cur.execute("DELETE FROM orby_customer_prefixes WHERE customer_id=%s", (cid,))
                n = cur.execute("DELETE FROM orby_customers WHERE id=%s", (cid,))
            db.commit()
            return n
        finally:
            db.close()

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

    # ---------- filtros salvos (Analise avancada)
    def saved_filters(self):
        try:
            rows = self._q("SELECT id,name,expr,description,category,builtin,created_by FROM orby_saved_filters "
                           "ORDER BY builtin DESC,category,name")
        except Exception:
            return []
        keys = ("id", "name", "expr", "description", "category", "builtin", "created_by")
        return [dict(zip(keys, r)) for r in rows]

    def save_filter(self, name, expr, description, user):
        self._q("""INSERT INTO orby_saved_filters (name,expr,description,category,builtin,created_by)
VALUES (%s,%s,%s,'Meus filtros',0,%s) ON DUPLICATE KEY UPDATE expr=IF(builtin=0,VALUES(expr),expr),
description=IF(builtin=0,VALUES(description),description)""", (name, expr, description, user), fetch=False)

    def delete_filter(self, fid):
        return self._q("DELETE FROM orby_saved_filters WHERE id=%s AND builtin=0", (fid,), fetch=False)

    # ---------- blocos do provedor para os dashboards
    def sync_prefixes(self, cfg, profile):
        from ..net_prefixes import sync
        db = self.conn_factory()
        try:
            return sync(db, cfg, profile)
        finally:
            db.close()

    # ---------- saude
    def health_items(self):
        try:
            rows = self._q("SELECT check_key,label,status,value,detail,since,updated_at FROM orby_health "
                           "ORDER BY FIELD(status,'crit','warn','unknown','ok'),check_key")
        except Exception:
            return None
        keys = ("key", "label", "status", "value", "detail", "since", "updated_at")
        return [dict(zip(keys, r)) for r in rows]

    # ---------- excecoes e linha de base
    def exceptions(self):
        try:
            rows = self._q("SELECT id,kind,value,side,direction,rule_name,action,factor,note,expires_at,prefixes,"
                           "synced_at,sync_error,created_by,updated_at FROM orby_exceptions ORDER BY kind,value")
        except Exception:
            return []
        keys = ("id", "kind", "value", "side", "direction", "rule_name", "action", "factor", "note", "expires_at",
                "prefixes", "synced_at", "sync_error", "created_by", "updated_at")
        return [dict(zip(keys, r)) for r in rows]

    def save_exception(self, e, user):
        """Insere (ou renova) uma excecao ja validada. Devolve o id."""
        db = self.conn_factory()
        try:
            with db.cursor() as cur:
                expires = ("UTC_TIMESTAMP() + INTERVAL %d DAY" % int(e["days"])) if e["days"] else "NULL"
                cur.execute("INSERT INTO orby_exceptions (kind,value,side,direction,rule_name,action,factor,note,"
                            "expires_at,created_by) VALUES (%s,%s,%s,%s,%s,%s,%s,%s," + expires + ",%s) "
                            "ON DUPLICATE KEY UPDATE factor=VALUES(factor),note=VALUES(note),"
                            "expires_at=VALUES(expires_at),created_by=VALUES(created_by)",
                            (e["kind"], e["value"], e["side"], e["direction"], e["rule_name"], e["action"],
                             e["factor"], e["note"], user))
                cur.execute("SELECT id FROM orby_exceptions WHERE kind=%s AND value=%s AND side=%s AND direction=%s "
                            "AND rule_name=%s AND action=%s", (e["kind"], e["value"], e["side"], e["direction"],
                                                               e["rule_name"], e["action"]))
                eid = cur.fetchone()[0]
            db.commit()
            return eid
        finally:
            db.close()

    def delete_exception(self, eid):
        db = self.conn_factory()
        try:
            with db.cursor() as cur:
                cur.execute("DELETE FROM orby_exception_prefixes WHERE exception_id=%s", (eid,))
                n = cur.execute("DELETE FROM orby_exceptions WHERE id=%s", (eid,))
            db.commit()
            return n
        finally:
            db.close()

    def sync_exception(self, eid):
        """Busca os prefixos do ASN agora (RIPEstat). Devolve a mensagem de resultado."""
        from ..exceptions import sync
        out = []
        self.with_connection(lambda db: sync(db, only_id=eid, log=out.append))
        return "; ".join(out)

    def baseline_table(self):
        from ..baseline import load
        return self.with_connection(lambda db: load(db.cursor()))

    def filter_rule_usual(self, rid, minute, days):
        from ..filter_rules import usual_samples
        return self.with_connection(lambda db: usual_samples(db.cursor(), rid, minute, days))

    # ---------- alarmes por filtro
    def filter_rules(self):
        try:
            rows = self._q("""SELECT r.id,r.name,r.enabled,r.severity,r.direction,r.expr,r.definition,r.builtin,
 s.status,s.last_bucket,s.last_bps,s.last_pps,s.last_flows,s.last_error,
 (SELECT COUNT(*) FROM orby_filter_incidents i WHERE i.rule_id=r.id AND i.started_at>=UTC_TIMESTAMP()-INTERVAL 7 DAY)
 FROM orby_filter_rules r LEFT JOIN orby_filter_rule_state s ON s.rule_id=r.id ORDER BY r.enabled DESC,r.name""")
        except Exception:
            return []
        keys = ("id", "name", "enabled", "severity", "direction", "expr", "definition", "builtin", "status",
                "last_bucket", "last_bps", "last_pps", "last_flows", "last_error", "incidents_7d")
        out = []
        for r in rows:
            item = dict(zip(keys, r))
            d = item["definition"]
            item["definition"] = json.loads(d) if isinstance(d, (str, bytes)) else d
            out.append(item)
        return out

    def filter_rule(self, rid):
        return next((r for r in self.filter_rules() if r["id"] == rid), None)

    def save_filter_rule(self, rid, name, enabled, severity, direction, expr, definition, user):
        data = json.dumps(definition, ensure_ascii=False)
        if rid:
            self._q("""UPDATE orby_filter_rules SET name=%s,enabled=%s,severity=%s,direction=%s,expr=%s,definition=%s,
 updated_by=%s WHERE id=%s""", (name, int(enabled), severity, direction, expr, data, user, rid), fetch=False)
            return rid
        db = self.conn_factory()
        try:
            with db.cursor() as cur:
                cur.execute("""INSERT INTO orby_filter_rules (name,enabled,severity,direction,expr,definition,updated_by)
 VALUES (%s,%s,%s,%s,%s,%s,%s)""", (name, int(enabled), severity, direction, expr, data, user))
                return cur.lastrowid
        finally:
            db.close()

    def set_filter_rule_enabled(self, rid, enabled):
        self._q("UPDATE orby_filter_rules SET enabled=%s WHERE id=%s", (int(enabled), rid), fetch=False)

    def delete_filter_rule(self, rid):
        return self._q("DELETE FROM orby_filter_rules WHERE id=%s", (rid,), fetch=False)

    def filter_rule_samples(self, rid, hours=6):
        rows = self._q("SELECT bucket_utc,bps,pps,flows,bpp,matched FROM orby_filter_rule_samples WHERE rule_id=%s "
                       "AND bucket_utc>=UTC_TIMESTAMP()-INTERVAL %s HOUR ORDER BY bucket_utc", (rid, hours))
        return [{"t": r[0], "bps": r[1], "pps": r[2], "flows": r[3], "bpp": r[4], "matched": bool(r[5])} for r in rows]

    def filter_incidents(self, rid=None, limit=50):
        try:
            rows = self._q("SELECT id,rule_id,rule_name,severity,status,started_at,last_match_at,resolved_at,peak_bps,"
                           "peak_pps,peak_flows,matches,top FROM orby_filter_incidents" +
                           (" WHERE rule_id=%s" if rid else "") +
                           " ORDER BY status='resolved',started_at DESC LIMIT %s", ((rid, limit) if rid else (limit,)))
        except Exception:
            return []
        keys = ("id", "rule_id", "rule_name", "severity", "status", "started_at", "last_match_at", "resolved_at",
                "peak_bps", "peak_pps", "peak_flows", "matches", "top")
        out = []
        for r in rows:
            item = dict(zip(keys, r))
            t = item["top"]
            item["top"] = json.loads(t) if isinstance(t, (str, bytes)) else (t or [])
            out.append(item)
        return out
