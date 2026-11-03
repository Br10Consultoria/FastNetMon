"""Saude do OrbyFlow: coleta, atrasos, disco, servicos e tempo de execucao dos timers.

Roda a cada 2 minutos (orbymon-health.timer), grava o resultado em orby_health (pagina Saude do painel) e avisa no
Telegram quando um item passa a ter problema (depois de 2 verificacoes seguidas, para nao avisar por oscilacao),
quando volta ao normal e, se continuar critico, a cada 2 horas.

    python -m fmn_filters.health --config /etc/orbymon/bidir.json [--telegram-env /etc/orbymon/telegram.env]
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import html
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

OK, WARN, CRIT, UNKNOWN = "ok", "warn", "crit", "unknown"
RANK = {OK: 0, UNKNOWN: 1, WARN: 2, CRIT: 3}
LABEL = {OK: "normal", WARN: "atenção", CRIT: "crítico", UNKNOWN: "sem dados"}
CONFIRM_RUNS = 2
REMIND = timedelta(hours=2)
DISK_PATHS = ("/", "/var/lib/orbymon", "/var/log/orbymon", "/var/lib/mysql")
# unidade -> (intervalo do timer em s, atencao a partir de, critico a partir de) em segundos de execucao
RUNTIME = {
    "orbymon-flow-rollup-huawei.service": (30, 40, 90),
    "orbymon-bidir-huawei.service": (60, 45, 90),
    "orbymon-filter-rules.service": (60, 45, 100),
    "orbymon-ip-huawei.service": (60, 45, 90),
    "orbymon-traffic-huawei.service": (60, 45, 90),
    "orbymon-ddos-huawei.service": (60, 45, 90),
    "orbymon-telegram.service": (30, 30, 90),
    "orbymon-backup.service": (86400, 900, 1800),
}


def item(key, label, status, value="", detail=""):
    return {"key": key, "label": label, "status": status, "value": value, "detail": detail}


def lag_status(age, warn, crit):
    if age is None:
        return UNKNOWN
    return CRIT if age >= crit else WARN if age >= warn else OK


def fmt_age(seconds):
    if seconds is None:
        return "—"
    seconds = int(seconds)
    if seconds < 120:
        return "%d s" % seconds
    if seconds < 7200:
        return "%d min" % (seconds // 60)
    if seconds < 172800:
        return "%.1f h" % (seconds / 3600)
    return "%.1f dias" % (seconds / 86400)


# ------------------------------------------------------------------ verificacoes sem banco
def check_nfcapd(flow_dir, now_ts=None):
    now_ts = now_ts or time.time()
    newest = None
    try:
        with os.scandir(flow_dir) as it:
            for e in it:
                if e.name.startswith("nfcapd.20") and e.is_file():
                    m = e.stat().st_mtime
                    newest = m if newest is None or m > newest else newest
    except OSError as exc:
        return item("nfcapd", "Coleta NetStream (nfcapd)", CRIT, "diretório inacessível", str(exc)[:200])
    age = None if newest is None else max(0.0, now_ts - newest)
    st = lag_status(age, 120, 300) if newest is not None else CRIT
    return item("nfcapd", "Coleta NetStream (nfcapd)", st, "último arquivo há %s" % fmt_age(age),
                "" if st == OK else "o roteador parou de exportar ou o nfcapd parou (%s)" % flow_dir)


BACKUP_DIR = "/var/lib/orbymon/backups"


def latest_backups(directory=BACKUP_DIR):
    """[(nome, tamanho, mtime)] dos backups, mais recente primeiro (lista o diretorio; nao le os arquivos)."""
    out = []
    with os.scandir(directory) as it:
        for e in it:
            if e.name.startswith("orbymon-backup-") and (e.name.endswith(".tar.gz") or e.name.endswith(".tar.gz.enc")):
                st = e.stat()
                out.append((e.name, st.st_size, st.st_mtime))
    return sorted(out, key=lambda x: -x[2])


def check_backup(directory=BACKUP_DIR, now_ts=None):
    label = "Backup diário"
    if not os.path.isdir(directory):
        return item("backup", label, WARN, "não instalado", "rode sudo bash scripts/setup-backup.sh")
    files = latest_backups(directory)
    if not files:
        return item("backup", label, WARN, "nenhum backup ainda", "veja journalctl -u orbymon-backup -n 30")
    age = (now_ts or time.time()) - files[0][2]
    st = CRIT if age > 4 * 86400 else WARN if age > 36 * 3600 else OK
    return item("backup", label, st, "último há %s (%d arquivo(s)%s)" % (
        fmt_age(age), len(files), ", cifrado" if files[0][0].endswith(".enc") else ""),
        "" if st == OK else "o backup diário não está rodando: veja journalctl -u orbymon-backup -n 30")


def check_disks(paths=DISK_PATHS, usage=shutil.disk_usage, stat=os.stat):
    out, seen = [], set()
    for p in paths:
        try:
            dev = stat(p).st_dev
        except OSError:
            continue
        if dev in seen:
            continue
        seen.add(dev)
        u = usage(p)
        pct = 100.0 * u.used / u.total if u.total else 0.0
        st = CRIT if pct >= 93 else WARN if pct >= 85 else OK
        out.append(item("disk:" + p, "Disco %s" % p, st, "%.0f%% usado · %.1f GB livres" % (pct, u.free / 1e9),
                        "" if st == OK else "reduza a retenção (página Retenção) ou amplie o disco"))
    return out


def _systemctl(args, timeout=10):
    try:
        return subprocess.run(["systemctl"] + args, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return None


def check_failed_units(run=_systemctl):
    out = run(["list-units", "orbymon-*", "--state=failed", "--plain", "--no-legend", "--no-pager"])
    if out is None:
        return item("services", "Serviços", UNKNOWN, "systemctl indisponível")
    failed = [line.split()[0] for line in out.splitlines() if line.strip()]
    if failed:
        return item("services", "Serviços", CRIT, "%d com falha" % len(failed),
                    ", ".join(failed[:8]) + " — veja journalctl -u <serviço> -n 50")
    return item("services", "Serviços", OK, "nenhum com falha")


def parse_show(text):
    return dict(line.split("=", 1) for line in (text or "").splitlines() if "=" in line)


def check_runtimes(units=RUNTIME, run=_systemctl):
    out = []
    for unit, (interval, warn, crit) in units.items():
        props = parse_show(run(["show", unit, "--property=LoadState,ExecMainStartTimestampMonotonic,"
                                "ExecMainExitTimestampMonotonic,ActiveState"]))
        if props.get("LoadState") != "loaded":
            continue
        try:
            start = int(props.get("ExecMainStartTimestampMonotonic") or 0)
            end = int(props.get("ExecMainExitTimestampMonotonic") or 0)
        except ValueError:
            continue
        if not start:
            continue
        name = unit.replace("orbymon-", "").replace(".service", "")
        if end < start:                              # ainda rodando: mede ate agora
            if props.get("ActiveState") not in ("activating", "active"):
                continue
            now = _monotonic_us(run)
            if now is None:
                continue
            dur, running = (now - start) / 1e6, True
        else:
            dur, running = (end - start) / 1e6, False
        st = CRIT if dur >= crit else WARN if dur >= warn else OK
        out.append(item("runtime:" + name, "Tempo de execução: %s" % name, st,
                        "%.1f s%s (timer de %d s)" % (dur, " em andamento" if running else "", interval),
                        "" if st == OK else "a execução está demorando perto ou além do intervalo: os dados atrasam"))
    return out


def _monotonic_us(run):
    try:
        return int(time.clock_gettime(time.CLOCK_MONOTONIC) * 1e6)
    except (AttributeError, OSError):
        return None


# ------------------------------------------------------------------ verificacoes no banco
def _one(cur, sql, params=()):
    try:
        cur.execute(sql, params)
        row = cur.fetchone()
        return row[0] if row else None
    except Exception:
        return None


def _age(now, when):
    return None if when is None else max(0.0, (now - when).total_seconds())


NAT_PORTS_WARN = float(os.environ.get("ORBYMON_NAT_PORTS_WARN", "80"))
NAT_PORTS_CRIT = float(os.environ.get("ORBYMON_NAT_PORTS_CRIT", "95"))


def check_nat_ports(cur, now):
    """Esgotamento de portas por IP publico do pool CGNAT (ultimo minuto gravado pelo receptor A10)."""
    try:
        cur.execute("SELECT public_ip,pool,tcp_ports,udp_ports,subscribers,capacity,bucket_utc FROM "
                    "orby_nat_public_minute WHERE bucket_utc=(SELECT MAX(bucket_utc) FROM orby_nat_public_minute "
                    "WHERE bucket_utc>=%s - INTERVAL 15 MINUTE) ORDER BY GREATEST(tcp_ports,udp_ports) DESC LIMIT 5",
                    (now,))
        rows = cur.fetchall()
    except Exception:
        return []                                 # tabela ainda nao instalada (setup-cgnat-ports.sh)
    if not rows:
        return []
    def pct(r):
        return 100.0 * max(int(r[2]), int(r[3])) / max(1, int(r[5]))
    worst = rows[0]
    p = pct(worst)
    hot = [r for r in rows if pct(r) >= NAT_PORTS_WARN]
    st = CRIT if p >= NAT_PORTS_CRIT else WARN if p >= NAT_PORTS_WARN else OK
    proto = "TCP" if int(worst[2]) >= int(worst[3]) else "UDP"
    detail = ""
    if st != OK:
        culprits = {}
        try:                                   # quem esta ocupando o IP (assinante pesado no mesmo minuto)
            ph = ",".join(["%s"] * len(hot))
            cur.execute("SELECT public_ip,inside_ip,GREATEST(tcp_ports,udp_ports),share_pct FROM orby_nat_heavy_minute "
                        "WHERE bucket_utc=%s AND public_ip IN (" + ph + ") ORDER BY share_pct DESC",
                        [worst[6]] + [r[0] for r in hot])
            for pub, inside, n, share in cur.fetchall():
                culprits.setdefault(pub, (inside, int(n), float(share)))
        except Exception:
            pass
        def who(r):
            c = culprits.get(r[0])
            return (" — assinante %s com %d portas (%.0f%% do IP)" % c) if c else ""
        detail = ("IPs públicos perto do limite: " + "; ".join("%s (%s) %.0f%%, %d assinantes%s" % (
            r[0], r[1] or "?", pct(r), int(r[4]), who(r)) for r in hot) +
                  ". Novas conexões dos outros assinantes desse IP podem falhar: veja o dashboard CGNAT - Assinantes.")
    return [item("cgnat_ports", "CGNAT: portas por IP público", st,
                 "maior uso %.0f%% (%s %s, %s, %d assinantes)" % (p, worst[0], proto, worst[1] or "?", int(worst[4])),
                 detail)]


def check_db(cur, cfg, now, telegram_on=False, a10_on=True):
    src = cfg["source"]
    out = []
    last = _one(cur, "SELECT MAX(bucket_utc) FROM orby_flow_minute WHERE source=%s", (src,))
    age = _age(now, last)
    st = lag_status(age, 300, 900)
    out.append(item("rollup", "Rollup dos fluxos (orby_flow_minute)", st, "último minuto há %s" % fmt_age(age),
                    "" if st == OK else "veja journalctl -u orbymon-flow-rollup-huawei -n 50"))
    checked = _one(cur, "SELECT last_checked_at FROM orby_bidir_checks WHERE source=%s", (src,))
    age = _age(now, checked)
    st = lag_status(age, 180, 600) if cfg.get("enabled") else OK
    out.append(item("detector", "Detector bidirecional", st,
                    ("última execução há %s" % fmt_age(age)) if cfg.get("enabled") else "desativado na configuração",
                    "" if st == OK else "veja journalctl -u orbymon-bidir-huawei -n 50"))
    if a10_on:
        nat = _one(cur, "SELECT MAX(bucket_utc) FROM orby_nat_user_minute")
        age = _age(now, nat)
        st = lag_status(age, 300, 900)
        out.append(item("nat", "Log NAT do A10", st, "último minuto há %s" % fmt_age(age),
                        "" if st == OK else "sem o log NAT não há identificação do assinante (orbymon-a10-nat)"))
        res = None
        try:
            cur.execute("SELECT SUM(nat_resolved),SUM(nat_unresolved) FROM orby_flow_ingested_files "
                        "WHERE source=%s AND ingested_at>=UTC_TIMESTAMP()-INTERVAL 1 HOUR", (src,))
            res = cur.fetchone()
        except Exception:
            pass
        ok_n, bad_n = (float(res[0] or 0), float(res[1] or 0)) if res else (0.0, 0.0)   # SUM vem como Decimal
        if ok_n + bad_n > 0:
            pct = 100.0 * ok_n / (ok_n + bad_n)
            st = WARN if pct < 50 else OK
            out.append(item("nat_resolve", "Fluxos de pool com assinante identificado (1 h)", st, "%.0f%%" % pct,
                            "" if st == OK else "o log NAT está incompleto ou atrasado em relação aos fluxos"))
    if a10_on:
        out += check_nat_ports(cur, now)
    try:
        cur.execute("SELECT r.name,s.last_bucket,s.last_error FROM orby_filter_rules r LEFT JOIN "
                    "orby_filter_rule_state s ON s.rule_id=r.id WHERE r.enabled=1")
        rules = cur.fetchall()
    except Exception:
        rules = None
    if rules is not None:
        bad = [r[0] for r in rules if r[2]]
        late = [r[0] for r in rules if not r[2] and (r[1] is None or _age(now, r[1]) > 600)]
        st = WARN if bad or late else OK
        detail = "; ".join(x for x in (("com erro: " + ", ".join(bad[:5])) if bad else "",
                                       ("sem avaliar há 10+ min: " + ", ".join(late[:5])) if late else "") if x)
        out.append(item("filter_rules", "Alarmes por filtro", st, "%d ligado(s)" % len(rules), detail))
    if telegram_on:
        stuck = _one(cur, "SELECT COUNT(*) FROM orby_attack_events WHERE notified_at IS NULL AND "
                          "event_time < %s - INTERVAL 10 MINUTE AND event_time >= %s - INTERVAL 1 DAY", (now, now))
        if stuck is not None:
            stuck = int(stuck)
            st = WARN if stuck else OK
            out.append(item("telegram", "Avisos pendentes no Telegram", st, "%d evento(s) sem aviso" % stuck,
                            "" if st == OK else "orbymon-telegram parado ou sem acesso à API do Telegram"))
    try:
        cur.execute("SELECT name,value,updated_at FROM orby_mitigation_status")
        mit = {r[0]: (r[1], r[2]) for r in cur.fetchall()}
    except Exception:
        mit = {}
    if mit.get("modo") and mit["modo"][0] != "off":
        age = _age(now, mit["modo"][1])
        bgp = (mit.get("bgp") or ("", None))[0]
        if age is None or age > 300:
            out.append(item("mitigation", "Mitigação (controlador)", WARN, "sem execução há %s" % fmt_age(age),
                            "veja journalctl -u orbymon-mitigation -n 30"))
        elif bgp.startswith("desativado"):
            out.append(item("mitigation", "Mitigação (BGP)", OK, "modo %s, BGP desligado" % mit["modo"][0]))
        else:
            st = OK if "Establ" in bgp else CRIT
            out.append(item("mitigation", "Mitigação (BGP)", st, bgp[:120],
                            "" if st == OK else "sessão BGP com o roteador fora: blackholes não serão anunciados"))
    oldest = _one(cur, "SELECT MIN(bucket_utc) FROM orby_flow_minute WHERE source=%s", (src,))
    if oldest is not None:
        keep = timedelta(days=cfg["retention_days"])
        behind = (now - oldest) - keep
        st = WARN if behind > timedelta(hours=12) else OK
        out.append(item("retention", "Retenção do rollup", st,
                        "dado mais antigo: %s (retenção %d dia(s))" % (fmt_age(_age(now, oldest)), cfg["retention_days"]),
                        "" if st == OK else "a limpeza não acompanha a entrada: tabela crescendo (veja o tamanho)"))
    try:
        cur.execute("SELECT TABLE_NAME, DATA_LENGTH+INDEX_LENGTH, TABLE_ROWS FROM information_schema.TABLES "
                    "WHERE TABLE_SCHEMA=DATABASE() ORDER BY DATA_LENGTH+INDEX_LENGTH DESC LIMIT 5")
        tops = cur.fetchall()
    except Exception:
        tops = []
    if tops:
        total = _one(cur, "SELECT SUM(DATA_LENGTH+INDEX_LENGTH) FROM information_schema.TABLES "
                          "WHERE TABLE_SCHEMA=DATABASE()") or 0
        out.append(item("db_size", "Banco de dados", OK, "%.1f GB" % (float(total) / 1e9),
                        "maiores: " + ", ".join("%s %.2f GB (~%s linhas)" % (t[0], float(t[1] or 0) / 1e9,
                                                                             "{:,}".format(int(t[2] or 0)).replace(",", "."))
                                                for t in tops)))
    return out


# ------------------------------------------------------------------ estado e avisos
def save(db, items, now):
    """Grava o resultado e devolve (novos_problemas, normalizados, lembretes) para avisar."""
    cur = db.cursor()
    cur.execute("SELECT check_key,status,since,bad_runs,notified_status,notified_at FROM orby_health")
    old = {r[0]: {"status": r[1], "since": r[2], "bad_runs": r[3], "notified": r[4], "notified_at": r[5]}
           for r in cur.fetchall()}
    alerts, recovered, reminders = [], [], []
    for it in items:
        prev = old.get(it["key"], {"status": None, "since": now, "bad_runs": 0, "notified": OK, "notified_at": None})
        since = prev["since"] if prev["status"] == it["status"] else now
        bad = RANK[it["status"]] >= RANK[WARN]
        runs = prev["bad_runs"] + 1 if bad else 0
        notified, notified_at = prev["notified"], prev["notified_at"]
        if bad and runs >= CONFIRM_RUNS and RANK[it["status"]] > RANK.get(notified, 0):
            alerts.append(dict(it, since=since))
            notified, notified_at = it["status"], now
        elif bad and it["status"] == CRIT and notified == CRIT and notified_at and now - notified_at >= REMIND:
            reminders.append(dict(it, since=since))
            notified_at = now
        elif not bad and RANK.get(notified, 0) >= RANK[WARN] and it["status"] == OK:
            recovered.append(dict(it, since=since))
            notified, notified_at = OK, now
        cur.execute("""INSERT INTO orby_health (check_key,label,status,value,detail,since,bad_runs,notified_status,
 notified_at,updated_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE label=VALUES(label),
 status=VALUES(status),value=VALUES(value),detail=VALUES(detail),since=VALUES(since),bad_runs=VALUES(bad_runs),
 notified_status=VALUES(notified_status),notified_at=VALUES(notified_at),updated_at=VALUES(updated_at)""",
                    (it["key"], it["label"][:100], it["status"], it["value"][:200], it["detail"][:500], since, runs,
                     notified, notified_at, now))
    keys = [it["key"] for it in items]
    if keys:
        cur.execute("DELETE FROM orby_health WHERE updated_at < %s - INTERVAL 1 DAY", (now,))
    db.commit()
    return alerts, recovered, reminders


def message(alerts, recovered, reminders, site=""):
    e = html.escape
    head = "[%s] " % e(site) if site else ""
    lines = []
    if alerts or reminders:
        worst = max([RANK[a["status"]] for a in alerts + reminders])
        lines.append("%s %s<b>Saúde do OrbyFlow: %s</b>" % ("🔴" if worst == RANK[CRIT] else "🟠", head,
                                                          "problema" if alerts else "problema continua"))
        for a in alerts + reminders:
            lines.append("• <b>%s</b> (%s): %s%s" % (e(a["label"]), LABEL[a["status"]], e(a["value"]),
                                                     ("\n  " + e(a["detail"])) if a["detail"] else ""))
    if recovered:
        if lines:
            lines.append("")
        lines.append("🟢 %s<b>Normalizado</b>" % head)
        for r in recovered:
            lines.append("• %s: %s" % (e(r["label"]), e(r["value"])))
    return "\n".join(lines)


CH_SPOOL = "/var/lib/orbymon/clickhouse-spool"


def check_clickhouse(spool=CH_SPOOL, now_ts=None):
    """Lotes que o rollup nao conseguiu gravar no ClickHouse ficam no spool; acumulando = ClickHouse fora."""
    d = Path(spool)
    if not d.is_dir():
        return []                                   # ClickHouse nao instalado
    files = list(d.glob("*.tsv.gz"))
    if not files:
        return [item("clickhouse", "ClickHouse (fluxos)", OK, "gravando em dia")]
    now_ts = time.time() if now_ts is None else now_ts
    age = now_ts - min(f.stat().st_mtime for f in files)
    st = CRIT if age > 3600 else WARN if age > 180 else OK
    return [item("clickhouse", "ClickHouse (fluxos)", st, "%d lote(s) aguardando há %s" % (len(files), fmt_age(age)),
                 "veja journalctl -u clickhouse-server -n 30 e sudo bash scripts/setup-clickhouse.sh --status")]


def _guard(key, label, fn):
    """Uma verificacao com defeito vira 'sem dados' em vez de derrubar todas as outras."""
    try:
        got = fn()
        return got if isinstance(got, list) else [got]
    except Exception as exc:
        return [item(key, label, UNKNOWN, "verificação falhou", "%s: %s" % (type(exc).__name__, str(exc)[:200]))]


def collect(db, cfg, flow_root, now, telegram_on=False, run=_systemctl, now_ts=None, disks=DISK_PATHS,
            backup_dir=BACKUP_DIR):
    items = _guard("nfcapd", "Coleta NetStream (nfcapd)", lambda: check_nfcapd(Path(flow_root) / cfg["source"], now_ts))

    def db_checks():
        with db.cursor() as cur:
            return check_db(cur, cfg, now, telegram_on, a10_on=bool(cfg.get("a10_sources") or cfg.get("nat_rules")))
    items += _guard("db", "Verificações no banco", db_checks)
    items += _guard("disk", "Disco", lambda: check_disks(disks))
    items += _guard("backup", "Backup diário", lambda: check_backup(backup_dir))
    items += _guard("services", "Serviços", lambda: check_failed_units(run))
    items += _guard("runtime", "Tempo de execução", lambda: check_runtimes(run=run))
    items += _guard("clickhouse", "ClickHouse (fluxos)", lambda: check_clickhouse(now_ts=now_ts))
    return items


def main(argv=None):
    ap = argparse.ArgumentParser(description="OrbyFlow: verificacao de saude")
    ap.add_argument("--config", default="/etc/orbymon/bidir.json")
    ap.add_argument("--flow-root", default="/var/lib/orbymon/flows")
    ap.add_argument("--telegram-env", help="telegram.env para avisar (lido como dados)")
    args = ap.parse_args(argv)
    try:
        from .bidir_config import read_config
        from .mysql_sink import connection_from_env
        cfg = read_config(args.config)
        telegram = site = None
        if args.telegram_env:
            from .admin.config_store import read_env
            from .notify_telegram import Settings, Telegram
            env = read_env(Path(args.telegram_env))
            if env.get("TELEGRAM_BOT_TOKEN") and env.get("TELEGRAM_CHAT_IDS"):
                s = Settings.from_env(env)
                from .channels import wrap
                telegram, site = wrap(Telegram(s.token, s.chats), os.environ.get("ORBYMON_NOTIFY_ENV", "/etc/orbymon/notify.env"), s.site), s.site
        now = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
        db = connection_from_env()
        try:
            items = collect(db, cfg, args.flow_root, now, telegram_on=telegram is not None)
            alerts, recovered, reminders = save(db, items, now)
        finally:
            db.close()
        for it in items:
            if it["status"] != OK:
                print("%s %s: %s %s" % (it["status"].upper(), it["label"], it["value"], it["detail"]))
        if telegram and (alerts or recovered or reminders):
            try:
                telegram.send(message(alerts, recovered, reminders, site))
            except Exception as exc:
                print("telegram: falha ao avisar (%s)" % type(exc).__name__, file=sys.stderr)
        print("saude: %d itens, %d problema(s)" % (len(items), sum(1 for i in items if RANK[i["status"]] >= 2)))
        return 0
    except Exception as exc:
        print("FALHA saude: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
