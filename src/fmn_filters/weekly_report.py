"""Resumo semanal de segurança no Telegram (segunda de manhã): o que a rede sofreu e o que os clientes fizeram.

  - ataques recebidos: detecções, IPs atingidos, maior ataque, vetores e redes de origem;
  - ataques originados e clientes suspeitos (pontuação: ataque originado 3, C2 5, NAT 2, má reputação 1);
  - clientes falando com C2/botnet;
  - blocos do provedor em blacklist;
  - CGNAT: maior uso de portas por IP público e assinantes com 10 mil+ portas;
  - alarmes por filtro: incidentes.
Cada parte é opcional: se a tabela ainda não existe (etapa não instalada), a seção some.

Uso: python -m fmn_filters.weekly_report [--env-file /etc/orbymon/telegram.env] [--days 7] [--print]
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from html import escape as e
from pathlib import Path
import sys

SCORE_SQL = """SELECT ent,SUM(o),SUM(c),SUM(r),SUM(n),SUM(o)*3+SUM(c)*5+SUM(r)+SUM(n)*2 AS score FROM (
SELECT IF(subscriber_ip<>'',subscriber_ip,local_ip) AS ent,COUNT(*) AS o,0 AS c,0 AS r,0 AS n FROM orby_attack_events
 WHERE direction='out' AND detection IN ('flow','filter') AND event_time>=%(s)s GROUP BY 1
UNION ALL SELECT IF(subscriber_ip<>'',subscriber_ip,local_ip),0,0,0,COUNT(*) FROM orby_attack_events
 WHERE detection='nat' AND event_time>=%(s)s GROUP BY 1
UNION ALL SELECT cpe_ip,0,COUNT(*),0,0 FROM orby_threat_hits WHERE category='bot' AND last_seen>=%(s)s GROUP BY 1
UNION ALL SELECT cpe_ip,0,0,COUNT(*),0 FROM orby_threat_hits WHERE category='reputacao' AND last_seen>=%(s)s GROUP BY 1
) x GROUP BY ent ORDER BY score DESC LIMIT %(n)s"""


def _q(cur, sql, params=None):
    """Consulta opcional: tabela ausente (etapa nao instalada) devolve None."""
    try:
        cur.execute(sql, params)
        return cur.fetchall()
    except Exception:
        return None


def rate(mbps):
    mbps = float(mbps or 0)
    return ("%.1f Gb/s" % (mbps / 1000) if mbps >= 1000 else "%.0f Mb/s" % mbps).replace(".", ",")


def collect(cur, start):
    p = {"s": start, "n": 5}
    d = {}
    d["in"] = _q(cur, "SELECT COUNT(*),COUNT(DISTINCT local_ip) FROM orby_attack_events WHERE direction='in' AND "
                      "detection IN ('flow','filter') AND event_time>=%s", (start,))
    d["biggest"] = _q(cur, "SELECT local_ip,mbps,pps,event_time,rule_name FROM orby_attack_events WHERE direction='in' "
                           "AND event_time>=%s ORDER BY mbps DESC LIMIT 1", (start,))
    d["targets"] = _q(cur, "SELECT local_ip,COUNT(*),MAX(mbps) FROM orby_attack_events WHERE direction='in' AND "
                           "event_time>=%s GROUP BY local_ip ORDER BY 2 DESC LIMIT 5", (start,))
    d["vectors"] = _q(cur, "SELECT main_vector,COUNT(*),COUNT(DISTINCT local_ip) FROM orby_attack_analysis WHERE "
                           "direction='in' AND event_time>=%s GROUP BY main_vector ORDER BY 2 DESC LIMIT 5", (start,))
    d["carpet"] = _q(cur, "SELECT COUNT(*),MAX(block_ips_hit) FROM orby_attack_analysis WHERE direction='in' AND "
                          "block_ips_hit>=8 AND event_time>=%s", (start,))
    d["asns"] = _q(cur, "SELECT top_asn,MAX(top_asn_name),MAX(top_country),COUNT(*) FROM orby_attack_analysis WHERE "
                        "direction='in' AND top_asn>0 AND event_time>=%s GROUP BY top_asn ORDER BY 4 DESC LIMIT 3",
                   (start,))
    d["out"] = _q(cur, "SELECT COUNT(*),COUNT(DISTINCT IF(subscriber_ip<>'',subscriber_ip,local_ip)) FROM "
                       "orby_attack_events WHERE direction='out' AND detection IN ('flow','filter') AND event_time>=%s",
                  (start,))
    d["out_vectors"] = _q(cur, "SELECT main_vector,COUNT(*) FROM orby_attack_analysis WHERE direction='out' AND "
                               "event_time>=%s GROUP BY main_vector ORDER BY 2 DESC LIMIT 3", (start,))
    d["suspects"] = _q(cur, SCORE_SQL, p)
    d["c2"] = _q(cur, "SELECT COUNT(DISTINCT cpe_ip),COUNT(DISTINCT remote_ip) FROM orby_threat_hits WHERE "
                      "category='bot' AND last_seen>=%s", (start,))
    d["c2_top"] = _q(cur, "SELECT cpe_ip,MAX(NULLIF(malware,'')),COUNT(*) FROM orby_threat_hits WHERE category='bot' AND "
                          "last_seen>=%s GROUP BY cpe_ip ORDER BY 3 DESC LIMIT 5", (start,))
    d["blacklists"] = _q(cur, "SELECT entry,source_label FROM orby_reputation_listings WHERE removed_at IS NULL "
                              "ORDER BY first_seen DESC LIMIT 8")
    d["bl_new"] = _q(cur, "SELECT COUNT(*) FROM orby_reputation_listings WHERE first_seen>=%s", (start,))
    d["nat_peak"] = _q(cur, "SELECT public_ip,MAX(100*GREATEST(tcp_ports,udp_ports)/capacity) AS p FROM "
                            "orby_nat_public_minute WHERE bucket_utc>=%s GROUP BY public_ip ORDER BY p DESC LIMIT 1",
                       (start,))
    d["nat_heavy"] = _q(cur, "SELECT COUNT(DISTINCT inside_ip) FROM orby_nat_heavy_minute WHERE bucket_utc>=%s AND "
                             "GREATEST(tcp_ports,udp_ports)>=10000", (start,))
    d["alarms"] = _q(cur, "SELECT rule_name,COUNT(*) FROM orby_filter_incidents WHERE started_at>=%s GROUP BY rule_name "
                          "ORDER BY 2 DESC LIMIT 5", (start,))
    return d


def render(d, start, end, site="", tzname="America/Sao_Paulo"):
    from zoneinfo import ZoneInfo
    tz = ZoneInfo(tzname)

    def local(t):
        return t.replace(tzinfo=timezone.utc).astimezone(tz).strftime("%d/%m %H:%M")
    out = ["📊 <b>Resumo semanal de segurança</b>" + (" · %s" % e(site) if site else ""),
           "%s a %s" % (local(start), local(end)), ""]
    if d.get("in") is not None:
        n, ips = d["in"][0] if d["in"] else (0, 0)
        out.append("🚨 <b>Ataques recebidos:</b> %d detecção(ões) em %d IP(s)" % (n or 0, ips or 0))
        if d.get("biggest"):
            ip, mbps, pps, t, rule = d["biggest"][0]
            out.append("Maior: <code>%s</code> %s em %s (%s)" % (e(ip), rate(mbps), local(t), e(rule)))
        if d.get("vectors"):
            out.append("Vetores: " + "; ".join("%s %d×" % (e(v), c) for v, c, _ in d["vectors"]))
        if d.get("carpet") and d["carpet"][0][0]:
            out.append("Carpet bombing: %d detecção(ões), até %d IPs do mesmo /24" % (d["carpet"][0][0],
                                                                                    d["carpet"][0][1] or 0))
        if d.get("asns"):
            out.append("Redes de origem: " + "; ".join("AS%d %s%s (%d)" % (a, e((nm or "")[:24]),
                                                                           " %s" % e(c) if c else "", n_)
                                                       for a, nm, c, n_ in d["asns"]))
        if d.get("targets"):
            out.append("Mais atacados: " + ", ".join("<code>%s</code> %d×" % (e(ip), c) for ip, c, _ in d["targets"]))
        out.append("")
    if d.get("out") is not None:
        n, cl = d["out"][0] if d["out"] else (0, 0)
        out.append("📤 <b>Ataques originados por clientes:</b> %d detecção(ões), %d cliente(s)" % (n or 0, cl or 0))
        if d.get("out_vectors"):
            out.append("Tipos: " + "; ".join("%s %d×" % (e(v), c) for v, c in d["out_vectors"]))
        out.append("")
    if d.get("c2") is not None:
        cpes, ips = d["c2"][0] if d["c2"] else (0, 0)
        out.append("🦠 <b>Clientes falando com C2/botnet:</b> %d (com %d servidor(es) de comando)" % (cpes or 0, ips or 0))
        for cpe, mal, n_ in (d.get("c2_top") or []):
            out.append("  • <code>%s</code>%s" % (e(cpe), (" — %s" % e(mal)) if mal else ""))
        out.append("")
    if d.get("suspects"):
        top = [r for r in d["suspects"] if (r[5] or 0) > 0]
        if top:
            out.append("🔎 <b>Clientes suspeitos</b> (originou ataque / C2 / NAT / má reputação):")
            for ent, o, c, r, n_, score in top:
                out.append("  • <code>%s</code> — pontos %d (%d/%d/%d/%d)" % (e(ent), score, o, c, n_, r))
            out.append("")
    if d.get("blacklists") is not None:
        new = d["bl_new"][0][0] if d.get("bl_new") else 0
        out.append("🛑 <b>Blacklists:</b> %d listagem(ns) ativa(s), %d nova(s) na semana" % (len(d["blacklists"]), new or 0))
        for entry, label in d["blacklists"][:5]:
            out.append("  • <code>%s</code> em %s" % (e(entry), e(label)))
        out.append("")
    if d.get("nat_peak"):
        ip, pct = d["nat_peak"][0]
        heavy = d["nat_heavy"][0][0] if d.get("nat_heavy") else 0
        out.append("🌐 <b>CGNAT:</b> maior uso de portas %.0f%% (<code>%s</code>); %d assinante(s) passaram de 10 mil "
                   "portas" % (float(pct or 0), e(ip), heavy or 0))
        out.append("")
    if d.get("alarms"):
        out.append("⏰ <b>Alarmes por filtro:</b> " + "; ".join("%s %d×" % (e(n_), c) for n_, c in d["alarms"]))
    return "\n".join(out).strip()


def main(argv=None):
    ap = argparse.ArgumentParser(description="OrbyFlow: resumo semanal de segurança no Telegram")
    ap.add_argument("--env-file", default="/etc/orbymon/telegram.env", help="telegram.env (lido como dado)")
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--print", action="store_true", help="só mostra na tela, não envia")
    args = ap.parse_args(argv)
    try:
        from .admin.config_store import read_env
        from .mysql_sink import connection_from_env
        env = read_env(Path(args.env_file)) if Path(args.env_file).exists() else {}
        end = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
        start = end - timedelta(days=max(1, min(31, args.days)))
        db = connection_from_env(read_timeout=300)
        try:
            cur = db.cursor()
            try:
                cur.execute("SET SESSION max_statement_time=120")
            except Exception:
                pass
            text = render(collect(cur, start), start, end, env.get("ORBYMON_SITE_NAME", ""),
                          env.get("ORBYMON_TZ", "America/Sao_Paulo") or "America/Sao_Paulo")
        finally:
            db.close()
        if args.print or env.get("ORBYMON_WEEKLY_REPORT", "1") == "0":
            print(text)
            return 0
        if not (env.get("TELEGRAM_BOT_TOKEN") and env.get("TELEGRAM_CHAT_IDS")):
            print("Telegram não configurado: resumo só na tela\n" + text)
            return 0
        from .notify_telegram import Settings, Telegram
        st = Settings.from_env(env)
        lines, size = [], 0
        for line in text.splitlines():           # corta em linha inteira (nao quebra tag HTML no limite do Telegram)
            if size + len(line) > 3900:
                lines.append("…")
                break
            lines.append(line)
            size += len(line) + 1
        Telegram(st.token, st.chats).send("\n".join(lines))
        print("resumo semanal enviado")
        return 0
    except Exception as exc:
        print("FALHA resumo semanal: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
