"""Analise automatica de cada ataque detectado: qual o vetor, de onde veio e como era o trafego.

Para cada evento novo de ataque (deteccao por fluxo, recebido ou originado) le os arquivos nfcapd brutos
da janela do evento (portas reais, flags TCP, tamanho de pacote, fragmentos) e grava em orby_attack_analysis:
  - vetor: "Amplificação DNS (UDP/53)", "SYN flood", "ACK flood", "Fragmentos UDP", "UDP flood em portas
    aleatórias", "Cliente usado como refletor NTP", "Varredura TCP/23 (Telnet)"... e os vetores secundarios
    (ataque multivetor) com a participacao de cada um;
  - origens: quantos IPs remotos, os principais e os ASNs/paises (GeoLite2);
  - carpet bombing: quantos IPs do mesmo /24 receberam o mesmo vetor na janela.
Aparece no detalhe do ataque (painel), no Telegram (mensagem "Análise do ataque") e no Grafana (Análise de ataques).

Uso: python -m fmn_filters.attack_analysis --config /etc/orbymon/bidir.json [--flow-root /var/lib/orbymon/flows]
     [--telegram-env /etc/orbymon/telegram.env] [--hours 6] [--limit 20] [--event ID] [--print]
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timedelta, timezone
from html import escape as e
import io
from ipaddress import ip_address, ip_network
import json
import os
from pathlib import Path
import subprocess
import sys
import time

NFDUMP = os.environ.get("ORBYMON_NFDUMP", "/usr/bin/nfdump")
MAX_WINDOW_MIN = 5
MAX_FLOWS = 400000
TIMEOUT = 60

# servicos usados em reflexao/amplificacao (porta de ORIGEM da resposta que chega na vitima)
AMP = {19: "Chargen", 53: "DNS", 69: "TFTP", 111: "Portmap", 123: "NTP", 137: "NetBIOS", 161: "SNMP",
       389: "CLDAP", 427: "SLP", 520: "RIP", 1434: "MSSQL", 1900: "SSDP", 3283: "Apple ARD", 3702: "WS-Discovery",
       5353: "mDNS", 5683: "CoAP", 10001: "Ubiquiti", 11211: "memcached", 17: "QOTD", 27015: "Steam",
       37810: "DVR", 32414: "Plex", 33848: "Jenkins"}
SCAN_PORTS = {22: "SSH", 23: "Telnet", 25: "SMTP", 80: "HTTP", 443: "HTTPS", 445: "SMB", 1433: "MSSQL",
              2323: "Telnet", 3306: "MySQL", 3389: "RDP", 5060: "SIP", 5555: "ADB", 6379: "Redis", 7547: "TR-069",
              8080: "HTTP", 8291: "Winbox", 8443: "HTTPS"}
PROTO = {"1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp", "58": "icmpv6"}


# ------------------------------------------------------------------ leitura dos fluxos
def nfdump(files, flow_dir, expr, extra=(), timeout=TIMEOUT):
    if not files:
        return ""
    rng = ["-R", "%s/%s:%s" % (flow_dir, files[0], files[-1])] if len(files) > 1 else ["-r", str(Path(flow_dir) / files[0])]
    env = {"TZ": "UTC", "PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    cp = subprocess.run(["nice", "-n", "10", NFDUMP] + rng + list(extra) + [expr], capture_output=True, text=True,
                        timeout=timeout, env=env)
    if cp.returncode != 0:
        raise RuntimeError("nfdump: %s" % ((cp.stderr or cp.stdout).strip()[:200]))
    return cp.stdout


def csv_rows(text):
    lines = [l for l in text.splitlines() if l.strip() and l.strip() != "No matching flows"]
    if "Summary" in lines:
        lines = lines[:lines.index("Summary")]
    return list(csv.DictReader(io.StringIO("\n".join(lines)))) if lines else []


def _f(row, k):
    try:
        return float(row.get(k) or 0)
    except ValueError:
        return 0.0


def _i(row, k):
    try:
        return int(float(row.get(k) or 0))
    except ValueError:
        return 0


def stats_of(rows, direction):
    """Agrega os fluxos de/para o IP atacado. direction 'in': remoto = origem; 'out': remoto = destino."""
    s = {"bytes": 0.0, "packets": 0.0, "flows": 0, "proto": Counter(), "rport": Counter(), "lport": Counter(),
         "rport_pk": Counter(), "flags": Counter(), "frag": 0.0, "remote": Counter(), "rasn": Counter(),
         "lports": set(), "tcp_pk": 0.0}
    for r in rows:
        by, pk = _f(r, "ibyt"), _f(r, "ipkt")
        if pk <= 0:
            continue
        pr = PROTO.get((r.get("pr") or "").strip(), (r.get("pr") or "").strip().lower())
        sp, dp = _i(r, "sp"), _i(r, "dp")
        rport, lport = (sp, dp) if direction == "in" else (dp, sp)
        remote = (r.get("sa") if direction == "in" else r.get("da")) or ""
        rasn = _i(r, "sas" if direction == "in" else "das")
        s["bytes"] += by
        s["packets"] += pk
        s["flows"] += 1
        s["proto"][pr] += by
        if pr in ("udp", "tcp"):
            s["rport"][(pr, rport)] += by
            s["rport_pk"][(pr, rport)] += pk
            s["lport"][(pr, lport)] += by
            if len(s["lports"]) < 5000:
                s["lports"].add((pr, lport))
            if sp == 0 and dp == 0:
                s["frag"] += by
        if pr == "tcp":
            flg = (r.get("flg") or "").replace(".", "").upper()
            s["tcp_pk"] += pk
            if flg == "S":
                s["flags"]["syn"] += pk
            elif "S" in flg and "A" in flg:
                s["flags"]["synack"] += pk
            elif "R" in flg and "S" not in flg:
                s["flags"]["rst"] += pk
            elif flg in ("A", "AP", "PA"):
                s["flags"]["ack"] += pk
            else:
                s["flags"]["other"] += pk
        s["remote"][remote] += by
        if rasn and not (64512 <= rasn <= 65535 or rasn >= 4200000000 or rasn == 23456):
            s["rasn"][rasn] += by
    return s


def _share(part, total):
    return part / total if total else 0.0


def classify(s, direction):
    """(rotulo principal, [(vetor, participacao)], fatos). Participacao por bytes."""
    total = s["bytes"]
    if total <= 0:
        return "Sem fluxos amostrados na janela", [], {}
    vectors = []
    frag = _share(s["frag"], total)
    used = 0.0
    # 1) reflexao/amplificacao: porta de servico do lado remoto (recebido) ou do nosso lado (originado = refletor)
    ports = s["rport"] if direction == "in" else s["lport"]
    for (pr, port), by in ports.most_common(6):
        if pr == "udp" and port in AMP and _share(by, total) >= 0.10:
            name = AMP[port]
            label = ("Amplificação %s (UDP/%d)" % (name, port)) if direction == "in" else \
                ("Cliente usado como refletor %s (UDP/%d)" % (name, port))
            vectors.append((label, _share(by, total)))
            used += by
    if frag >= 0.10:
        vectors.append(("Fragmentos UDP (porta 0)", frag))
        used += s["frag"]
    tcp = _share(s["proto"]["tcp"], total)
    if tcp >= 0.10:
        fl = s["flags"]
        tpk = max(1.0, s["tcp_pk"])
        kind = None
        if _share(fl["syn"], tpk) >= 0.6:
            kind = "SYN flood"
            if direction == "out":
                (pr, port), _ = (s["rport"].most_common(1) or [(("tcp", 0), 0)])[0]
                if len(s["remote"]) >= 50 and port in SCAN_PORTS:
                    kind = "Varredura TCP/%d (%s)" % (port, SCAN_PORTS[port])
                elif len(s["remote"]) >= 50:
                    kind = "Varredura/SYN para muitos destinos"
        elif _share(fl["synack"], tpk) >= 0.5:
            kind = "Reflexão TCP (SYN-ACK)" if direction == "in" else "SYN-ACK saindo (cliente usado como refletor TCP)"
        elif _share(fl["ack"], tpk) >= 0.6:
            kind = "ACK flood"
        elif _share(fl["rst"], tpk) >= 0.5:
            kind = "RST flood"
        else:
            kind = "TCP flood"
        vectors.append((kind, tcp))
        used += s["proto"]["tcp"]
    for pr, label in (("icmp", "ICMP flood"), ("icmpv6", "ICMPv6 flood"), ("gre", "GRE flood"), ("esp", "ESP flood")):
        if _share(s["proto"][pr], total) >= 0.10:
            vectors.append((label, _share(s["proto"][pr], total)))
            used += s["proto"][pr]
    rest_udp = s["proto"]["udp"] - sum(by for (pr, port), by in ports.items() if pr == "udp" and port in AMP) - s["frag"]
    if _share(rest_udp, total) >= 0.10:
        lp = {p for pr, p in s["lports"] if pr == "udp"}
        if direction == "in" and len(lp) >= 50:
            label = "UDP flood em portas aleatórias"
        else:
            other = s["lport"] if direction == "in" else s["rport"]
            top = [(port, by) for (pr, port), by in other.most_common(5) if pr == "udp"]
            label = ("UDP flood na porta %d" % top[0][0]) if top and top[0][0] else "UDP flood"
        vectors.append((label, _share(rest_udp, total)))
    vectors.sort(key=lambda v: -v[1])
    if not vectors:
        top = s["proto"].most_common(1)
        vectors = [("Tráfego %s" % (top[0][0].upper() if top else "misto"), 1.0)]
    main = vectors[0][0] + (" + multivetor" if len([v for v in vectors if v[1] >= 0.15]) > 1 else "")
    facts = {"bytes_por_pacote": round(total / max(1.0, s["packets"])), "fragmentos": round(frag, 3),
             "ips_remotos": len(s["remote"]), "fluxos": s["flows"],
             "protocolos": {k: round(_share(v, total), 3) for k, v in s["proto"].most_common(4)}}
    if s["tcp_pk"]:
        facts["flags_tcp"] = {k: round(_share(v, s["tcp_pk"]), 3) for k, v in s["flags"].most_common()}
    return main, [(l, round(sh, 3)) for l, sh in vectors], facts


def top_sources(s, geo=None, n=5):
    total = s["bytes"] or 1.0
    remotes = [{"ip": ip, "share": round(by / total, 3)} for ip, by in s["remote"].most_common(n) if ip]
    asn = Counter()
    names = {}
    if geo is not None:
        for ip, by in s["remote"].most_common(3000):
            info = geo.lookup(ip) or {}
            key = (info.get("asn") or 0, info.get("country") or "")
            asn[key] += by
            names[key] = info.get("asn_name") or ""
    else:
        for a, by in s["rasn"].items():
            asn[(a, "")] += by
    asns = [{"asn": a, "nome": names.get((a, c), ""), "pais": c, "share": round(by / total, 3)}
            for (a, c), by in asn.most_common(n) if a]
    return remotes, asns


# ------------------------------------------------------------------ analise de um evento
def window_of(ev):
    minutes = max(1, min(MAX_WINDOW_MIN, int((ev.get("details") or {}).get("minutes") or 1)))
    end = ev["event_time"] + timedelta(minutes=1)
    return end - timedelta(minutes=minutes), end


def select_files(flow_dir, start, end, slack=45):
    from .flow_query import select_files as sf
    return sf(flow_dir, start, end, slack)


def analyze(ev, flow_dir, geo=None, run=nfdump):
    ip = ev["local_ip"]
    ip_address(ip)                          # nunca monta filtro com texto que nao seja IP
    start, end = window_of(ev)
    files = select_files(flow_dir, start, end)
    if not files:
        return {"vector": "Sem arquivos de fluxo da janela", "vectors": [], "facts": {}, "start": start, "end": end,
                "files": 0}
    side = "dst" if ev["direction"] == "in" else "src"
    rows = csv_rows(run(files, flow_dir, "%s ip %s" % (side, ip), ["-o", "csv", "-c", str(MAX_FLOWS)]))
    s = stats_of(rows, ev["direction"])
    main, vectors, facts = classify(s, ev["direction"])
    remotes, asns = top_sources(s, geo)
    out = {"vector": main, "vectors": vectors, "facts": facts, "top_remotos": remotes, "top_asns": asns,
           "start": start, "end": end, "files": len(files)}
    # carpet bombing: o mesmo vetor (porta de origem) contra varios IPs do /24 na mesma janela
    if ev["direction"] == "in" and ip_address(ip).version == 4 and s["bytes"]:
        (pr, port), by = (s["rport"].most_common(1) or [(("", 0), 0)])[0]
        cond = None
        if pr == "udp" and port in AMP and _share(by, s["bytes"]) >= 0.3:
            cond = "proto udp and src port %d" % port
        elif _share(s["frag"], s["bytes"]) >= 0.3:
            cond = "proto udp and port 0"
        elif _share(s["flags"]["syn"], max(1.0, s["tcp_pk"])) >= 0.6 and _share(s["proto"]["tcp"], s["bytes"]) >= 0.5:
            cond = "proto tcp and flags S and not flags A"
        if cond:
            net = ip_network(ip + "/24", strict=False)
            try:
                hit = csv_rows(run(files, flow_dir, "%s and dst net %s" % (cond, net), ["-A", "dstip", "-o", "csv"]))
                n = len({r.get("da") for r in hit if r.get("da")})
                out["facts"]["ips_do_bloco_atingidos"] = n
                out["facts"]["bloco"] = str(net)
                if n >= 8:
                    out["vector"] += " · carpet bombing (%d IPs do %s)" % (n, net)
            except Exception:
                pass
    return out


def summary(a):
    """Texto curto (uma linha) para listas e Telegram."""
    f = a.get("facts") or {}
    parts = [a["vector"]]
    sec = [("%s %d%%" % (l, round(sh * 100))) for l, sh in a.get("vectors", [])[1:3] if sh >= 0.1]
    if sec:
        parts.append("também " + ", ".join(sec))
    if f.get("ips_remotos"):
        parts.append("%d origem(ns) amostrada(s)" % f["ips_remotos"])
    if a.get("top_asns"):
        x = a["top_asns"][0]
        parts.append("principal AS%d %s%s %d%%" % (x["asn"], x.get("nome", "")[:24], (" (%s)" % x["pais"]) if
                                                   x.get("pais") else "", round(x["share"] * 100)))
    if f.get("bytes_por_pacote"):
        parts.append("%d B/pacote" % f["bytes_por_pacote"])
    return " · ".join(parts)


# ------------------------------------------------------------------ banco
EVENT_COLS = ("event_id", "event_time", "rule_name", "severity", "direction", "scope", "pool", "local_ip",
              "subscriber_ip", "mbps", "pps", "details", "notified_at")


def pending(cur, since, limit, event_id=None):
    if event_id:
        cur.execute("SELECT " + ",".join("e." + c for c in EVENT_COLS[:-1]) + ",NULL FROM orby_attack_events e "
                    "WHERE e.event_id=%s", (event_id,))
    else:
        cur.execute("SELECT " + ",".join("e." + c for c in EVENT_COLS[:-1]) + ",NULL FROM orby_attack_events e "
                    "LEFT JOIN orby_attack_analysis a ON a.event_id=e.event_id WHERE e.event_time>=%s AND "
                    "e.detection='flow' AND a.event_id IS NULL ORDER BY e.event_time DESC LIMIT %s", (since, limit))
    out = []
    for row in cur.fetchall():
        ev = dict(zip(EVENT_COLS, row))
        try:
            ev["details"] = json.loads(ev["details"]) if isinstance(ev["details"], (str, bytes)) else (ev["details"] or {})
        except ValueError:
            ev["details"] = {}
        out.append(ev)
    return out


SAVE_SQL = """INSERT INTO orby_attack_analysis (event_id,event_time,direction,local_ip,subscriber_ip,rule_name,vector,
main_vector,summary,remote_ips,top_asn,top_asn_name,top_country,bytes_per_packet,fragment_share,block_ips_hit,
details,analyzed_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
ON DUPLICATE KEY UPDATE vector=VALUES(vector),main_vector=VALUES(main_vector),summary=VALUES(summary),
remote_ips=VALUES(remote_ips),top_asn=VALUES(top_asn),top_asn_name=VALUES(top_asn_name),top_country=VALUES(top_country),
bytes_per_packet=VALUES(bytes_per_packet),fragment_share=VALUES(fragment_share),block_ips_hit=VALUES(block_ips_hit),
details=VALUES(details),analyzed_at=VALUES(analyzed_at)"""


def save(cur, ev, a, now):
    f = a.get("facts") or {}
    top = (a.get("top_asns") or [{}])[0]
    main = (a.get("vectors") or [(a["vector"], 1)])[0][0]
    details = {k: v for k, v in a.items() if k not in ("start", "end")}
    details["janela"] = [a["start"].strftime("%Y-%m-%d %H:%M"), a["end"].strftime("%Y-%m-%d %H:%M")]
    cur.execute(SAVE_SQL, (ev["event_id"], ev["event_time"], ev["direction"], ev["local_ip"], ev["subscriber_ip"] or "",
                           ev["rule_name"][:100], a["vector"][:160], main[:80], summary(a)[:255],
                           int(f.get("ips_remotos") or 0), int(top.get("asn") or 0), (top.get("nome") or "")[:80],
                           (top.get("pais") or "")[:2], int(f.get("bytes_por_pacote") or 0),
                           float(f.get("fragmentos") or 0), int(f.get("ips_do_bloco_atingidos") or 0),
                           json.dumps(details, ensure_ascii=False, default=str), now))


def telegram_text(ev, a, site=""):
    head = "🔎 <b>Análise do ataque</b>" + (" · %s" % e(site) if site else "")
    who = ev["subscriber_ip"] or ev["local_ip"]
    sense = "recebido por" if ev["direction"] == "in" else "originado de"
    lines = [head, "%s <code>%s</code> (%s)" % (sense, e(who), e(ev["rule_name"])),
             "<b>Vetor:</b> %s" % e(a["vector"])]
    for l, sh in (a.get("vectors") or [])[1:4]:
        lines.append("  • %s: %d%%" % (e(l), round(sh * 100)))
    f = a.get("facts") or {}
    if f.get("ips_remotos"):
        lines.append("<b>Origens amostradas:</b> %d IPs" % f["ips_remotos"])
    if a.get("top_asns"):
        lines.append("<b>Principais redes:</b> " + "; ".join(
            "AS%d %s%s %d%%" % (x["asn"], e(x.get("nome", "")[:28]), (" (%s)" % e(x["pais"])) if x.get("pais") else "",
                                round(x["share"] * 100)) for x in a["top_asns"][:3]))
    if f.get("bytes_por_pacote"):
        lines.append("Pacote médio: %d bytes%s" % (f["bytes_por_pacote"], (" · fragmentos %d%%" % round(
            f["fragmentos"] * 100)) if f.get("fragmentos", 0) >= 0.05 else ""))
    if f.get("ips_do_bloco_atingidos", 0) >= 2:
        lines.append("Mesmo vetor em <b>%d IPs</b> do %s" % (f["ips_do_bloco_atingidos"], e(f.get("bloco", ""))))
    return "\n".join(lines)


def should_notify(cur, ev, now, quiet_min=60):
    """Uma analise por alvo/regra a cada quiet_min (o ataque longo gera eventos a cada poucos minutos)."""
    cur.execute("SELECT COUNT(*) FROM orby_attack_analysis WHERE local_ip=%s AND direction=%s AND rule_name=%s AND "
                "notified_at>=%s", (ev["local_ip"], ev["direction"], ev["rule_name"], now - timedelta(minutes=quiet_min)))
    return int(cur.fetchone()[0]) == 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="OrbyFlow: análise automática dos ataques detectados")
    ap.add_argument("--config", default="/etc/orbymon/bidir.json")
    ap.add_argument("--flow-root", default=os.environ.get("ORBYMON_FLOW_ROOT", "/var/lib/orbymon/flows"))
    ap.add_argument("--telegram-env", help="telegram.env (lido como dado) para mandar a análise")
    ap.add_argument("--hours", type=float, default=6, help="olha eventos das últimas N horas (padrão 6)")
    ap.add_argument("--limit", type=int, default=20, help="eventos por execução (padrão 20)")
    ap.add_argument("--event", help="analisa só este event_id (mostra na tela)")
    ap.add_argument("--print", action="store_true", help="mostra o resultado")
    args = ap.parse_args(argv)
    try:
        from .bidir_config import read_config
        from .mysql_sink import connection_from_env
        cfg = read_config(args.config)
        flow_dir = Path(args.flow_root) / cfg["source"]
        geo = None
        try:
            from .enrichment import Enricher
            paths = [p if os.access(p, os.R_OK) else None for p in (
                os.environ.get("ORBYMON_ASN_MMDB") or "/var/lib/orbymon/geoip/GeoLite2-ASN.mmdb",
                os.environ.get("ORBYMON_CITY_MMDB") or "/var/lib/orbymon/geoip/GeoLite2-City.mmdb")]
            if any(paths):
                geo = Enricher(*paths)
        except Exception:
            geo = None
        telegram = site = None
        min_sev = "high"
        if args.telegram_env and Path(args.telegram_env).exists():
            from .admin.config_store import read_env
            from .notify_telegram import Settings, Telegram
            tenv = read_env(Path(args.telegram_env))
            if tenv.get("TELEGRAM_BOT_TOKEN") and tenv.get("TELEGRAM_CHAT_IDS") and \
                    tenv.get("ORBYMON_NOTIFY_ANALYSIS", "1") != "0":
                st = Settings.from_env(tenv)
                telegram, site, min_sev = Telegram(st.token, st.chats), st.site, st.min_severity
        from .notify_telegram import SEVERITY_ORDER
        now = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
        db = connection_from_env(read_timeout=120)
        started, done, sent = time.time(), 0, 0
        try:
            cur = db.cursor()
            events = pending(cur, now - timedelta(hours=args.hours), max(1, min(200, args.limit)), args.event)
            for ev in events:
                if time.time() - started > 240:
                    break
                if ev["event_time"] > now - timedelta(minutes=1):
                    continue                     # o minuto ainda esta sendo gravado
                try:
                    a = analyze(ev, flow_dir, geo)
                except Exception as exc:
                    a = {"vector": "Análise falhou: %s" % str(exc)[:120], "vectors": [], "facts": {},
                         "start": ev["event_time"], "end": ev["event_time"]}
                save(cur, ev, a, now)
                db.commit()
                done += 1
                if args.print or args.event:
                    print("%s %s %s -> %s" % (ev["event_time"], ev["direction"], ev["local_ip"], summary(a)))
                if telegram and a.get("vectors") and \
                        SEVERITY_ORDER.get(ev["severity"], 0) >= SEVERITY_ORDER.get(min_sev, 0) and \
                        should_notify(cur, ev, now):
                    try:
                        telegram.send(telegram_text(ev, a, site))
                        cur.execute("UPDATE orby_attack_analysis SET notified_at=%s WHERE event_id=%s",
                                    (now, ev["event_id"]))
                        db.commit()
                        sent += 1
                    except Exception as exc:
                        print("telegram: falha (%s)" % type(exc).__name__, file=sys.stderr)
            cur.execute("DELETE FROM orby_attack_analysis WHERE event_time < %s", (now - timedelta(days=180),))
            db.commit()
        finally:
            db.close()
        print("analise de ataques: %d evento(s) analisado(s), %d aviso(s), %.0f s" % (done, sent, time.time() - started))
        return 0
    except Exception as exc:
        print("FALHA analise de ataques: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
