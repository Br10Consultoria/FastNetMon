"""Calibracao dos limites da F4 com o trafego real (somente leitura, exceto com --apply).

Mede, por regra e tipo de IP (dedicado, pool CGNAT, IP privado, assinante), a distribuicao
de pacotes/s e Mbps por entidade e minuto, exatamente como o detector agrupa. Minutos de
entidades com evento de ataque registrado sao ignorados. Propoe:

    limite = max(percentil 99,9 x fator, piso)

e estima quantos alarmes os limites atuais teriam gerado no periodo (2+ minutos seguidos).
Calibra apenas min_pps e min_mbps; criterios estruturais (IPs remotos, SYN, porta 0) ficam.
Regras NAT usam alocacoes de porta por minuto do log do A10 (sem amostragem).
"""
from __future__ import annotations

import argparse
from array import array
from collections import Counter, defaultdict
import copy
from datetime import datetime, timedelta, timezone
import json
import math
import os
from pathlib import Path
import shutil
import sys

from .bidir_config import DEFAULT_CONFIG, read_config, validate_config
from .bidir_detector import _entities

FLOOR = {"min_pps": 1000.0, "min_mbps": 10.0}
NAT_FLOOR = {"min_allocs_per_min": 1000.0, "min_active_ports": 2000.0}
MIN_MINUTES = 360            # 6 h de dados antes de permitir --apply
ROWS_SQL = """SELECT bucket_utc,direction,scope,local_ip,subscriber_ip,protocol,local_port,remote_port,
SUM(packets),SUM(bytes),SUM(syn_packets),SUM(zero_port_packets) FROM orby_flow_minute
WHERE source=%s AND bucket_utc >= %s AND bucket_utc < %s
GROUP BY bucket_utc,direction,scope,local_ip,subscriber_ip,protocol,local_port,remote_port"""
EVENTS_SQL = """SELECT event_time,local_ip,subscriber_ip FROM orby_attack_events
WHERE event_time >= %s AND event_time < %s"""
NAT_SQL = """SELECT bucket_utc,inside_ip,allocs,active_ports FROM orby_nat_user_minute
WHERE bucket_utc >= %s AND bucket_utc < %s ORDER BY bucket_utc"""


def percentile(values, pct):
    if not values:
        return 0.0
    ordered = sorted(values)
    return float(ordered[min(len(ordered) - 1, max(0, math.ceil(pct * len(ordered)) - 1))])


def round_up(value):
    """Arredonda para cima com 2 algarismos significativos (23456 -> 24000)."""
    if value <= 0:
        return 0
    digits = int(math.floor(math.log10(value))) - 1
    step = 10 ** max(digits, 0)
    result = math.ceil(value / step) * step
    return int(result) if result >= 1 else round(result, 2)


RATIO_KEYS = ("min_syn_ratio", "min_zero_port_ratio")


class _Track:
    """Distribuicao e simulacao de alarmes de uma (regra, escopo).

    Regras com proporcao (SYN, porta 0) medem o proprio sinal: pacotes SYN/s ou de porta 0/s.
    """
    __slots__ = ("sig", "tot", "mbps", "ratio", "slot", "streak", "last", "alarms_now", "limits", "n", "ratio_key",
                 "offenders")

    def __init__(self, limits, n):
        self.sig, self.tot, self.mbps, self.ratio = array("f"), array("f"), array("f"), array("f")
        self.slot = array("B")                  # tipo de dia x 24 + hora local
        self.streak, self.last = {}, {}
        self.offenders = Counter()
        self.alarms_now = 0
        self.limits, self.n = limits, n
        self.ratio_key = next((k for k in RATIO_KEYS if k in limits), None)

    @staticmethod
    def fires(limits, ratio_key, tot, mbps, ratio):
        return ((("min_pps" not in limits) or tot >= limits["min_pps"]) and
                (("min_mbps" not in limits) or mbps >= limits["min_mbps"]) and
                (ratio_key is None or ratio >= limits[ratio_key]))

    def add(self, key, minute, packets, nbytes, syn, zero, slot=0):
        tot, mbps = packets / 60.0, nbytes * 8 / 60e6
        self.slot.append(slot)
        part = {"min_syn_ratio": syn, "min_zero_port_ratio": zero}.get(self.ratio_key, packets)
        ratio = part / packets if packets else 0.0
        self.sig.append(part / 60.0)
        self.tot.append(tot)
        self.mbps.append(mbps)
        self.ratio.append(ratio)
        if not self.fires(self.limits, self.ratio_key, tot, mbps, ratio):
            self.streak.pop(key, None)
            return
        run = self.streak.get(key, 0) + 1 if self.last.get(key) == minute - 1 else 1
        self.streak[key], self.last[key] = run, minute
        if run == self.n:                       # alarme dispara ao completar a sequencia
            self.alarms_now += 1
            self.offenders[key] += 1


class Calibrator:
    def __init__(self, cfg, attacks=frozenset(), exc=None):
        from zoneinfo import ZoneInfo
        from .baseline import settings
        self.cfg = cfg
        self.attacks = attacks                  # {(entidade, minuto)} a ignorar
        self.exc = exc                          # excecoes (exceptions.Matcher): lado local
        self.tz = ZoneInfo(settings(cfg)["timezone"])
        self.slots = {}
        self.rules = [r for r in cfg["rules"] if r["enabled"]]
        self.tracks = {(r["name"], s): _Track(r["limits"][s], r["consecutive_minutes"])
                       for r in self.rules for s in r["limits"]}
        self.current = None
        self.acc = defaultdict(lambda: [0.0, 0.0, 0.0, 0.0])
        self.minutes = set()
        self.ignored = set()

    def _flush(self):
        if self.current is None:
            return
        minute = self.current
        slot = self.slots.get(minute // 60)
        if slot is None:
            from .baseline import slot as local_slot
            daytype, hour = local_slot(datetime.fromtimestamp(minute * 60, timezone.utc).replace(tzinfo=None), self.tz)
            slot = self.slots[minute // 60] = (24 if daytype == "wke" else 0) + hour
        for (rule_name, vscope, entity, proto, lport, rport), (packets, nbytes, syn, zero) in self.acc.items():
            if (entity, minute) in self.attacks:
                self.ignored.add((entity, minute))
                continue
            self.tracks[(rule_name, vscope)].add((vscope, entity, proto, lport, rport), minute,
                                                 packets, nbytes, syn, zero, slot)
        self.acc.clear()

    def add(self, row):
        minute = int(row["bucket_utc"].replace(tzinfo=timezone.utc).timestamp() // 60)
        if minute != self.current:
            if self.current is not None and minute < self.current:
                raise ValueError("linhas precisam estar em ordem de minuto")
            self._flush()
            self.current = minute
        self.minutes.add(minute)
        for rule in self.rules:
            if row["direction"] != rule["direction"] or row["protocol"] not in rule["protocols"]:
                continue
            if rule.get("local_ports") and row["local_port"] not in rule["local_ports"]:
                continue
            if rule.get("remote_ports") and row["remote_port"] not in rule["remote_ports"]:
                continue
            split = rule["split_by"]
            if self.exc and self.exc.ignore_row(rule["name"], rule["direction"],
                                                (row["local_ip"], row["subscriber_ip"]), row.get("remote_ip", "")):
                continue
            for vscope, entity in _entities(row):
                if vscope not in rule["limits"]:
                    continue
                if self.exc and self.exc.multiplier(rule["name"], rule["direction"], entity) != 1:
                    continue                    # perfil proprio: fora da distribuicao geral
                item = self.acc[(rule["name"], vscope, entity, row["protocol"],
                                 row["local_port"] if "local_port" in split else 0,
                                 row["remote_port"] if "remote_port" in split else 0)]
                item[0] += float(row["packets"])
                item[1] += float(row["bytes"])
                item[2] += float(row.get("syn_packets") or 0.0)
                item[3] += float(row.get("zero_port_packets") or 0.0)

    def finish(self, factor=2.0, floor=None, max_down=0.5, max_up=4.0):
        """Proposta = p99,9 x fator, com piso, limitada a [atual x max_down, atual x max_up] por rodada."""
        self._flush()
        floor = floor or FLOOR
        days = max(len(self.minutes) / 1440.0, 1 / 1440.0)
        report, proposal = [], copy.deepcopy(self.cfg)
        by_name = {r["name"]: r for r in proposal["rules"]}
        for (rule_name, vscope), tr in sorted(self.tracks.items()):
            limits = tr.limits
            new = dict(limits)
            entry = {"regra": rule_name, "escopo": vscope, "amostras": len(tr.tot),
                     "sinal": {"min_syn_ratio": "SYN/s", "min_zero_port_ratio": "porta0/s"}.get(tr.ratio_key, "total"),
                     "alarmes_atuais_por_dia": round(tr.alarms_now / days, 1)}
            for metric, values in (("min_pps", tr.sig), ("min_mbps", tr.mbps)):
                if metric not in limits:
                    continue
                p99, p999, peak = percentile(values, .99), percentile(values, .999), max(values, default=0.0)
                entry[metric] = {"atual": limits[metric], "p99": round(p99, 1), "p99_9": round(p999, 1),
                                 "maximo": round(peak, 1), "limitado": False}
                if len(values) >= 100:          # sem amostras suficientes, mantem o limite atual
                    raw = max(p999 * factor, floor[metric])
                    bounded = min(max(raw, limits[metric] * max_down), limits[metric] * max_up)
                    entry[metric]["limitado"] = bounded != raw
                    new[metric] = round_up(bounded)
                entry[metric]["proposto"] = new[metric]
            entry["minutos_acima_do_proposto"] = sum(
                1 for t, m, r in zip(tr.tot, tr.mbps, tr.ratio) if _Track.fires(new, tr.ratio_key, t, m, r))
            entry["reincidentes"] = [{"escopo": k[0], "entidade": k[1], "protocolo": k[2], "porta_local": k[3],
                                      "porta_remota": k[4], "alarmes": c} for k, c in tr.offenders.most_common(5)]
            by_name[rule_name]["limits"][vscope].update(new)
            report.append(entry)
        return {"minutos_com_dados": len(self.minutes), "dias": round(days, 2),
                "entidade_minutos_ignorados_por_ataque": len(self.ignored), "regras": report,
                "linha_de_base": self.baseline_rows()}, proposal

    def baseline_rows(self, min_samples=None):
        """[(regra, escopo, tipo de dia, hora, metrica, p99_9, p50, amostras)] por hora local com dados."""
        from .baseline import MIN_SAMPLES
        min_samples = min_samples or MIN_SAMPLES
        out = []
        for (rule_name, vscope), tr in sorted(self.tracks.items()):
            by_slot = defaultdict(list)
            for i, sl in enumerate(tr.slot):
                by_slot[sl].append(i)
            for sl, idx in sorted(by_slot.items()):
                if len(idx) < min_samples:
                    continue
                daytype, hour = ("wke" if sl >= 24 else "wkd"), sl % 24
                for metric, values in (("min_pps", tr.sig), ("min_mbps", tr.mbps)):
                    if metric in tr.limits:
                        vals = [values[i] for i in idx]
                        out.append((rule_name, vscope, daytype, hour, metric, round(percentile(vals, .999), 4),
                                    round(percentile(vals, .5), 4), len(vals)))
        return out


def calibrate_nat(cfg, rows, proposal, factor=2.0):
    allocs = [float(r["allocs"]) for r in rows]
    ports = [float(r["active_ports"]) for r in rows]
    report = []
    for rule in proposal["nat_rules"]:
        entry = {"regra": rule["name"], "amostras": len(allocs)}
        for metric, values in (("min_allocs_per_min", allocs), ("min_active_ports", ports)):
            if metric not in rule:
                continue
            entry[metric] = {"atual": rule[metric], "p99_9": round(percentile(values, .999), 1),
                             "maximo": round(max(values, default=0.0), 1)}
            if len(values) >= 100:
                raw = max(percentile(values, .999) * factor, NAT_FLOOR[metric])
                rule[metric] = round_up(min(max(raw, rule[metric] * 0.5), rule[metric] * 4.0))
            entry[metric]["proposto"] = rule[metric]
        report.append(entry)
    return report


def attack_minutes(events, margin=5):
    out = set()
    for when, local_ip, subscriber_ip in events:
        minute = int(when.replace(tzinfo=timezone.utc).timestamp() // 60)
        for entity in {local_ip, subscriber_ip} - {""}:
            for m in range(minute - margin, minute + margin + 1):
                out.add((entity, m))
    return frozenset(out)


def run(cfg, hours=24, factor=2.0, now=None, max_down=0.5, max_up=4.0, save_baseline=False):
    from .mysql_sink import connection_from_env
    import pymysql.cursors
    end = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(
        tzinfo=None, second=0, microsecond=0) - timedelta(minutes=cfg["settle_minutes"] + 1)
    start = end - timedelta(hours=hours)
    # uma hora do detalhado pode levar mais de 30 s para comecar a chegar com o banco ocupado (ordenacao no
    # servidor): o padrao de 30 s derrubava a conexao ("Lost connection ... timed out") e a calibracao falhava
    db = connection_from_env(read_timeout=900)
    try:
        with db.cursor() as cur:
            cur.execute(EVENTS_SQL, (start, end))
            attacks = attack_minutes(cur.fetchall())
            cur.execute(NAT_SQL, (start, end))
            nat_rows = [dict(zip(("bucket_utc", "inside_ip", "allocs", "active_ports"), r)) for r in cur.fetchall()]
            from .exceptions import load as load_exceptions
            exc = load_exceptions(cur, end)
        cal = Calibrator(cfg, attacks, exc)
        names = ("bucket_utc", "direction", "scope", "local_ip", "subscriber_ip", "protocol",
                 "local_port", "remote_port", "packets", "bytes", "syn_packets", "zero_port_packets")
        hour = start
        while hour < end:                       # uma hora por consulta: tabelas temporarias pequenas
            nxt = min(hour + timedelta(hours=1), end)
            with db.cursor(pymysql.cursors.SSCursor) as cur:
                cur.execute(ROWS_SQL + " ORDER BY bucket_utc", (cfg["source"], hour, nxt))
                for values in cur:
                    cal.add(dict(zip(names, values)))
            hour = nxt
    finally:
        db.close()
    summary, proposal = cal.finish(factor, max_down=max_down, max_up=max_up)
    summary["nat"] = calibrate_nat(cfg, nat_rows, proposal, factor)
    if save_baseline:
        if hours < 23:
            raise ValueError("--baseline precisa de --hours 23 ou mais (um dia inteiro)")
        from .baseline import merge
        day = (end.replace(tzinfo=timezone.utc).astimezone(cal.tz)).date()
        db = connection_from_env()
        try:
            with db.cursor() as cur:
                summary["linha_de_base_gravada"] = merge(cur, summary["linha_de_base"], day)
            db.commit()
        except Exception as exc:        # tabela ausente/sem permissao: a proposta de limites sai mesmo assim
            summary["linha_de_base_erro"] = str(exc)[:200]
        finally:
            db.close()
    summary["periodo_utc"] = [start.isoformat(), end.isoformat()]
    summary["fator"] = factor
    return summary, validate_config(proposal)


def render(summary):
    lines = ["Periodo UTC %s ate %s | %d minutos com dados (%.2f dias) | fator %.1f x p99,9" % (
        summary["periodo_utc"][0], summary["periodo_utc"][1], summary["minutos_com_dados"],
        summary["dias"], summary["fator"])]
    lines.append("%-34s %-17s %-8s %8s %10s | %-29s | %-29s | %s" % (
        "regra", "escopo", "sinal", "amostras", "alarm/dia", "pps atual -> proposto (p99,9)",
        "Mbps atual -> proposto (p99,9)", "min acima"))
    for e in summary["regras"]:
        cell = []
        for metric in ("min_pps", "min_mbps"):
            m = e.get(metric)
            cell.append("%s -> %s%s (%s)" % (m["atual"], m["proposto"], "*" if m["limitado"] else "",
                                              m["p99_9"]) if m else "-")
        lines.append("%-34s %-17s %-8s %8d %10s | %-29s | %-29s | %d" % (
            e["regra"][:34], e["escopo"], e["sinal"], e["amostras"], e["alarmes_atuais_por_dia"],
            cell[0], cell[1], e["minutos_acima_do_proposto"]))
    for e in summary["nat"]:
        for metric in ("min_allocs_per_min", "min_active_ports"):
            if metric in e:
                m = e[metric]
                lines.append("NAT %-30s %-17s %8d            | %s %s -> %s (p99,9 %s)" % (
                    e["regra"][:30], "assinante", e["amostras"], metric, m["atual"], m["proposto"], m["p99_9"]))
    lines.append("* = limitado pela trava da rodada (no maximo metade ou 4x do atual); rode de novo amanha.")
    lines.append("alarm/dia e min acima nao consideram o numero de IPs remotos: sao um teto.")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="OrbyFlow F4: calibracao dos limites com o trafego real")
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--hours", type=int, default=24, help="periodo analisado (o rollup guarda 2 dias)")
    ap.add_argument("--factor", type=float, default=2.0, help="limite = p99,9 x fator (padrao 2)")
    ap.add_argument("--max-down", type=float, default=0.5, help="limite novo >= atual x este valor")
    ap.add_argument("--max-up", type=float, default=4.0, help="limite novo <= atual x este valor")
    ap.add_argument("--write", help="grava a configuracao proposta neste arquivo")
    ap.add_argument("--json", help="grava o relatorio completo em JSON neste arquivo")
    ap.add_argument("--apply", action="store_true", help="faz backup e aplica a proposta na configuracao")
    ap.add_argument("--baseline", action="store_true",
                    help="grava a linha de base por hora (orby_baseline); uma vez por dia, com --hours 24")
    args = ap.parse_args(argv)
    try:
        if not 1 <= args.hours <= 47 or not 1.2 <= args.factor <= 10:
            raise ValueError("--hours 1..47 e --factor 1.2..10")
        cfg = read_config(args.config)
        if not (0.1 <= args.max_down <= 1 and 1 <= args.max_up <= 20):
            raise ValueError("--max-down 0.1..1 e --max-up 1..20")
        summary, proposal = run(cfg, args.hours, args.factor, max_down=args.max_down, max_up=args.max_up,
                                save_baseline=args.baseline)
        print(render(summary))
        if args.baseline:
            if summary.get("linha_de_base_erro"):
                print("AVISO linha de base nao gravada (rode scripts/setup-baseline.sh): %s"
                      % summary["linha_de_base_erro"], file=sys.stderr)
            else:
                print("linha de base: %d hora(s) atualizadas" % summary.get("linha_de_base_gravada", 0))
        text = json.dumps(proposal, ensure_ascii=False, indent=2) + "\n"
        if args.json:
            Path(args.json).write_text(json.dumps(summary, ensure_ascii=False, indent=2, default=str) + "\n")
        if args.write:
            Path(args.write).write_text(text)
            print("proposta gravada em", args.write)
        if args.apply:
            if summary["minutos_com_dados"] < MIN_MINUTES:
                raise ValueError("so %d minutos de dados; aguarde pelo menos %d (6 h) antes de aplicar"
                                 % (summary["minutos_com_dados"], MIN_MINUTES))
            target = Path(os.path.realpath(args.config))   # segue o link para o diretorio do painel
            backup = target.with_name(target.name + ".bak." + datetime.now().strftime("%Y%m%d%H%M%S"))
            shutil.copy2(target, backup)            # mesmo conteudo e permissoes do original
            try:
                os.chown(backup, target.stat().st_uid, target.stat().st_gid)
            except PermissionError:
                pass
            tmp = target.with_name(target.name + ".tmp")
            tmp.write_text(text)
            os.chmod(tmp, 0o640)
            try:
                os.chown(tmp, target.stat().st_uid, target.stat().st_gid)
            except PermissionError:
                pass
            tmp.replace(target)
            print("APLICADO. Backup: %s (o detector usa a configuracao nova no proximo minuto)" % backup)
        return 0
    except Exception as exc:
        print("FALHA calibracao: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
