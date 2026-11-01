"""Linha de base por hora do dia (dias uteis x fim de semana) e limites dinamicos do detector.

A calibracao diaria mede, para cada regra e tipo de IP, o p99,9 do sinal por entidade/minuto em cada hora
local e grava em orby_baseline como media movel entre dias. Com o limite dinamico ligado
(bidir.json -> dynamic_thresholds.enabled), o detector usa em cada minuto:

    limite = min(limite fixo, max(p99,9 da hora x fator, limite fixo x piso))

Ou seja: nas horas calmas o limite desce (pega ataque menor de madrugada) e nunca fica acima do limite
fixo calibrado; o piso impede que desca demais. Sem dias suficientes de historico na hora, vale o fixo.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
import math
from zoneinfo import ZoneInfo

DEFAULTS = {"enabled": False, "factor": 2.0, "min_days": 3, "floor_ratio": 0.25, "timezone": "America/Sao_Paulo"}
METRICS = ("min_pps", "min_mbps")
DAYTYPES = {"wkd": "dias úteis", "wke": "fim de semana"}
MIN_SAMPLES = 30          # amostras (entidade x minuto) na hora para a hora valer
ALPHA_MIN = 0.2           # peso minimo do dia novo na media movel (~ ultimas 5 semanas)


def validate_settings(obj):
    if not isinstance(obj, dict) or set(obj) - set(DEFAULTS):
        raise ValueError("dynamic_thresholds: campos " + ",".join(sorted(DEFAULTS)))
    out = dict(DEFAULTS)
    out.update(obj)
    if type(out["enabled"]) is not bool:
        raise ValueError("dynamic_thresholds.enabled deve ser booleano")
    for key, low, high in (("factor", 1.2, 10), ("floor_ratio", 0.05, 1)):
        if type(out[key]) not in (int, float) or not math.isfinite(out[key]) or not low <= out[key] <= high:
            raise ValueError("dynamic_thresholds.%s entre %s e %s" % (key, low, high))
    if type(out["min_days"]) is not int or not 1 <= out["min_days"] <= 28:
        raise ValueError("dynamic_thresholds.min_days entre 1 e 28")
    try:
        ZoneInfo(out["timezone"])
    except Exception:
        raise ValueError("dynamic_thresholds.timezone invalido")
    return out


def settings(cfg):
    return validate_settings(cfg.get("dynamic_thresholds") or {})


def slot(when_utc, tz):
    """(tipo de dia, hora local) de um minuto UTC (naive)."""
    local = when_utc.replace(tzinfo=timezone.utc).astimezone(tz if isinstance(tz, ZoneInfo) else ZoneInfo(tz))
    return ("wke" if local.weekday() >= 5 else "wkd"), local.hour


def load(cur):
    """{(regra, escopo, tipo, hora, metrica): (p99_9, dias)}; vazio se a tabela nao existe."""
    try:
        cur.execute("SELECT rule_name,scope,daytype,hour,metric,p99_9,days FROM orby_baseline")
    except Exception as exc:
        if "orby_baseline" in str(exc):
            return {}
        raise
    return {(r[0], r[1], r[2], int(r[3]), r[4]): (float(r[5]), int(r[6])) for r in cur.fetchall()}


class Limits:
    """Limites efetivos por (regra, escopo, minuto), com cache por hora."""

    def __init__(self, cfg, table):
        self.st = settings(cfg)
        self.tz = ZoneInfo(self.st["timezone"])
        self.table = table if self.st["enabled"] else {}
        self._cache = {}

    def get(self, rule_name, scope, static, minute):
        if not self.table:
            return static, False
        key = (rule_name, scope, minute.replace(minute=0, second=0, microsecond=0))
        got = self._cache.get(key)
        if got is None:
            got = effective(rule_name, scope, static, slot(minute, self.tz), self.table, self.st)
            self._cache[key] = got
        return got


def effective(rule_name, scope, static, where, table, st):
    """(limites, dinamico?) para um slot (tipo de dia, hora)."""
    out, dynamic = dict(static), False
    for metric in METRICS:
        if metric not in static:
            continue
        base = table.get((rule_name, scope, where[0], where[1], metric))
        if not base or base[1] < st["min_days"]:
            continue
        value = min(static[metric], max(base[0] * st["factor"], static[metric] * st["floor_ratio"]))
        if value < static[metric]:
            out[metric], dynamic = round(value, 3), True
    return out, dynamic


def merge(cur, rows, day: date):
    """Incorpora as medidas do dia: rows = [(regra, escopo, tipo, hora, metrica, p99_9, p50, amostras)].
    Cada (chave, dia) entra uma vez so: rodar a calibracao de novo no mesmo dia nao pesa em dobro."""
    changed = 0
    for rule_name, scope, daytype, hour, metric, p999, p50, n in rows:
        cur.execute("SELECT p99_9,p50,days,last_day FROM orby_baseline WHERE rule_name=%s AND scope=%s AND "
                    "daytype=%s AND hour=%s AND metric=%s", (rule_name, scope, daytype, hour, metric))
        old = cur.fetchone()
        if old is None:
            cur.execute("INSERT INTO orby_baseline (rule_name,scope,daytype,hour,metric,p99_9,p50,samples,days,"
                        "last_day) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,1,%s)",
                        (rule_name, scope, daytype, hour, metric, p999, p50, n, day))
        elif old[3] is not None and old[3] >= day:
            continue
        else:
            days = int(old[2])
            alpha = max(1.0 / (days + 1), ALPHA_MIN)
            cur.execute("UPDATE orby_baseline SET p99_9=%s,p50=%s,samples=%s,days=%s,last_day=%s WHERE "
                        "rule_name=%s AND scope=%s AND daytype=%s AND hour=%s AND metric=%s",
                        (old[0] + (p999 - old[0]) * alpha, old[1] + (p50 - old[1]) * alpha, n, min(days + 1, 9999),
                         day, rule_name, scope, daytype, hour, metric))
        changed += 1
    return changed


def profile(table, cfg, rule, scope):
    """Para o painel: por tipo de dia, 24 horas com (p99_9, dias, limite efetivo) de cada metrica."""
    st = settings(cfg)
    static = rule["limits"][scope]
    forced = dict(st, enabled=True)
    out = {}
    for daytype in DAYTYPES:
        hours = []
        for hour in range(24):
            lim, dyn = effective(rule["name"], scope, static, (daytype, hour), table, forced)
            item = {"hour": hour, "dynamic": dyn}
            for metric in METRICS:
                if metric in static:
                    base = table.get((rule["name"], scope, daytype, hour, metric))
                    item[metric] = {"base": base[0] if base else None, "days": base[1] if base else 0,
                                    "limit": lim[metric], "static": static[metric]}
            hours.append(item)
        out[daytype] = hours
    return out
