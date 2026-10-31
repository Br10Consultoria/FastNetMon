"""Read-only health check of the existing A10 TCP syslog receiver on flow.

No restart, network connections, file-content reads, log deletion or output
of subscriber data. All checks are passive and deliberately conservative:
healthy services do NOT prove that CGNAT events were delivered intact.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

from .a10_storage_inventory import DEFAULT_DIR, inventory


def _run(args: list[str]) -> str | None:
    """A small, fixed allowlist of read-only system commands; no shell."""
    if args[:2] not in (["systemctl", "show"], ["ss", "-H"]):
        raise ValueError("Comando nao permitido")
    try:
        result = subprocess.run(args, capture_output=True, text=True,
                                timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout if result.returncode == 0 else None


def _systemd_properties(unit: str, fields: tuple[str, ...]) -> dict[str, str] | None:
    if unit not in ("rsyslog.service", "orbymon-a10-logrotate.timer",
                    "orbymon-a10-logrotate.service"):
        raise ValueError("Unit nao permitida")
    output = _run(["systemctl", "show", unit,
                   *["-p" + field for field in fields], "--no-pager"])
    if output is None:
        return None
    values = {}
    for line in output.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in fields:
            values[key] = value
    return values


def _listener_summary(port: int) -> dict:
    output = _run(["ss", "-H", "-ltn"])
    if output is None:
        return {"verificavel": False, "escutando": None, "escutas": 0}
    matched = 0
    recv_max = 0
    backlog_max = 0
    for line in output.splitlines():
        fields = line.split()
        # "LISTEN 0 25 0.0.0.0:5514 0.0.0.0:*"
        if len(fields) < 5 or fields[0] != "LISTEN":
            continue
        local_port = fields[3].rpartition(":")[2]
        if not local_port.isdigit() or int(local_port) != port:
            continue
        matched += 1
        try:
            recv_max = max(recv_max, int(fields[1]))
            backlog_max = max(backlog_max, int(fields[2]))
        except (ValueError, IndexError):
            pass
    return {
        "verificavel": True, "escutando": bool(matched),
        "escutas": matched, "fila_recebimento_maxima": recv_max,
        "backlog_configurado_maximo": backlog_max,
    }


def evaluate_health(*, rsyslog_active: bool | None,
                    listener: dict, timer_active: bool | None,
                    rotation_result: str | None,
                    rotation_last_age_seconds: float | None,
                    storage: dict,
                    freshness_warning: float = 120,
                    freshness_critical: float = 300,
                    rotation_warning: float = 5400) -> dict:
    """Strict thresholds and status; even an OK is NOT delivery homologation."""
    if not 0 < freshness_warning < freshness_critical:
        raise ValueError("Limites de atividade invalidos")
    if rotation_warning <= 0:
        raise ValueError("Limite de rotacao invalido")
    critical = []
    warnings = []
    unknown = []

    if rsyslog_active is False:
        critical.append("rsyslog_inativo")
    elif rsyslog_active is None:
        unknown.append("estado_rsyslog_indisponivel")

    if listener["escutando"] is False:
        critical.append("tcp_5514_sem_escuta")
    elif listener["escutando"] is None:
        unknown.append("escuta_tcp_nao_verificavel")
    elif listener.get("fila_recebimento_maxima", 0) > 0:
        # A queue >0 is a *snapshot*, not evidence of dropped records.
        warnings.append("fila_tcp_recebimento_nao_vazia_no_instante")

    if timer_active is False:
        warnings.append("timer_rotacao_inativo")
    elif timer_active is None:
        unknown.append("timer_rotacao_nao_verificavel")

    if rotation_result not in (None, "success"):
        warnings.append("ultima_execucao_rotacao_com_falha")
    elif rotation_result is None:
        unknown.append("resultado_rotacao_indisponivel")

    if rotation_last_age_seconds is None:
        unknown.append("ultimo_termino_rotacao_indisponivel")
    elif rotation_last_age_seconds > rotation_warning:
        warnings.append("rotacao_sem_execucao_recente")

    if not storage.get("arquivo_ativo_existe", False):
        critical.append("arquivo_ativo_ausente")
    else:
        age = storage.get("arquivo_ativo_sem_modificacao_segundos")
        if age is None:
            unknown.append("idade_arquivo_indisponivel")
        elif age >= freshness_critical:
            critical.append("arquivo_sem_gravacao_recente")
        elif age >= freshness_warning:
            warnings.append("arquivo_com_gravacao_atrasada")

    free_pct = storage.get("disco_livre_percentual")
    if free_pct is None:
        unknown.append("espaco_livre_nao_verificavel")
    elif free_pct < 10:
        critical.append("disco_livre_abaixo_10_porcento")
    elif free_pct < 20:
        warnings.append("disco_livre_abaixo_20_porcento")

    state = ("critico" if critical else "atencao" if warnings else
             "inconclusivo" if unknown else "operacional_na_amostra")
    return {
        "status": state,
        "alertas_criticos": critical,
        "alertas_atencao": warnings,
        "verificacoes_indisponiveis": unknown,
        "rsyslog_ativo": rsyslog_active,
        "tcp_5514": listener,
        "timer_rotacao_ativo": timer_active,
        "resultado_ultima_rotacao": rotation_result,
        "segundos_desde_ultima_rotacao": (
            round(rotation_last_age_seconds, 1)
            if rotation_last_age_seconds is not None else None
        ),
        "arquivo_ativo_modificado_ha_segundos": storage.get(
            "arquivo_ativo_sem_modificacao_segundos"
        ),
        "disco_livre_percentual": free_pct,
        "disco_livre_gib": storage.get("disco_livre_gib"),
        "total_logs_gib": storage.get("total_de_arquivos_regulares_gib"),
        "arquivos_compactados": storage.get("grupos", {}).get(
            "rotacionados_comprimidos", {}).get("arquivos"),
        "homologacao_entrega_syslog": False,
        "historico_cgnat_integral_comprovado": False,
        "observacao": (
            "Verifica disponibilidade e metadados locais. Nao comprova "
            "completude do fluxo RFC5424/TCP, entrega de mensagens, "
            "integridade da retencao ou correlacao com clientes."
        ),
    }


def _rotation_age(props: dict[str, str] | None) -> float | None:
    if not props:
        return None
    raw = props.get("ExecMainExitTimestampMonotonic")
    if not raw or not raw.isdigit() or int(raw) == 0:
        return None
    # systemd ExecMainExitTimestampMonotonic is microseconds from the
    # system's CLOCK_MONOTONIC epoch (not wall-clock time).
    if not hasattr(time, "CLOCK_MONOTONIC"):
        return None
    return max(0.0, time.clock_gettime(time.CLOCK_MONOTONIC) -
               int(raw) / 1_000_000)


def probe(log_directory: Path = DEFAULT_DIR, *, port: int = 5514) -> dict:
    if not 1 <= port <= 65535:
        raise ValueError("Porta TCP invalida")
    storage = inventory(log_directory)
    rsyslog = _systemd_properties("rsyslog.service", ("ActiveState",))
    timer = _systemd_properties("orbymon-a10-logrotate.timer", ("ActiveState",))
    service = _systemd_properties(
        "orbymon-a10-logrotate.service",
        ("Result", "ExecMainExitTimestampMonotonic"),
    )
    result = evaluate_health(
        rsyslog_active=(rsyslog.get("ActiveState") == "active") if rsyslog else None,
        listener=_listener_summary(port),
        timer_active=(timer.get("ActiveState") == "active") if timer else None,
        rotation_result=service.get("Result") if service else None,
        rotation_last_age_seconds=_rotation_age(service),
        storage=storage,
    )
    result["porta_tcp_observada"] = port
    result["inventario_de_armazenamento"] = storage
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="A10 flow: checagem passiva de rsyslog, TCP, rotacao e disco")
    parser.add_argument("--log-dir", type=Path, default=DEFAULT_DIR)
    parser.add_argument("--port", type=int, default=5514)
    args = parser.parse_args(argv)
    try:
        result = probe(args.log_dir, port=args.port)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError) as exc:
        print("Falha no diagnostico passivo A10: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
