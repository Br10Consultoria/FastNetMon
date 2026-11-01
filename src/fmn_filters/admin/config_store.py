"""Leitura e gravacao validada, atomica e com backup dos arquivos de configuracao do OrbyMon."""
from __future__ import annotations

import copy
from datetime import datetime
from ipaddress import ip_address, ip_network
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

from ..bidir_config import build_scopes, validate_config
from ..cgnat_baseline import validate_config as validate_profile

ENV_VALUE = re.compile(r"^[^'\\\r\n\x00]*$")   # sem aspas simples, barra invertida ou quebra de linha


class Paths:
    def __init__(self, env=os.environ):
        self.config = Path(env.get("ORBYMON_CONFIG", "/etc/orbymon/bidir.json"))
        self.telegram = Path(env.get("ORBYMON_TELEGRAM_ENV", "/etc/orbymon/telegram.env"))
        self.retention = Path(env.get("ORBYMON_RETENTION_ENV", "/etc/orbymon/retention.env"))
        self.calibration = Path(env.get("ORBYMON_CALIBRATION_DIR", "/var/lib/orbymon/calibration"))
        self.backups = Path(env.get("ORBYMON_ADMIN_BACKUP_DIR", "/var/lib/orbymon/admin/backups"))


def read_env(path: Path) -> dict:
    """Le KEY=VALUE (com ou sem aspas). Nunca executa o arquivo."""
    out = {}
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        out[key.strip()] = value
    return out


def render_env(values: dict, header: str, keep_lines=()) -> str:
    lines = ["# " + header, "# Gerado pelo painel OrbyMon. Valores entre aspas simples; nao execute este arquivo."]
    for key, value in values.items():
        value = str(value)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or not ENV_VALUE.match(value):
            raise ValueError("valor invalido para %s (aspas simples, barra invertida e quebras de linha nao sao aceitas)" % key)
        lines.append("%s='%s'" % (key, value))
    lines.extend(keep_lines)
    return "\n".join(lines) + "\n"


class ConfigStore:
    def __init__(self, paths: Paths | None = None):
        self.p = paths or Paths()

    # ---------- leitura
    def bidir(self) -> dict:
        return validate_config(json.loads(self.p.config.read_text(encoding="utf-8")))

    def profile(self, cfg=None) -> dict:
        cfg = cfg or self.bidir()
        return validate_profile(json.loads(Path(cfg["cgnat_profile_path"]).read_text(encoding="utf-8")))

    def telegram(self) -> dict:
        return read_env(self.p.telegram)

    def retention(self) -> dict:
        return read_env(self.p.retention)

    # ---------- gravacao
    def _backup(self, path: Path):
        if path.exists():
            self.p.backups.mkdir(parents=True, exist_ok=True)
            target = self.p.backups / ("%s.%s" % (path.name, datetime.now().strftime("%Y%m%d-%H%M%S-%f")))
            shutil.copy2(path, target)
            os.chmod(target, 0o600)
            return target
        return None

    def _write(self, path: Path, text: str):
        """Atomico (arquivo temporario + rename) com o mesmo dono, grupo e permissao do original.
        Segue links simbolicos: /etc/orbymon/x -> /etc/orbymon/managed/x (diretorio do painel)."""
        path = Path(os.path.realpath(path))
        st = path.stat() if path.exists() else None
        self._backup(path)
        try:
            fd, tmp = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
        except PermissionError:
            # sem escrita no diretorio: grava no proprio arquivo (o dono e o painel)
            with open(path, "r+" if path.exists() else "w", encoding="utf-8") as fh:
                fh.seek(0)
                fh.write(text)
                fh.truncate()
                fh.flush()
                os.fsync(fh.fileno())
            return
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, (st.st_mode & 0o777) if st else 0o640)
            if st:
                try:
                    os.chown(tmp, st.st_uid, st.st_gid)
                except PermissionError:
                    try:
                        os.chown(tmp, -1, st.st_gid)
                    except PermissionError:
                        pass                   # diretorio setgid ja define o grupo
            os.replace(tmp, path)
        except Exception:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    def save_network(self, cfg: dict, profile: dict):
        """Valida configuracao e perfil juntos (como os servicos fazem) antes de gravar os dois."""
        cfg = validate_config(copy.deepcopy(cfg))
        profile = validate_profile(copy.deepcopy(profile))
        build_scopes(cfg, profile)
        self._write(Path(cfg["cgnat_profile_path"]), json.dumps(profile, ensure_ascii=False, indent=2) + "\n")
        self._write(self.p.config, json.dumps(cfg, ensure_ascii=False, indent=2) + "\n")

    def save_bidir(self, cfg: dict):
        cfg = validate_config(copy.deepcopy(cfg))
        build_scopes(cfg, self.profile(cfg))
        self._write(self.p.config, json.dumps(cfg, ensure_ascii=False, indent=2) + "\n")

    def save_telegram(self, values: dict):
        self._write(self.p.telegram, render_env(values, "Alertas OrbyMon no Telegram (contem o token: nao compartilhe)"))

    def save_retention(self, log_days: int, flow_days: int):
        """Somente os dias. O comando de envio a nuvem fica em retention-archive.conf (root, fora do painel)."""
        if not (1 <= log_days <= 3650 and 1 <= flow_days <= 3650):
            raise ValueError("dias de retencao entre 1 e 3650")
        self._write(self.p.retention, render_env(
            {"ORBYMON_LOG_RETENTION_DAYS": log_days, "ORBYMON_FLOW_RETENTION_DAYS": flow_days},
            "Retencao de arquivos do OrbyMon"))

    # ---------- calibracao
    def calibration_proposal(self):
        path = self.p.calibration / "bidir.proposed.json"
        if not path.exists():
            return None, None
        proposal = json.loads(path.read_text(encoding="utf-8"))
        reports = sorted(self.p.calibration.glob("relatorio-*.json"), key=lambda f: f.stat().st_mtime)
        report = None
        if reports:
            try:
                report = json.loads(reports[-1].read_text(encoding="utf-8"))
            except (OSError, ValueError):
                report = None
        return proposal, report

    def apply_calibration(self):
        """Aplica somente os limites da proposta; o resto da configuracao atual e preservado."""
        proposal, _ = self.calibration_proposal()
        if proposal is None:
            raise ValueError("nao ha proposta de calibracao")
        cfg = self.bidir()
        by_name = {r["name"]: r for r in proposal.get("rules", [])}
        changed = []
        for rule in cfg["rules"]:
            new = by_name.get(rule["name"])
            if not new:
                continue
            for scope, limits in rule["limits"].items():
                for metric in ("min_pps", "min_mbps"):
                    value = new.get("limits", {}).get(scope, {}).get(metric)
                    if metric in limits and value is not None and value != limits[metric]:
                        changed.append("%s/%s/%s: %s -> %s" % (rule["name"], scope, metric, limits[metric], value))
                        limits[metric] = value
        nat_new = {r["name"]: r for r in proposal.get("nat_rules", [])}
        for rule in cfg["nat_rules"]:
            for metric in ("min_allocs_per_min", "min_active_ports"):
                value = nat_new.get(rule["name"], {}).get(metric)
                if metric in rule and value is not None and value != rule[metric]:
                    changed.append("%s/%s: %s -> %s" % (rule["name"], metric, rule[metric], value))
                    rule[metric] = value
        self.save_bidir(cfg)
        return changed


def parse_cidrs(text: str, version=None, allow_host=True):
    out = []
    for raw in re.split(r"[\s,;]+", text or ""):
        if not raw:
            continue
        net = ip_network(raw, strict=not allow_host)
        if version and net.version != version:
            raise ValueError("%s nao e IPv%d" % (raw, version))
        out.append(str(net))
    return out


def parse_ips(text: str):
    return [str(ip_address(raw)) for raw in re.split(r"[\s,;]+", text or "") if raw]


def parse_ints(text: str, low, high):
    out = []
    for raw in re.split(r"[\s,;]+", text or ""):
        if not raw:
            continue
        raw = raw.upper().removeprefix("AS")
        value = int(raw)
        if not low <= value <= high:
            raise ValueError("%s fora do intervalo" % raw)
        out.append(value)
    return out
