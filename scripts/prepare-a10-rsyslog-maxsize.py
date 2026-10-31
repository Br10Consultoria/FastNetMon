#!/usr/bin/env python3
"""Stage the rsyslog 64k global message cap with backup and validation, no restart."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

MAIN = Path("/etc/rsyslog.conf")
CONF_D = Path("/etc/rsyslog.d")
SETTING = 'global(maxMessageSize="64k")'
PATTERN = re.compile(r'\bmaxmessagesize\s*=|\$maxmessagesize\b', re.I)


def find_settings(main_content, includes=()):
    found = []
    for path, content in [(str(MAIN), main_content), *includes]:
        for lineno, line in enumerate(content.splitlines(), 1):
            if not line.lstrip().startswith("#") and PATTERN.search(line):
                found.append((path, lineno))
    return found


def add_setting(content):
    if find_settings(content):
        raise ValueError("maxMessageSize ja configurado no arquivo principal")
    return SETTING + "\n" + content


def validate_rsyslog():
    result = subprocess.run(["rsyslogd", "-N1"], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError("rsyslogd -N1 falhou: " + result.stderr[-3500:])


def execute(apply):
    if os.geteuid() != 0:
        raise RuntimeError("Execute como root/sudo")
    if MAIN.is_symlink() or not MAIN.is_file():
        raise RuntimeError("/etc/rsyslog.conf ausente ou symlink; revisao manual necessaria")
    original = MAIN.read_text(encoding="utf-8")
    includes = [(str(p), p.read_text(encoding="utf-8"))
                for p in sorted(CONF_D.glob("*.conf")) if p.is_file()]
    existing = find_settings(original, includes)
    if existing:
        print("[ATENCAO] maxMessageSize ja configurado em " +
              ", ".join(f"{path}:{lineno}" for path, lineno in existing))
        print("Revisar antes de aplicar nova diretiva.")
        return 2
    validate_rsyslog()
    if not apply:
        print("[CHECK] rsyslogd -N1 OK e nenhuma diretiva maxMessageSize encontrada.")
        print("[CHECK] Proposta: primeira linha de /etc/rsyslog.conf -> " + SETTING)
        print("[CHECK] Arquivos e servicos inalterados.")
        return 0

    backup = MAIN.with_name("rsyslog.conf.orbymon-before64k-" +
                            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".bak")
    if backup.exists():
        raise RuntimeError("Backup com o mesmo nome ja existe; nao sobrescrever.")
    original_mode = stat.S_IMODE(MAIN.stat().st_mode)
    shutil.copy2(MAIN, backup)
    backup.chmod(0o600)
    tempname = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=MAIN.parent,
                                         prefix=".rsyslog-orbymon-", delete=False) as h:
            tempname = h.name
            h.write(add_setting(original))
            h.flush()
            os.fsync(h.fileno())
        os.chmod(tempname, original_mode)
        os.replace(tempname, MAIN)
        tempname = None
        try:
            validate_rsyslog()
        except RuntimeError:
            shutil.copy2(backup, MAIN)
            MAIN.chmod(original_mode)
            raise
    finally:
        if tempname and os.path.exists(tempname):
            os.unlink(tempname)
    print("[OK] Configuracao 64k validada; rsyslog NAO foi reiniciado.")
    print("[BACKUP] " + str(backup))
    print("[AVISO] O limite e global e pode elevar memoria usada por todos os inputs.")
    print("[APLICAR EM JANELA] sudo systemctl restart rsyslog")
    print("[VALIDAR] sudo ss -lntp | grep ':5514' e auditar novos dados A10")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="Preparar rsyslog 64k para A10 sem restart")
    p.add_argument("--apply", action="store_true", help="Gravar apos backup e validação; nao reiniciar")
    args = p.parse_args(argv)
    try:
        return execute(args.apply)
    except (OSError, RuntimeError, UnicodeError, ValueError) as exc:
        print("[ERRO] " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
