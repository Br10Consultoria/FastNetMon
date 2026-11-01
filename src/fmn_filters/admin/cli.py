"""Linha de comando do painel: python -m fmn_filters.admin.cli <comando> <usuario>

  create-user NOME   cria usuario (senha pedida no terminal; 2FA ativado no primeiro acesso)
  set-password NOME  redefine a senha (troca obrigatoria no proximo acesso)
  reset-2fa NOME     apaga o 2FA (novo QR code no proximo acesso)
  unlock NOME        limpa as tentativas de login falhas
  enable/disable NOME
  list
"""
from __future__ import annotations

import getpass
import sys

from . import security
from .db import Store


def _password():
    first = getpass.getpass("Senha (minimo 12 caracteres; nao aparece na tela): ")
    if first != getpass.getpass("Confirme: "):
        raise ValueError("as senhas nao conferem")
    return security.hash_password(first)


def main(argv=None, store=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    store = store or Store()
    cmd, name = argv[0], (argv[1].strip().lower() if len(argv) > 1 else "")
    try:
        if cmd == "list":
            for u in store.users():
                print("%-24s 2fa=%s desativado=%s ultimo_acesso=%s" % (
                    u["username"], "sim" if u["totp_enabled"] else "nao", "sim" if u["disabled"] else "nao",
                    u["last_login"] or "-"))
            return 0
        from .app import USERNAME
        if not USERNAME.match(name):
            raise ValueError("usuario: 3 a 40 caracteres (a-z, 0-9, . _ -)")
        user = store.user(username=name)
        if cmd == "create-user":
            if user:
                raise ValueError("usuario ja existe")
            store.create_user(name, _password(), must_change=False)
        elif not user:
            raise ValueError("usuario nao encontrado")
        elif cmd == "set-password":
            store.set_password(user["id"], _password(), must_change=True)
        elif cmd == "reset-2fa":
            store.set_totp(user["id"], None, False)
        elif cmd == "unlock":
            store.clear_fails(name)
        elif cmd in ("enable", "disable"):
            store.set_disabled(user["id"], cmd == "disable")
        else:
            raise ValueError("comando desconhecido: " + cmd)
        store.audit("terminal", "local", "cli_" + cmd.replace("-", "_"), name)
        print("ok: %s %s" % (cmd, name))
        return 0
    except Exception as exc:
        print("FALHA: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
