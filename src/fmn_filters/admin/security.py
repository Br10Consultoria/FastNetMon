"""Senhas (scrypt), TOTP (RFC 6238) e utilitarios de seguranca do painel. So biblioteca padrao."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1
MIN_PASSWORD = 12


def hash_password(password: str) -> str:
    if len(password) < MIN_PASSWORD:
        raise ValueError("a senha precisa de pelo menos %d caracteres" % MIN_PASSWORD)
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    return "scrypt$%d$%d$%d$%s$%s" % (SCRYPT_N, SCRYPT_R, SCRYPT_P, salt.hex(), digest.hex())


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, digest = stored.split("$")
        if algo != "scrypt":
            return False
        test = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p),
                              dklen=len(bytes.fromhex(digest)))
        return hmac.compare_digest(test, bytes.fromhex(digest))
    except (ValueError, TypeError):
        return False


DUMMY_HASH = hash_password("x" * MIN_PASSWORD)   # mesmo custo quando o usuario nao existe


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return "%06d" % code


def totp_now(secret: str, at: float | None = None) -> str:
    return _hotp(secret, int((time.time() if at is None else at) // 30))


def verify_totp(secret: str, code: str, last_step: int = -1, at: float | None = None, window: int = 1):
    """Retorna o passo aceito (para impedir reuso do mesmo codigo) ou None."""
    code = (code or "").strip().replace(" ", "")
    if not (len(code) == 6 and code.isdigit()):
        return None
    step = int((time.time() if at is None else at) // 30)
    for candidate in range(step - window, step + window + 1):
        if candidate > last_step and hmac.compare_digest(_hotp(secret, candidate), code):
            return candidate
    return None


def otpauth_uri(secret: str, username: str, issuer: str = "OrbyMon") -> str:
    label = urllib.parse.quote("%s:%s" % (issuer, username))
    return "otpauth://totp/%s?%s" % (label, urllib.parse.urlencode(
        {"secret": secret, "issuer": issuer, "algorithm": "SHA1", "digits": 6, "period": 30}))


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def same_token(a, b) -> bool:
    return bool(a) and bool(b) and hmac.compare_digest(str(a), str(b))
