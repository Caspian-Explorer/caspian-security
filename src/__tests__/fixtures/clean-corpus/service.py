"""Idiomatic, SECURE Python service module.

Nothing here should trigger an Error- or Warning-severity finding —
this file guards against false-positive regressions.
"""

import hashlib
import hmac
import os
import secrets

import psycopg2


def get_connection():
    return psycopg2.connect(dsn=os.environ["DATABASE_URL"])


def find_user(conn, email: str):
    with conn.cursor() as cur:
        cur.execute("SELECT id, email FROM users WHERE email = %s", (email,))
        return cur.fetchone()


def create_session_token() -> str:
    return secrets.token_urlsafe(32)


def verify_signature(payload: bytes, signature: str) -> bool:
    key = os.environ["WEBHOOK_SIGNING_KEY"].encode()
    expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def store_upload(base_dir: str, filename: str) -> str:
    safe_name = os.path.basename(filename)
    target = os.path.normpath(os.path.join(base_dir, safe_name))
    if not target.startswith(os.path.abspath(base_dir)):
        raise ValueError("invalid path")
    return target
