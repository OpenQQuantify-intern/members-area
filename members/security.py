"""SQLite-backed throttling for signup and login attempts."""

import hashlib
import hmac
import ipaddress
import time

from flask import current_app, request

from .db import get_db


def client_ip():
    """Trust PythonAnywhere's overwritten header only in its explicit host mode."""
    if (current_app.config["APP_ENV"] == "production"
            and current_app.config["PYTHONANYWHERE_PROXY"]):
        value = request.headers.get("X-Real-IP", "").strip()
        try:
            # Reject lists, ports, and zone identifiers; canonicalize IPv6.
            if "%" not in value:
                return str(ipaddress.ip_address(value))
        except ValueError:
            pass
    return request.remote_addr or "unknown"


def consume_auth_attempt(scope, identity):
    """Atomically count both IP and account attempts. Return retry seconds."""
    now = int(time.time())
    window = current_app.config["AUTH_WINDOW_SECONDS"]
    started = now - (now % window)
    expires = started + window
    prefix = "AUTH_" + scope.upper()
    limits = (
        ("ip", client_ip(), current_app.config[prefix + "_IP_LIMIT"]),
        ("account", identity, current_app.config[prefix + "_ACCOUNT_LIMIT"]),
    )
    db = get_db()
    retry_after = 0
    # The write lock prevents simultaneous workers from losing increments.
    with db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM auth_rate_limits WHERE expires_at <= ?", (now,))
        for kind, value, maximum in limits:
            key = hmac.new(
                current_app.secret_key.encode("utf-8"),
                f"{scope}:{kind}:{value}".encode("utf-8"), hashlib.sha256,
            ).hexdigest()
            db.execute(
                """INSERT INTO auth_rate_limits (bucket_key, window_start, attempts, expires_at)
                   VALUES (?, ?, 1, ?)
                   ON CONFLICT(bucket_key) DO UPDATE SET
                     attempts = CASE WHEN window_start = excluded.window_start
                                     THEN attempts + 1 ELSE 1 END,
                     window_start = excluded.window_start,
                     expires_at = excluded.expires_at""",
                (key, started, expires),
            )
            attempts = db.execute(
                "SELECT attempts FROM auth_rate_limits WHERE bucket_key = ?", (key,),
            ).fetchone()["attempts"]
            if attempts > maximum:
                retry_after = expires - now
    return retry_after
