"""Our registration, credentials, sessions, logout, and access-control logic."""

import hashlib
import secrets
import sqlite3
import time
from functools import wraps

from flask import (
    Blueprint, current_app, flash, g, make_response,
    redirect, render_template, request, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from .db import get_db
from .forms import LoginForm, RegistrationForm
from .security import consume_auth_attempt

bp = Blueprint("auth", __name__)
LOGIN_ERROR = "Unable to log in with those details."


def token_digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def load_current_user():
    """Validate server-side session, expiry, version, and blocked status."""
    g.user = None
    g.auth_session_hash = None
    token = session.get("auth_token")
    if token is None:
        return
    if not isinstance(token, str) or len(token) != 43:
        session.clear()
        return

    digest = token_digest(token)
    row = get_db().execute(
        """SELECT u.id, u.email, u.is_admin, u.is_blocked, u.created_at,
                  u.session_version, s.session_version AS login_version
           FROM member_sessions AS s JOIN users AS u ON u.id = s.user_id
           WHERE s.token_hash = ? AND s.expires_at > ?""",
        (digest, int(time.time())),
    ).fetchone()
    if row is None or row["is_blocked"] or row["session_version"] != row["login_version"]:
        session.clear()
        return
    # Password hashes and reset tokens never become template context.
    g.user = row
    g.auth_session_hash = digest


def login_required(view):
    @wraps(view)
    def protected(*args, **kwargs):
        if g.user is None:
            flash("Please log in to access the members area.", "info")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return protected


def begin_session(user):
    now = int(time.time())
    token = secrets.token_urlsafe(32)
    db = get_db()
    with db:
        db.execute("BEGIN IMMEDIATE")
        # Credential changes/deletion can race a login after its hash check.
        # Recheck the credential fingerprint inside the write transaction.
        active = db.execute(
            """SELECT id FROM users WHERE id = ? AND is_blocked = 0
               AND session_version = ? AND password_hash = ?""",
            (user["id"], user["session_version"], user["password_hash"]),
        ).fetchone()
        if active is None:
            return False
        db.execute("DELETE FROM member_sessions WHERE expires_at <= ?", (now,))
        db.execute(
            """INSERT INTO member_sessions (token_hash, user_id, session_version, expires_at)
               VALUES (?, ?, ?, ?)""",
            (token_digest(token), user["id"], user["session_version"],
             now + current_app.config["AUTH_SESSION_SECONDS"]),
        )
    # Drop the anonymous session/CSRF state before creating the login session.
    session.clear()
    session["auth_token"] = token
    session.permanent = True
    return True


def throttle_response(form, template, scope, validated):
    """All CSRF-valid POSTs are counted, including invalid input."""
    if request.method != "POST":
        return None
    identity = form.email.data if validated else "invalid-input"
    retry = consume_auth_attempt(scope, identity)
    if not retry:
        return None
    response = make_response(render_template(
        template, form=form, error="Too many attempts. Please try again later.",
    ), 429)
    response.headers["Retry-After"] = str(retry)
    return response


@bp.route("/register", methods=["GET", "POST"])
def register():
    if g.user is not None:
        return redirect(url_for("auth.members"))
    form = RegistrationForm()
    validated = form.validate_on_submit()
    throttled = throttle_response(form, "auth/register.html", "register", validated)
    if throttled is not None:
        return throttled
    error = None
    if validated:
        password_hash = generate_password_hash(form.password.data)
        db = get_db()
        try:
            with db:
                # No client-supplied role, status, or user ID is accepted.
                db.execute(
                    "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                    (form.email.data, password_hash),
                )
        except sqlite3.IntegrityError:
            error = "Unable to create an account with those details. If you already have an account, please log in."
        else:
            session.clear()
            flash("Your account is ready. Please log in.", "success")
            return redirect(url_for("auth.login"), code=303)
    return render_template("auth/register.html", form=form, error=error)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user is not None:
        return redirect(url_for("auth.members"))
    form = LoginForm()
    validated = form.validate_on_submit()
    throttled = throttle_response(form, "auth/login.html", "login", validated)
    if throttled is not None:
        return throttled
    error = None
    if validated:
        db = get_db()
        user = db.execute(
            "SELECT id, password_hash, session_version, is_blocked FROM users WHERE email = ?",
            (form.email.data,),
        ).fetchone()
        password_hash = user["password_hash"] if user else current_app.extensions["auth_dummy_hash"]
        password_ok = check_password_hash(password_hash, form.password.data)
        if user is not None and password_ok:
            # Recheck after hashing in case credentials/status changed meanwhile.
            current = db.execute(
                """SELECT id, session_version, password_hash FROM users
                   WHERE id = ? AND is_blocked = 0 AND password_hash = ?
                     AND session_version = ?""",
                (user["id"], user["password_hash"], user["session_version"]),
            ).fetchone()
            if current is not None and begin_session(current):
                # Ignore arbitrary `next` URLs to avoid open redirects.
                return redirect(url_for("auth.members"), code=303)
        error = LOGIN_ERROR
    return render_template("auth/login.html", form=form, error=error)


@bp.get("/members")
@login_required
def members():
    return render_template("members.html")


@bp.post("/logout")
@login_required
def logout():
    db = get_db()
    with db:
        db.execute("DELETE FROM member_sessions WHERE token_hash = ?", (g.auth_session_hash,))
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"), code=303)


def init_app(app):
    # Unknown emails still do a password-hash check, reducing timing differences.
    app.extensions["auth_dummy_hash"] = generate_password_hash(secrets.token_urlsafe(32))
    app.before_request(load_current_user)
