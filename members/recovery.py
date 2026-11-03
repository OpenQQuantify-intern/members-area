"""Self-service password recovery without disclosing account information."""

import hashlib
import re
import secrets
import time

from flask import (
    Blueprint, current_app, flash, g, jsonify, make_response,
    redirect, render_template, request, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from . import mail
from .db import get_db
from .forms import ForgotPasswordForm, ResetPasswordForm
from .security import consume_auth_attempt

bp = Blueprint("recovery", __name__)
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
INVALID_LINK = "This link is invalid or has expired. Please request a new one."


class InvalidReset(Exception):
    pass


def digest_token(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def find_reset(token):
    if not isinstance(token, str) or not TOKEN_PATTERN.fullmatch(token):
        return None
    return get_db().execute(
        """SELECT r.id AS reset_id, r.user_id, u.email, u.password_hash, u.session_version
           FROM password_reset_tokens AS r JOIN users AS u ON u.id = r.user_id
           WHERE r.token_hash = ? AND r.used_at IS NULL AND r.expires_at > ?
             AND u.is_blocked = 0""",
        (digest_token(token), int(time.time())),
    ).fetchone()


def issue_reset(email):
    """Create one active token while the account is still eligible."""
    db = get_db()
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    with db:
        db.execute("BEGIN IMMEDIATE")
        user = db.execute(
            "SELECT id, email FROM users WHERE email = ? AND is_blocked = 0", (email,),
        ).fetchone()
        if user is None:
            return None
        db.execute("DELETE FROM password_reset_tokens WHERE expires_at <= ?", (now,))
        db.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (user["id"],))
        db.execute(
            "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
            (user["id"], digest_token(token), now + current_app.config["RESET_TOKEN_SECONDS"]),
        )
    return user["email"], token


def invalid_link_response(status=400):
    return make_response(render_template(
        "recovery/invalid.html", message=INVALID_LINK,
    ), status)


def throttle(scope, identity, as_json=False):
    retry_after = consume_auth_attempt(scope, identity)
    if not retry_after:
        return None
    if as_json:
        response = jsonify(valid=False, message="Too many attempts. Please try again later.")
        response.status_code = 429
    else:
        response = make_response(render_template(
            "error.html", title="Please try again later",
            message="There have been too many recovery attempts. Please wait before trying again.",
        ), 429)
    response.headers["Retry-After"] = str(retry_after)
    return response


@bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    form = ForgotPasswordForm()
    valid = form.validate_on_submit()
    if request.method == "POST":
        limited = throttle("forgot", form.email.data if valid else "invalid-input")
        if limited is not None:
            return limited
    if valid:
        # Global missing configuration gives the same result for every address.
        if not mail.mail_configured():
            return make_response(render_template(
                "error.html", title="Please try again later",
                message="Password recovery is temporarily unavailable. Please try again later.",
            ), 503)
        issued = issue_reset(form.email.data)
        if issued is not None:
            recipient, token = issued
            # A URL fragment is not sent to servers or recorded in access logs.
            reset_url = current_app.config["PUBLIC_BASE_URL"] + url_for("recovery.reset_password") + "#token=" + token
            try:
                mail.send_reset_email(recipient, reset_url)
            except mail.DeliveryError as error:
                db = get_db()
                with db:
                    db.execute("DELETE FROM password_reset_tokens WHERE token_hash = ?", (digest_token(token),))
                current_app.logger.warning("Password-reset email delivery failed: %s", error)
        # Same redirect/content whether unknown, blocked, accepted, or rejected by provider.
        return redirect(url_for("recovery.forgot_sent"), code=303)
    return render_template("recovery/forgot.html", form=form), (400 if request.method == "POST" else 200)


@bp.get("/forgot-password/sent")
def forgot_sent():
    return render_template("recovery/sent.html")


@bp.post("/reset-password/check")
def check_link():
    token = request.form.get("token", "")
    identity = digest_token(token) if TOKEN_PATTERN.fullmatch(token) else "invalid-input"
    limited = throttle("reset_check", identity, as_json=True)
    if limited is not None:
        return limited
    if find_reset(token) is None:
        return jsonify(valid=False, message=INVALID_LINK), 400
    return jsonify(valid=True)


def redeem_reset(token, password_hash, verified):
    """Consume the token and revoke credentials/sessions in one transaction."""
    db = get_db()
    with db:
        db.execute("BEGIN IMMEDIATE")
        current = find_reset(token)
        if (current is None or current["reset_id"] != verified["reset_id"]
                or current["user_id"] != verified["user_id"]
                or current["session_version"] != verified["session_version"]
                or current["password_hash"] != verified["password_hash"]):
            raise InvalidReset
        now = int(time.time())
        consumed = db.execute(
            "UPDATE password_reset_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL AND expires_at > ?",
            (now, current["reset_id"], now),
        )
        if consumed.rowcount != 1:
            raise InvalidReset
        db.execute(
            "UPDATE users SET password_hash = ?, session_version = session_version + 1 WHERE id = ?",
            (password_hash, current["user_id"]),
        )
        db.execute("DELETE FROM member_sessions WHERE user_id = ?", (current["user_id"],))
        db.execute(
            "DELETE FROM password_reset_tokens WHERE user_id = ? AND id != ?",
            (current["user_id"], current["reset_id"]),
        )
        # If this browser was signed into a different account, end that browser's
        # session too before clearing its cookie; preserve its other sessions.
        if g.auth_session_hash is not None:
            db.execute("DELETE FROM member_sessions WHERE token_hash = ?", (g.auth_session_hash,))


@bp.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    form = ResetPasswordForm()
    if request.method == "GET":
        return render_template("recovery/reset.html", form=form, ready=False)
    token = form.token.data or ""
    identity = digest_token(token) if TOKEN_PATTERN.fullmatch(token) else "invalid-input"
    limited = throttle("reset", identity)
    if limited is not None:
        return limited
    verified = find_reset(token)
    if verified is None:
        return invalid_link_response()
    if not form.validate_on_submit():
        return render_template("recovery/reset.html", form=form, ready=True), 400
    if check_password_hash(verified["password_hash"], form.new_password.data):
        form.new_password.errors.append("Choose a password different from your current one.")
        return render_template("recovery/reset.html", form=form, ready=True), 400
    password_hash = generate_password_hash(form.new_password.data)
    try:
        redeem_reset(token, password_hash, verified)
    except InvalidReset:
        return invalid_link_response()
    session.clear()
    flash("Your password was reset. Please log in with your new password. All previous sessions have been signed out.", "success")
    try:
        mail.send_password_changed_email(verified["email"])
    except mail.DeliveryError as error:
        current_app.logger.warning("Password-change notification delivery failed: %s", error)
    return redirect(url_for("auth.login"), code=303)
