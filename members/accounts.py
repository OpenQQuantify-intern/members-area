"""Own-account changes with password reauthentication and atomic authorization."""

import sqlite3
import time

from flask import Blueprint, flash, g, make_response, redirect, render_template, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from .auth import login_required
from .db import get_db
from .forms import ChangeEmailForm, ChangePasswordForm, DeleteAccountForm
from .security import consume_auth_attempt

bp = Blueprint("accounts", __name__)


class SessionChanged(Exception):
    """The account or session changed since this request was authenticated."""


def settings_response(active=None, form=None, status=200):
    forms = {
        "email_form": form if active == "email" else ChangeEmailForm(formdata=None),
        "password_form": form if active == "password" else ChangePasswordForm(formdata=None),
        "delete_form": form if active == "delete" else DeleteAccountForm(formdata=None),
    }
    return make_response(render_template("account.html", **forms), status)


def session_changed_response():
    session.clear()
    flash("Your account or session changed. Please log in again.", "info")
    return redirect(url_for("auth.login"), code=303)


def verify_current_password(password):
    """Read the current owner from the session identity, never a submitted ID."""
    user = get_db().execute(
        "SELECT id, email, password_hash, session_version, is_blocked FROM users WHERE id = ?",
        (g.user["id"],),
    ).fetchone()
    if user is None or user["is_blocked"] or user["session_version"] != g.user["session_version"]:
        raise SessionChanged
    if not check_password_hash(user["password_hash"], password):
        return None
    return user


def apply_change(action, value, user):
    """Commit a change only while the verified credentials/session still match."""
    db = get_db()
    with db:
        db.execute("BEGIN IMMEDIATE")
        # This is static SQL. Only parameter values come from input.
        owner_guard = """id = ? AND password_hash = ? AND session_version = ?
            AND is_blocked = 0 AND EXISTS (
                SELECT 1 FROM member_sessions AS s
                WHERE s.user_id = users.id AND s.token_hash = ?
                  AND s.session_version = users.session_version AND s.expires_at > ?
            )"""
        owner_values = (
            user["id"], user["password_hash"], user["session_version"],
            g.auth_session_hash, int(time.time()),
        )
        if action == "email":
            result = db.execute(
                "UPDATE users SET email = ?, session_version = session_version + 1 WHERE " + owner_guard,
                (value, *owner_values),
            )
        elif action == "password":
            result = db.execute(
                "UPDATE users SET password_hash = ?, session_version = session_version + 1 WHERE " + owner_guard,
                (value, *owner_values),
            )
        elif action == "delete":
            result = db.execute("DELETE FROM users WHERE " + owner_guard, owner_values)
        else:
            raise ValueError("Unknown account action")
        if result.rowcount != 1:
            # Raising inside the transaction rolls back every partial change.
            raise SessionChanged
        if action != "delete":
            db.execute("DELETE FROM member_sessions WHERE user_id = ?", (user["id"],))
            db.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (user["id"],))
        # Account deletion cascades to sessions/reset tokens via foreign keys.


def handle_change(action, form):
    retry_after = consume_auth_attempt("account", str(g.user["id"]))
    if retry_after:
        response = make_response(render_template(
            "error.html", title="Please try again later",
            message="There have been too many account-change attempts. Please wait before trying again.",
        ), 429)
        response.headers["Retry-After"] = str(retry_after)
        return response

    if not form.validate_on_submit():
        return settings_response(action, form, 400)
    try:
        user = verify_current_password(form.current_password.data)
    except SessionChanged:
        return session_changed_response()
    if user is None:
        form.current_password.errors.append("The current password is incorrect.")
        return settings_response(action, form, 400)

    value = None
    if action == "email":
        value = form.new_email.data
        if value == user["email"]:
            form.new_email.errors.append("Enter a different email address.")
            return settings_response(action, form, 400)
    elif action == "password":
        if form.new_password.data == form.current_password.data:
            form.new_password.errors.append("Choose a password different from your current one.")
            return settings_response(action, form, 400)
        # Hash before taking the write lock, then atomically recheck the owner.
        value = generate_password_hash(form.new_password.data)

    try:
        apply_change(action, value, user)
    except SessionChanged:
        return session_changed_response()
    except sqlite3.IntegrityError:
        if action != "email":
            raise
        form.new_email.errors.append("That email address cannot be used. Try a different email.")
        return settings_response(action, form, 400)

    session.clear()
    if action == "delete":
        flash("Your account has been deleted.", "success")
        return redirect(url_for("public.home"), code=303)
    message = (
        "Your email was updated. Please log in with your new email address."
        if action == "email" else
        "Your password was updated. Please log in with your new password."
    )
    flash(message + " All previous sessions have been signed out.", "success")
    return redirect(url_for("auth.login"), code=303)


@bp.get("/account")
@login_required
def index():
    return settings_response()


@bp.post("/account/email")
@login_required
def change_email():
    return handle_change("email", ChangeEmailForm())


@bp.post("/account/password")
@login_required
def change_password():
    return handle_change("password", ChangePasswordForm())


@bp.post("/account/delete")
@login_required
def delete_account():
    return handle_change("delete", DeleteAccountForm())
