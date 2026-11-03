"""Admin member management and a server-only administrator setup command."""

import sqlite3
import time
from functools import wraps
from math import ceil

import click
from email_validator import EmailNotValidError, validate_email
from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from flask.cli import with_appcontext
from werkzeug.security import check_password_hash, generate_password_hash

from .auth import login_required
from .db import get_db

bp = Blueprint("admin", __name__)
PAGE_SIZE = 25


def admin_required(view):
    @wraps(view)
    def protected(*args, **kwargs):
        if g.user["is_admin"] != 1:
            abort(403)
        return view(*args, **kwargs)
    return login_required(protected)


def require_current_admin(db):
    """Recheck authorization inside the transaction that reads/changes data."""
    actor = db.execute(
        """SELECT u.id FROM users AS u JOIN member_sessions AS s ON s.user_id = u.id
           WHERE u.id = ? AND u.is_admin = 1 AND u.is_blocked = 0
             AND s.token_hash = ? AND s.session_version = u.session_version
             AND s.expires_at > ?""",
        (g.user["id"], g.auth_session_hash, int(time.time())),
    ).fetchone()
    if actor is None:
        abort(403)
    return actor


def filters(source):
    query = source.get("q", "").strip()[:254]
    status = source.get("status", "all")
    if status not in {"all", "active", "blocked"}:
        status = "all"
    page = source.get("page", 1, type=int) or 1
    return query, status, max(1, min(page, 1000000))


@bp.get("/admin/users")
@admin_required
def users():
    query, status, requested_page = filters(request.args)
    clauses = []
    parameters = []
    if query:
        escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        clauses.append("email LIKE ? ESCAPE '\\'")
        parameters.append("%" + escaped + "%")
    if status != "all":
        clauses.append("is_blocked = ?")
        parameters.append(1 if status == "blocked" else 0)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    db = get_db()
    with db:
        # One read snapshot covers permission validation and the result set.
        db.execute("BEGIN")
        require_current_admin(db)
        counts = db.execute(
            """SELECT COUNT(*) AS total,
                      COALESCE(SUM(is_blocked = 0), 0) AS active,
                      COALESCE(SUM(is_blocked = 1), 0) AS blocked FROM users""",
        ).fetchone()
        filtered_total = db.execute("SELECT COUNT(*) FROM users" + where, parameters).fetchone()[0]
        pages = max(1, ceil(filtered_total / PAGE_SIZE))
        page = min(requested_page, pages)
        members = db.execute(
            "SELECT id, email, is_admin, is_blocked, created_at FROM users" + where
            + " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
            (*parameters, PAGE_SIZE, (page - 1) * PAGE_SIZE),
        ).fetchall()
    return render_template(
        "admin/users.html", members=members, counts=counts, filtered_total=filtered_total,
        page=page, pages=pages, query=query, status=status,
    )


def set_member_blocked(user_id, blocked):
    if not 1 <= user_id <= 9223372036854775807:
        abort(404)
    db = get_db()
    with db:
        db.execute("BEGIN IMMEDIATE")
        actor = require_current_admin(db)
        target = db.execute("SELECT id, is_blocked FROM users WHERE id = ?", (user_id,)).fetchone()
        if target is None:
            abort(404)
        if target["id"] == actor["id"]:
            return "self"
        if bool(target["is_blocked"]) == blocked:
            return "unchanged"
        db.execute(
            "UPDATE users SET is_blocked = ?, session_version = session_version + 1 WHERE id = ?",
            (int(blocked), user_id),
        )
        # Both transitions revoke old credentials so unblocking cannot revive
        # a copied cookie or a link that was issued before the block.
        db.execute("DELETE FROM member_sessions WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (user_id,))
    return "changed"


def change_status(user_id, blocked):
    result = set_member_blocked(user_id, blocked)
    if result == "self":
        return render_template(
            "error.html", title="Your own access is protected",
            message="Ask another administrator to change your account's access status.",
        ), 409
    if result == "unchanged":
        flash("This account already has that access status.", "info")
    elif blocked:
        flash("Member blocked. Their sessions and reset links were revoked.", "success")
    else:
        flash("Member unblocked. They can log in again; previous sessions and reset links remain invalid.", "success")
    query, status, page = filters(request.form)
    return redirect(url_for("admin.users", q=query, status=status, page=page), code=303)


@bp.post("/admin/users/<int:user_id>/block")
@admin_required
def block(user_id):
    return change_status(user_id, True)


@bp.post("/admin/users/<int:user_id>/unblock")
@admin_required
def unblock(user_id):
    return change_status(user_id, False)


@click.command("create-admin")
@click.option("--email", prompt="Admin email", help="Your new or existing administrator email.")
@with_appcontext
def create_admin(email):
    """Create an admin or promote an existing account with its current password."""
    try:
        email = validate_email(email.strip().lower(), check_deliverability=False, allow_smtputf8=False).ascii_email.lower()
    except EmailNotValidError:
        raise click.ClickException("Enter a valid administrator email address.") from None
    db = get_db()
    existing = db.execute(
        "SELECT id, email, password_hash, session_version, is_admin, is_blocked FROM users WHERE email = ?",
        (email,),
    ).fetchone()
    if existing is not None:
        if existing["is_blocked"]:
            raise click.ClickException("This account is blocked. Have another admin unblock it, or create a different admin account.")
        if existing["is_admin"]:
            click.echo("This account is already an active administrator. No changes were made.")
            return
        password = click.prompt("Current account password", hide_input=True)
        if not check_password_hash(existing["password_hash"], password):
            raise click.ClickException("The current password is incorrect. No changes were made.")
        with db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute(
                """UPDATE users SET is_admin = 1, session_version = session_version + 1
                   WHERE id = ? AND email = ? AND password_hash = ? AND session_version = ?
                     AND is_admin = 0 AND is_blocked = 0""",
                (existing["id"], email, existing["password_hash"], existing["session_version"]),
            )
            if changed.rowcount != 1:
                raise click.ClickException("The account changed during setup. Run the command again.")
            db.execute("DELETE FROM member_sessions WHERE user_id = ?", (existing["id"],))
            db.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (existing["id"],))
        click.echo("Existing account promoted to administrator. Log in again using its current password.")
        return

    password = click.prompt("New admin password", hide_input=True, confirmation_prompt=True)
    if not 15 <= len(password) <= 128:
        raise click.ClickException("Use a password between 15 and 128 characters. No account was created.")
    password_hash = generate_password_hash(password)
    try:
        with db:
            db.execute(
                "INSERT INTO users (email, password_hash, is_admin) VALUES (?, ?, 1)",
                (email, password_hash),
            )
    except sqlite3.IntegrityError:
        raise click.ClickException("That account was created during setup. Run the command again to verify its current password.") from None
    click.echo("Administrator account created. Log in using the email and password you entered.")


def init_app(app):
    app.cli.add_command(create_admin)
