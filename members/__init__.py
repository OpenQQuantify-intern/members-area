"""Application setup for the members area."""

import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, render_template, request
from flask_wtf.csrf import CSRFError, CSRFProtect

csrf = CSRFProtect()


def create_app(test_config=None):
    """Create a separately configurable Flask application."""
    project_root = Path(__file__).resolve().parent.parent
    load_dotenv(project_root / ".env", override=False)

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        DATABASE=str(Path(app.instance_path) / "members.sqlite3"),
        SECRET_KEY=os.environ.get("SECRET_KEY") or None,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("APP_ENV") == "production",
        SESSION_COOKIE_NAME="members_session",
        SESSION_REFRESH_EACH_REQUEST=False,
        PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
        AUTH_SESSION_SECONDS=3600,
        AUTH_WINDOW_SECONDS=900,
        AUTH_LOGIN_IP_LIMIT=30,
        AUTH_LOGIN_ACCOUNT_LIMIT=10,
        AUTH_REGISTER_IP_LIMIT=10,
        AUTH_REGISTER_ACCOUNT_LIMIT=5,
        AUTH_ACCOUNT_IP_LIMIT=20,
        AUTH_ACCOUNT_ACCOUNT_LIMIT=10,
        AUTH_FORGOT_IP_LIMIT=10,
        AUTH_FORGOT_ACCOUNT_LIMIT=3,
        AUTH_RESET_IP_LIMIT=30,
        AUTH_RESET_ACCOUNT_LIMIT=10,
        AUTH_RESET_CHECK_IP_LIMIT=60,
        AUTH_RESET_CHECK_ACCOUNT_LIMIT=20,
        RESET_TOKEN_SECONDS=900,
        APP_ENV=os.environ.get("APP_ENV", "development"),
        PYTHONANYWHERE_PROXY=os.environ.get("PYTHONANYWHERE_PROXY") == "1",
        PUBLIC_BASE_URL=os.environ.get("PUBLIC_BASE_URL", "http://127.0.0.1:5000"),
        BREVO_API_KEY=os.environ.get("BREVO_API_KEY", ""),
        MAIL_SENDER_EMAIL=os.environ.get("MAIL_SENDER_EMAIL", ""),
        MAIL_SENDER_NAME=os.environ.get("MAIL_SENDER_NAME", "MembersArea"),
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    if test_config is not None:
        app.config.update(test_config)
    if app.config["APP_ENV"] == "production":
        app.config["SESSION_COOKIE_SECURE"] = True

    if not isinstance(app.secret_key, str) or len(app.secret_key) < 32:
        raise RuntimeError(
            "A persistent random SECRET_KEY is required. "
            "For local development, run: python setup_local.py"
        )

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    from . import accounts, admin, auth, db, mail, public, recovery

    db.init_app(app)
    mail.init_app(app)
    auth.init_app(app)
    admin.init_app(app)
    csrf.init_app(app)
    app.register_blueprint(public.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(accounts.bp)
    app.register_blueprint(recovery.bp)
    app.register_blueprint(admin.bp)

    @app.errorhandler(403)
    def forbidden(error):
        return render_template(
            "error.html", title="Access restricted",
            message="Only administrators can open this area or perform this action.",
        ), 403

    @app.errorhandler(CSRFError)
    def csrf_error(error):
        return render_template(
            "error.html", title="Please refresh the page",
            message="Your form has expired or could not be verified. Refresh the page and try again.",
        ), 400

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'self'; "
            "img-src 'self'; object-src 'none'; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'"
        )
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
        if app.config["SESSION_COOKIE_SECURE"] and request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    return app
