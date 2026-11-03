"""Transactional email delivery through Brevo's allowlisted HTTPS API."""

from html import escape
from urllib.parse import urlsplit

import requests
from email_validator import EmailNotValidError, validate_email
from flask import current_app

BREVO_ENDPOINT = "https://api.brevo.com/v3/smtp/email"


class DeliveryError(Exception):
    """A sanitized error that never contains credentials, tokens, or recipients."""


def canonical_base_url(value, production=False):
    value = value.strip()
    if not value or any(character.isspace() for character in value):
        raise ValueError("PUBLIC_BASE_URL must be a complete origin URL without whitespace.")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("PUBLIC_BASE_URL is invalid.") from error
    if (not parsed.hostname or parsed.username or parsed.password or parsed.query
            or parsed.fragment or parsed.path not in ("", "/")):
        raise ValueError("PUBLIC_BASE_URL must contain only a scheme, hostname, and optional port.")
    loopback = parsed.hostname.lower() in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (not production and parsed.scheme == "http" and loopback):
        raise ValueError("Use HTTPS for PUBLIC_BASE_URL; HTTP is allowed only for local development.")
    if production and loopback:
        raise ValueError("Production PUBLIC_BASE_URL must be the live public HTTPS origin.")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("PUBLIC_BASE_URL has an invalid port.")
    return value.rstrip("/")


def mail_configured():
    return bool(current_app.config["BREVO_API_KEY"] and current_app.config["MAIL_SENDER_EMAIL"])


def send_email(recipient, subject, text, html_content=None):
    """Provider acceptance is not proof of inbox delivery; verify it manually."""
    if not mail_configured():
        raise DeliveryError("Email delivery is not configured.")
    payload = {
        "sender": {"name": current_app.config["MAIL_SENDER_NAME"],
                   "email": current_app.config["MAIL_SENDER_EMAIL"]},
        "to": [{"email": recipient}],
        "subject": subject,
        "textContent": text,
        "htmlContent": html_content or "<html><body><p>" + escape(text).replace("\n", "<br>") + "</p></body></html>",
    }
    try:
        response = requests.post(
            BREVO_ENDPOINT,
            headers={"api-key": current_app.config["BREVO_API_KEY"], "accept": "application/json"},
            json=payload, timeout=(3, 8), allow_redirects=False,
        )
    except requests.RequestException:
        raise DeliveryError("Email provider could not be reached.") from None
    try:
        if response.status_code != 201:
            # Never include response bodies: they can echo confidential data.
            raise DeliveryError(f"Email provider rejected the request (HTTP {response.status_code}).")
    finally:
        response.close()


def send_reset_email(recipient, reset_url):
    minutes = current_app.config["RESET_TOKEN_SECONDS"] // 60
    send_email(
        recipient,
        "Reset your MembersArea password",
        "We received a request to reset your MembersArea password.\n\n"
        f"Open this link to choose a new password:\n{reset_url}\n\n"
        f"The link expires in {minutes} minutes and can be used once. "
        "Only the most recently requested link works.\n\n"
        "If you did not request this, you can ignore this email. "
        "Your password has not changed.\n",
        html_content=(
            "<html><body><h1>Reset your password</h1>"
            "<p>We received a request to reset your MembersArea password.</p>"
            f'<p><a href="{escape(reset_url, quote=True)}">Choose a new password</a></p>'
            f"<p>This link expires in {minutes} minutes and can be used once. "
            "Only the most recently requested link works.</p>"
            "<p>If you did not request this, ignore this email. Your password has not changed.</p>"
            "</body></html>"
        ),
    )


def send_password_changed_email(recipient):
    send_email(
        recipient,
        "Your MembersArea password was changed",
        "Your MembersArea password has been reset. All previous sessions and "
        "outstanding reset links have been invalidated.\n\n"
        "If this was not you, request a new reset link from the MembersArea login page.\n",
    )


def init_app(app):
    production = app.config["APP_ENV"] == "production"
    app.config["PUBLIC_BASE_URL"] = canonical_base_url(app.config["PUBLIC_BASE_URL"], production)
    for key in ("BREVO_API_KEY", "MAIL_SENDER_EMAIL", "MAIL_SENDER_NAME"):
        value = app.config[key].strip()
        if "\r" in value or "\n" in value:
            raise ValueError(f"{key} must be a single line.")
        app.config[key] = value
    if app.config["MAIL_SENDER_EMAIL"]:
        try:
            app.config["MAIL_SENDER_EMAIL"] = validate_email(
                app.config["MAIL_SENDER_EMAIL"], check_deliverability=False, allow_smtputf8=False,
            ).ascii_email
        except EmailNotValidError:
            raise ValueError("MAIL_SENDER_EMAIL must be a valid sender address.") from None
    if production and not (app.config["BREVO_API_KEY"] and app.config["MAIL_SENDER_EMAIL"]):
        raise ValueError("Configure BREVO_API_KEY and a verified MAIL_SENDER_EMAIL before production deployment.")
