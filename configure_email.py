"""Save local email credentials with a hidden prompt; never send them in chat."""

import getpass
import os
from pathlib import Path

from dotenv import dotenv_values, set_key
from email_validator import EmailNotValidError, validate_email


def configure_email(project_root):
    path = Path(project_root) / ".env"
    existing = dotenv_values(path) if path.exists() else {}
    if os.environ.get("APP_ENV") == "production" or existing.get("APP_ENV") == "production":
        raise RuntimeError("This helper is for local development. Manage production credentials on the host.")
    if not (os.environ.get("SECRET_KEY") or existing.get("SECRET_KEY")):
        raise RuntimeError("First run: python setup_local.py")

    key = getpass.getpass("Brevo API key (hidden; leave blank to keep an existing key): ").strip()
    key = key or existing.get("BREVO_API_KEY", "")
    if not key or "\r" in key or "\n" in key:
        raise ValueError("Enter a valid, single-line Brevo API key.")
    sender = input("Your verified sender email address: ").strip()
    sender = sender or existing.get("MAIL_SENDER_EMAIL", "")
    try:
        sender = validate_email(sender, check_deliverability=False, allow_smtputf8=False).ascii_email
    except EmailNotValidError:
        raise ValueError("Enter the sender email address you verified in Brevo.") from None

    if not path.exists():
        path.write_text("APP_ENV=development\n", encoding="utf-8")
        if os.name != "nt":
            path.chmod(0o600)
    set_key(str(path), "BREVO_API_KEY", key)
    set_key(str(path), "MAIL_SENDER_EMAIL", sender)
    if not existing.get("MAIL_SENDER_NAME"):
        set_key(str(path), "MAIL_SENDER_NAME", "MembersArea")
    if not existing.get("PUBLIC_BASE_URL"):
        set_key(str(path), "PUBLIC_BASE_URL", "http://127.0.0.1:5000")
    print("Email settings saved privately. Restart Flask and test Forgot your password using an account whose inbox you control.")


if __name__ == "__main__":
    configure_email(Path(__file__).resolve().parent)
