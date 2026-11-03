"""Run privately on PythonAnywhere to create production configuration."""

import getpass
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path

from dotenv import dotenv_values, set_key
from email_validator import EmailNotValidError, validate_email


def configure_host(project_root):
    root = Path(project_root).resolve()
    path = root / ".env"
    if path.is_symlink():
        raise RuntimeError("Use a regular private .env file, not a symbolic link.")
    original = path.read_text(encoding="utf-8") if path.exists() else ""
    existing = dotenv_values(path) if path.exists() else {}
    if path.exists() and existing.get("APP_ENV") != "production":
        raise RuntimeError("This folder has local configuration. Run this helper only in the separate server checkout.")

    username = input("PythonAnywhere username (from your dashboard): ").strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", username):
        raise ValueError("Enter only your PythonAnywhere username, not an email address or URL.")
    key = getpass.getpass("Brevo API key (hidden; blank keeps an existing server key): ").strip()
    key = key or existing.get("BREVO_API_KEY", "")
    if not key or any(character.isspace() for character in key):
        raise ValueError("A single-line Brevo API key is required.")
    sender = input("Verified Brevo sender email (blank keeps the existing sender): ").strip()
    sender = sender or existing.get("MAIL_SENDER_EMAIL", "")
    try:
        sender = validate_email(sender, check_deliverability=False, allow_smtputf8=False).ascii_email
    except EmailNotValidError:
        raise ValueError("Enter the sender email you verified in Brevo.") from None
    secret = existing.get("SECRET_KEY") or secrets.token_hex(32)
    if len(secret) < 32:
        raise ValueError("The existing server SECRET_KEY must have at least 32 random characters.")
    values = {
        "APP_ENV": "production",
        "SECRET_KEY": secret,
        "PUBLIC_BASE_URL": f"https://{username}.pythonanywhere.com",
        "PYTHONANYWHERE_PROXY": "1",
        "BREVO_API_KEY": key,
        "MAIL_SENDER_EMAIL": sender,
        "MAIL_SENDER_NAME": existing.get("MAIL_SENDER_NAME") or "MembersArea",
    }
    for name, value in values.items():
        if name in os.environ and os.environ[name] != value:
            raise RuntimeError(f"The environment variable {name} overrides this file. Clear it in the console and retry.")

    # Validate everything first, then replace the private file atomically.
    descriptor, temporary = tempfile.mkstemp(prefix=".env.host-", dir=root)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(original)
        for name, value in values.items():
            set_key(temporary, name, value)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    print(f"Production configuration saved privately for {values['PUBLIC_BASE_URL']}.")
    print("Next: initialize the database, create an admin, and configure the Web tab.")


if __name__ == "__main__":
    root = Path(__file__).resolve().parent
    try:
        if Path.home().parent != Path("/home") or not root.is_relative_to(Path.home()):
            raise RuntimeError("Run this script in your PythonAnywhere home folder, not on your Windows computer.")
        if not sys.stdin.isatty():
            raise RuntimeError("Open an interactive Bash console so the API key can be entered privately.")
        configure_host(root)
    except (ValueError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None
