"""Create a private local secret without printing it or replacing user data."""

import os
import secrets
from pathlib import Path

from dotenv import dotenv_values, set_key


def configure_local(project_root):
    path = Path(project_root) / ".env"
    existing = dotenv_values(path) if path.exists() else {}
    if os.environ.get("APP_ENV") == "production" or existing.get("APP_ENV") == "production":
        raise RuntimeError("This helper is for local development only.")

    if not path.exists():
        path.write_text(
            "APP_ENV=development\nPUBLIC_BASE_URL=http://127.0.0.1:5000\n",
            encoding="utf-8",
        )
        if os.name != "nt":
            path.chmod(0o600)

    secret = os.environ.get("SECRET_KEY") or existing.get("SECRET_KEY")
    if not secret:
        set_key(str(path), "SECRET_KEY", secrets.token_hex(32))
        print("Local configuration ready. A private random secret was created.")
    elif len(secret) < 32:
        raise RuntimeError("Your existing SECRET_KEY is too short. Set a random key of at least 32 characters.")
    else:
        print("Local configuration ready. Your existing secret was preserved.")


if __name__ == "__main__":
    configure_local(Path(__file__).resolve().parent)
