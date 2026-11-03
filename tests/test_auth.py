"""Run: python -m unittest discover -s tests -v. CSRF stays enabled."""

import os
import re
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from dotenv import dotenv_values
from werkzeug.security import check_password_hash

from members import create_app
from members.db import get_db
from members.security import consume_auth_attempt
from setup_local import configure_local

PASSWORD = "a long unique test passphrase"


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = {
            "TESTING": True,
            "SECRET_KEY": "test-only-key-" + "x" * 50,
            "DATABASE": str(Path(self.temp.name) / "test.sqlite3"),
            "AUTH_LOGIN_IP_LIMIT": 1000,
            "AUTH_LOGIN_ACCOUNT_LIMIT": 1000,
            "AUTH_REGISTER_IP_LIMIT": 1000,
            "AUTH_REGISTER_ACCOUNT_LIMIT": 1000,
        }
        self.app = create_app(self.config)
        self.client = self.app.test_client()
        self.assertEqual(self.app.test_cli_runner().invoke(args=["init-db"]).exit_code, 0)

    def csrf(self, client, path):
        response = client.get(path)
        self.assertEqual(response.status_code, 200)
        match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', response.get_data(as_text=True))
        self.assertIsNotNone(match, response.get_data(as_text=True))
        return match.group(1)

    def register(self, email="alice@example.com", password=PASSWORD, **extra):
        data = {"email": email, "password": password, "confirm_password": password,
                "csrf_token": self.csrf(self.client, "/register")}
        data.update(extra)
        return self.client.post("/register", data=data)

    def login(self, email="alice@example.com", password=PASSWORD, client=None, path="/login", **extra):
        client = client or self.client
        data = {"email": email, "password": password, "csrf_token": self.csrf(client, "/login")}
        data.update(extra)
        return client.post(path, data=data)

    def db_execute(self, statement, parameters=()):
        with self.app.app_context():
            db = get_db()
            result = db.execute(statement, parameters)
            rows = result.fetchall()
            db.commit()
            return rows

    def test_public_pages_assets_and_anonymous_protection(self):
        for url in ["/", "/login", "/register", "/static/css/styles.css", "/static/js/main.js"]:
            with self.client.get(url) as response:
                self.assertEqual(response.status_code, 200, url)
        response = self.client.get("/members")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/login"))
        self.assertEqual(self.client.get("/logout").status_code, 405)

    def test_register_login_member_logout_and_revoked_cookie(self):
        self.assertEqual(self.register(" Alice@EXAMPLE.com ").status_code, 303)
        user = self.db_execute("SELECT * FROM users")[0]
        self.assertEqual(user["email"], "alice@example.com")
        self.assertNotEqual(user["password_hash"], PASSWORD)
        self.assertTrue(user["password_hash"].startswith("scrypt:"))
        self.assertTrue(check_password_hash(user["password_hash"], PASSWORD))
        self.assertEqual(self.login().status_code, 303)
        response = self.client.get("/members")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"alice@example.com", response.data)
        self.assertNotIn(user["password_hash"].encode(), response.data)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        cookie_name = self.app.config["SESSION_COOKIE_NAME"]
        stolen_cookie = self.client.get_cookie(cookie_name).value
        with self.client.session_transaction() as data:
            token = data["auth_token"]
            self.assertNotIn("password", data)
            self.assertNotIn("password_hash", data)
        stored = self.db_execute("SELECT token_hash FROM member_sessions")[0][0]
        self.assertNotEqual(stored, token)
        self.assertEqual(len(stored), 64)
        response = self.client.post("/logout", data={"csrf_token": self.csrf(self.client, "/members")})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(len(self.db_execute("SELECT * FROM member_sessions")), 0)
        replay = self.app.test_client()
        replay.set_cookie(cookie_name, stolen_cookie)
        self.assertEqual(replay.get("/members").status_code, 302)

    def test_duplicate_email_and_client_roles(self):
        self.assertEqual(self.register(is_admin="1", is_blocked="1", id="99").status_code, 303)
        user = self.db_execute("SELECT * FROM users")[0]
        self.assertEqual((user["is_admin"], user["is_blocked"]), (0, 0))
        response = self.register("ALICE@example.com")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Unable to create an account", response.data)
        self.assertEqual(len(self.db_execute("SELECT * FROM users")), 1)

    def test_server_side_validation_and_no_password_echo(self):
        for email, password in [("bad-address", PASSWORD), ("alice@example.com", "short"),
                                ("alice@example.com", "x" * 129),
                                ("x' OR 1=1--", PASSWORD)]:
            self.assertEqual(self.register(email, password).status_code, 200)
        response = self.register(confirm_password="different passphrase")
        self.assertIn(b"The passwords must match", response.data)
        self.assertNotIn(PASSWORD.encode(), response.data)
        self.assertEqual(len(self.db_execute("SELECT * FROM users")), 0)

    def test_csrf_missing_cross_browser_and_logout_protection(self):
        self.assertEqual(self.client.post("/register", data={"email": "alice@example.com"}).status_code, 400)
        self.assertEqual(self.client.post("/login", data={}).status_code, 400)
        token = self.csrf(self.client, "/register")
        other = self.app.test_client()
        response = other.post("/register", data={"email": "bob@example.com", "password": PASSWORD,
                                               "confirm_password": PASSWORD, "csrf_token": token})
        self.assertEqual(response.status_code, 400)
        self.register()
        self.login()
        self.assertEqual(self.client.post("/logout", data={}).status_code, 400)
        self.assertEqual(self.client.get("/members").status_code, 200)

    def test_unknown_wrong_and_blocked_login_share_generic_error(self):
        self.register()
        for email, password in [("missing@example.com", PASSWORD), ("alice@example.com", "wrong password")]:
            response = self.login(email, password)
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"Unable to log in with those details.", response.data)
        self.db_execute("UPDATE users SET is_blocked = 1, session_version = session_version + 1")
        response = self.login()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Unable to log in with those details.", response.data)
        self.assertEqual(self.client.get("/members").status_code, 302)

    def test_blocking_existing_session_and_session_version_revocation(self):
        self.register()
        self.login()
        self.db_execute("UPDATE users SET is_blocked = 1")
        self.assertEqual(self.client.get("/members").status_code, 302)
        self.db_execute("UPDATE users SET is_blocked = 0, session_version = session_version + 1")
        self.login()
        self.db_execute("UPDATE users SET session_version = session_version + 1")
        self.assertEqual(self.client.get("/members").status_code, 302)

    def test_expired_and_deleted_user_sessions_are_rejected(self):
        self.register()
        self.login()
        self.db_execute("UPDATE member_sessions SET expires_at = ?", (int(time.time()) - 1,))
        self.assertEqual(self.client.get("/members").status_code, 302)
        self.login()
        self.db_execute("DELETE FROM users")
        self.assertEqual(len(self.db_execute("SELECT * FROM member_sessions")), 0)
        self.assertEqual(self.client.get("/members").status_code, 302)

    def test_members_cannot_select_another_identity_or_open_redirect(self):
        self.register()
        self.register("bob@example.com")
        other_id = self.db_execute("SELECT id FROM users WHERE email = ?", ("bob@example.com",))[0][0]
        response = self.login(path="/login?next=https://example.org", user_id=other_id, is_admin="1")
        self.assertEqual(response.status_code, 303)
        self.assertTrue(response.location.endswith("/members"))
        response = self.client.get(f"/members?user_id={other_id}")
        self.assertIn(b"alice@example.com", response.data)
        self.assertNotIn(b"bob@example.com", response.data)
        self.assertEqual(self.client.get("/register").status_code, 302)
        self.assertEqual(self.client.get("/login").status_code, 302)
        other = self.app.test_client()
        self.assertEqual(self.login("bob@example.com", client=other).status_code, 303)
        self.assertNotIn(b"alice@example.com", other.get("/members").data)
        self.assertEqual(len(self.db_execute("SELECT * FROM users")), 2)

    def test_throttling_is_durable_and_does_not_trust_forwarded_ip(self):
        self.app.config.update(AUTH_LOGIN_IP_LIMIT=2, AUTH_LOGIN_ACCOUNT_LIMIT=1000)
        for _ in range(2):
            self.assertEqual(self.login("missing@example.com").status_code, 200)
        # A new app/process shares the database, not an in-memory counter.
        second_app = create_app({**self.config, "AUTH_LOGIN_IP_LIMIT": 2})
        other = second_app.test_client()
        token = self.csrf(other, "/login")
        response = other.post("/login", data={"email": "another@example.com", "password": PASSWORD,
                                               "csrf_token": token},
                              headers={"X-Forwarded-For": "203.0.113.99"})
        self.assertEqual(response.status_code, 429)
        self.assertGreater(int(response.headers["Retry-After"]), 0)
        for row in self.db_execute("SELECT bucket_key FROM auth_rate_limits"):
            self.assertNotIn("example.com", row[0])
            self.assertEqual(len(row[0]), 64)

    def test_database_init_preserves_accounts(self):
        self.register()
        result = self.app.test_cli_runner().invoke(args=["init-db"])
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(len(self.db_execute("SELECT * FROM users")), 1)

    def test_upgrade_adds_new_tables_to_existing_database(self):
        self.register()
        # Reproduce the first milestone's state: users exist, new tables do not.
        self.db_execute("DROP TABLE member_sessions")
        self.db_execute("DROP TABLE auth_rate_limits")
        result = self.app.test_cli_runner().invoke(args=["init-db"])
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(len(self.db_execute("SELECT * FROM users")), 1)
        self.assertEqual(self.login().status_code, 303)
        self.assertEqual(self.client.get("/members").status_code, 200)

    def test_concurrent_attempts_are_counted_atomically(self):
        self.app.config.update(AUTH_LOGIN_IP_LIMIT=4, AUTH_LOGIN_ACCOUNT_LIMIT=4)
        def attempt(index):
            with self.app.test_request_context("/login", environ_base={"REMOTE_ADDR": "198.51.100.1"}):
                return consume_auth_attempt("login", "alice@example.com")
        with ThreadPoolExecutor(max_workers=4) as executor:
            outcomes = list(executor.map(attempt, range(8)))
        self.assertEqual(sum(value == 0 for value in outcomes), 4)
        self.assertEqual(sorted(row[0] for row in self.db_execute("SELECT attempts FROM auth_rate_limits")), [8, 8])

    def test_secure_cookie_and_security_headers(self):
        secure_app = create_app({**self.config, "SESSION_COOKIE_SECURE": True})
        response = secure_app.test_client().get("/login", base_url="https://localhost")
        cookie = response.headers["Set-Cookie"]
        self.assertIn("Secure", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("form-action 'self'", response.headers["Content-Security-Policy"])
        self.assertIn("Strict-Transport-Security", response.headers)

    def test_missing_secret_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "SECRET_KEY"):
            create_app({**self.config, "SECRET_KEY": None})

    def test_local_setup_preserves_secret_existing_settings_and_database(self):
        root = Path(self.temp.name)
        env_path = root / ".env"
        env_path.write_text("APP_ENV=development\nCUSTOM_SETTING=keep-me\nSECRET_KEY=\n")
        db_path = root / "test.sqlite3"
        before = db_path.read_bytes()
        with patch.dict(os.environ, {"APP_ENV": "development", "SECRET_KEY": ""}):
            configure_local(root)
            first = dotenv_values(env_path)["SECRET_KEY"]
            configure_local(root)
        self.assertEqual(len(first), 64)
        self.assertEqual(dotenv_values(env_path)["SECRET_KEY"], first)
        self.assertEqual(dotenv_values(env_path)["CUSTOM_SETTING"], "keep-me")
        self.assertEqual(db_path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
