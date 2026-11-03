"""Recovery integration tests intercept HTTP; no real emails are sent."""

import hashlib
import re
import secrets
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import requests
from werkzeug.security import check_password_hash

import test_auth as auth_fixture
from members import create_app, mail, recovery

PASSWORD = auth_fixture.PASSWORD
NEW_PASSWORD = "a fresh different reset passphrase"


class RecoveryTests(unittest.TestCase):
    csrf = auth_fixture.AuthenticationTests.csrf
    register = auth_fixture.AuthenticationTests.register
    login = auth_fixture.AuthenticationTests.login
    db_execute = auth_fixture.AuthenticationTests.db_execute

    def setUp(self):
        auth_fixture.AuthenticationTests.setUp(self)
        self.app.config.update(
            PUBLIC_BASE_URL="https://members.example.com", BREVO_API_KEY="fake-key-for-tests-only",
            MAIL_SENDER_EMAIL="sender@example.com", MAIL_SENDER_NAME="MembersArea",
            AUTH_FORGOT_IP_LIMIT=1000, AUTH_FORGOT_ACCOUNT_LIMIT=1000,
            AUTH_RESET_IP_LIMIT=1000, AUTH_RESET_ACCOUNT_LIMIT=1000,
            AUTH_RESET_CHECK_IP_LIMIT=1000, AUTH_RESET_CHECK_ACCOUNT_LIMIT=1000,
        )
        self.http_patch = patch("members.mail.requests.post")
        self.http = self.http_patch.start()
        self.addCleanup(self.http_patch.stop)
        self.http.return_value = MagicMock(status_code=201)

    def request_reset(self, email="alice@example.com", client=None):
        client = client or self.client
        token = self.csrf(client, "/forgot-password")
        return client.post("/forgot-password", data={"email": email, "csrf_token": token})

    def latest_token(self):
        for call in reversed(self.http.call_args_list):
            payload = call.kwargs["json"]
            if payload["subject"] == "Reset your MembersArea password":
                match = re.search(r'https://members\.example\.com/reset-password#token=([A-Za-z0-9_-]{43})', payload["textContent"])
                self.assertIsNotNone(match)
                return match.group(1)
        self.fail("No reset email was submitted to the intercepted provider.")

    def check(self, token, client=None):
        client = client or self.client
        csrf_token = self.csrf(client, "/reset-password")
        return client.post("/reset-password/check", data={"token": token}, headers={"X-CSRFToken": csrf_token})

    def finish(self, token, password=NEW_PASSWORD, confirm=None, client=None, **extra):
        client = client or self.client
        data = {"csrf_token": self.csrf(client, "/reset-password"), "token": token,
                "new_password": password, "confirm_password": password if confirm is None else confirm}
        data.update(extra)
        return client.post("/reset-password", data=data)

    def test_request_sends_real_api_shape_and_stores_only_digest(self):
        self.register()
        self.assertEqual(self.request_reset(" ALICE@EXAMPLE.COM ").status_code, 303)
        token = self.latest_token()
        record = self.db_execute("SELECT * FROM password_reset_tokens")[0]
        self.assertEqual(record["token_hash"], hashlib.sha256(token.encode()).hexdigest())
        self.assertNotEqual(record["token_hash"], token)
        self.assertIsNone(record["used_at"])
        self.assertTrue(898 <= record["expires_at"] - int(time.time()) <= 900)
        call = self.http.call_args
        self.assertEqual(call.args[0], "https://api.brevo.com/v3/smtp/email")
        self.assertEqual(call.kwargs["headers"]["api-key"], "fake-key-for-tests-only")
        self.assertEqual(call.kwargs["json"]["to"], [{"email": "alice@example.com"}])
        self.assertIn("htmlContent", call.kwargs["json"])
        self.assertEqual(call.kwargs["timeout"], (3, 8))
        self.assertFalse(call.kwargs["allow_redirects"])

    def test_known_unknown_and_blocked_addresses_share_public_response(self):
        self.register()
        known = self.request_reset()
        before = self.http.call_count
        unknown = self.request_reset("missing@example.com")
        self.db_execute("UPDATE users SET is_blocked = 1")
        blocked = self.request_reset()
        self.assertEqual((known.status_code, known.location), (unknown.status_code, unknown.location))
        self.assertEqual((known.status_code, known.location), (blocked.status_code, blocked.location))
        self.assertEqual(self.http.call_count, before)
        response = self.client.get(known.location)
        self.assertNotIn(b"alice@example.com", response.data)
        self.assertNotIn(b"missing@example.com", response.data)
        self.assertIn(b"If an active account matches", response.data)

    def test_missing_mail_configuration_has_same_failure_for_all_addresses(self):
        self.register()
        self.app.config["BREVO_API_KEY"] = ""
        for email in ["alice@example.com", "missing@example.com"]:
            response = self.request_reset(email)
            self.assertEqual(response.status_code, 503)
            self.assertIn(b"temporarily unavailable", response.data)
        self.assertEqual(self.http.call_count, 0)
        self.assertEqual(len(self.db_execute("SELECT * FROM password_reset_tokens")), 0)

    def test_get_and_check_do_not_consume_or_publish_token(self):
        self.register()
        self.request_reset()
        token = self.latest_token()
        response = self.client.get("/reset-password")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(token.encode(), response.data)
        self.assertIn(b"recovery.js", response.data)
        self.assertEqual(self.check(token).json, {"valid": True})
        self.assertIsNone(self.db_execute("SELECT used_at FROM password_reset_tokens")[0][0])
        self.assertNotIn(token.encode(), self.client.get("/forgot-password/sent").data)
        with self.client.session_transaction() as data:
            self.assertNotIn(token, str(dict(data)))

    def test_complete_reset_revokes_sessions_and_other_links_without_auto_login(self):
        self.register()
        self.register("bob@example.com")
        self.login()
        other = self.app.test_client()
        bob = self.app.test_client()
        self.login(client=other)
        self.login("bob@example.com", client=bob)
        self.request_reset()
        token = self.latest_token()
        alice_id = self.db_execute("SELECT id FROM users WHERE email = ?", ("alice@example.com",))[0][0]
        bob_before = dict(self.db_execute("SELECT * FROM users WHERE email = ?", ("bob@example.com",))[0])
        extra_token = secrets.token_urlsafe(32)
        self.db_execute("INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
                        (alice_id, hashlib.sha256(extra_token.encode()).hexdigest(), int(time.time()) + 900))
        reset_browser = self.app.test_client()
        response = self.finish(token, client=reset_browser, user_id=bob_before["id"], is_blocked="0", is_admin="1")
        self.assertEqual(response.status_code, 303)
        self.assertTrue(response.location.endswith("/login"))
        self.assertEqual(reset_browser.get("/members").status_code, 302)
        self.assertEqual(other.get("/members").status_code, 302)
        self.assertEqual(self.client.get("/members").status_code, 302)
        self.assertEqual(bob.get("/members").status_code, 200)
        self.assertEqual(dict(self.db_execute("SELECT * FROM users WHERE email = ?", ("bob@example.com",))[0]), bob_before)
        alice = self.db_execute("SELECT * FROM users WHERE id = ?", (alice_id,))[0]
        self.assertTrue(check_password_hash(alice["password_hash"], NEW_PASSWORD))
        self.assertEqual((alice["is_blocked"], alice["is_admin"], alice["session_version"]), (0, 0, 2))
        self.assertEqual(self.check(extra_token).status_code, 400)
        self.assertIsNotNone(self.db_execute("SELECT used_at FROM password_reset_tokens")[0][0])
        self.assertEqual(self.finish(token).status_code, 400)
        self.assertEqual(self.login(password=PASSWORD).status_code, 200)
        self.assertEqual(self.login(password=NEW_PASSWORD).status_code, 303)
        notice = self.http.call_args.kwargs["json"]
        self.assertEqual(notice["subject"], "Your MembersArea password was changed")
        self.assertNotIn(NEW_PASSWORD, notice["textContent"])

    def test_new_request_invalidates_old_link_and_expired_used_links_fail(self):
        self.register()
        self.request_reset()
        first = self.latest_token()
        self.request_reset()
        second = self.latest_token()
        self.assertNotEqual(first, second)
        self.assertEqual(self.check(first).status_code, 400)
        self.assertEqual(self.finish(first).status_code, 400)
        self.db_execute("UPDATE password_reset_tokens SET expires_at = ?", (int(time.time()) - 1,))
        self.assertEqual(self.check(second).status_code, 400)
        self.assertEqual(self.finish(second).status_code, 400)
        self.request_reset()
        third = self.latest_token()
        self.db_execute("UPDATE password_reset_tokens SET used_at = ?", (int(time.time()),))
        self.assertEqual(self.check(third).status_code, 400)
        self.assertEqual(self.finish(third).status_code, 400)

    def test_invalid_and_malformed_tokens_do_not_change_account(self):
        self.register()
        before = self.db_execute("SELECT password_hash FROM users")[0][0]
        for token in ["", "short", "é" * 43, "A" * 43, "../wrong-token"]:
            self.assertEqual(self.check(token).status_code, 400)
            response = self.finish(token)
            self.assertEqual(response.status_code, 400)
            self.assertIn(b"invalid or has expired", response.data)
        self.assertEqual(self.db_execute("SELECT password_hash FROM users")[0][0], before)

    def test_validation_errors_preserve_token_and_do_not_echo_passwords(self):
        self.register()
        self.request_reset()
        token = self.latest_token()
        for password, confirm in [("short", "short"), ("x" * 129, "x" * 129),
                                  (NEW_PASSWORD, "different confirmation"), (PASSWORD, PASSWORD)]:
            response = self.finish(token, password, confirm)
            self.assertEqual(response.status_code, 400)
            self.assertIsNone(self.db_execute("SELECT used_at FROM password_reset_tokens")[0][0])
            self.assertNotIn(password.encode(), response.data)
        self.assertEqual(self.finish(token).status_code, 303)

    def test_csrf_is_required_for_all_recovery_post_endpoints(self):
        self.register()
        self.request_reset()
        token = self.latest_token()
        for path, data in [("/forgot-password", {"email": "alice@example.com"}),
                           ("/reset-password/check", {"token": token}),
                           ("/reset-password", {"token": token, "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD})]:
            self.assertEqual(self.client.post(path, data=data).status_code, 400)
        other = self.app.test_client()
        csrf_token = self.csrf(self.client, "/reset-password")
        self.csrf(other, "/reset-password")
        self.assertEqual(other.post("/reset-password/check", data={"token": token, "csrf_token": csrf_token}).status_code, 400)
        self.assertIsNone(self.db_execute("SELECT used_at FROM password_reset_tokens")[0][0])

    def test_host_header_cannot_poison_reset_link(self):
        self.register()
        response = self.client.get("/forgot-password", base_url="http://attacker.example")
        csrf_token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', response.get_data(as_text=True)).group(1)
        response = self.client.post("/forgot-password", base_url="http://attacker.example",
                                    data={"email": "alice@example.com", "csrf_token": csrf_token})
        self.assertEqual(response.status_code, 303)
        token = self.latest_token()
        text = self.http.call_args.kwargs["json"]["textContent"]
        self.assertNotIn("attacker.example", text)
        link = re.search(r'https://[^\s]+', text).group(0)
        parsed = urlsplit(link)
        self.assertEqual((parsed.netloc, parsed.path, parsed.query), ("members.example.com", "/reset-password", ""))
        self.assertEqual(parse_qs(parsed.fragment)["token"], [token])

    def test_blocked_account_cannot_use_existing_reset_link(self):
        self.register()
        self.request_reset()
        token = self.latest_token()
        before = self.db_execute("SELECT password_hash FROM users")[0][0]
        self.db_execute("UPDATE users SET is_blocked = 1")
        self.assertEqual(self.check(token).status_code, 400)
        self.assertEqual(self.finish(token).status_code, 400)
        current = self.db_execute("SELECT * FROM users")[0]
        self.assertEqual((current["password_hash"], current["is_blocked"]), (before, 1))

    def test_account_email_change_and_deletion_invalidate_recovery_links(self):
        self.register()
        self.request_reset()
        first = self.latest_token()
        self.login()
        response = self.client.post("/account/email", data={
            "csrf_token": self.csrf(self.client, "/account"), "new_email": "alice.updated@example.com", "current_password": PASSWORD,
        })
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.check(first).status_code, 400)
        self.request_reset("alice.updated@example.com")
        second = self.latest_token()
        self.login("alice.updated@example.com")
        response = self.client.post("/account/delete", data={
            "csrf_token": self.csrf(self.client, "/account"), "current_password": PASSWORD, "confirm_delete": "y",
        })
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.check(second).status_code, 400)

    def test_rate_limits_cover_requests_checks_and_redemption(self):
        self.register()
        self.app.config.update(AUTH_FORGOT_ACCOUNT_LIMIT=1, AUTH_RESET_CHECK_ACCOUNT_LIMIT=1, AUTH_RESET_ACCOUNT_LIMIT=1)
        self.assertEqual(self.request_reset().status_code, 303)
        token = self.latest_token()
        response = self.request_reset()
        self.assertEqual(response.status_code, 429)
        self.assertGreater(int(response.headers["Retry-After"]), 0)
        self.assertEqual(self.check(token).status_code, 200)
        self.assertEqual(self.check(token).status_code, 429)
        self.assertEqual(self.finish(token, "short").status_code, 400)
        self.assertEqual(self.finish(token).status_code, 429)
        self.assertIsNone(self.db_execute("SELECT used_at FROM password_reset_tokens")[0][0])

    def test_failed_delivery_cleans_token_and_keeps_public_response_generic(self):
        self.register()
        self.http.return_value.status_code = 401
        self.http.return_value.text = "private-provider-data-should-not-be-logged"
        with self.assertLogs(self.app.logger, level="WARNING") as logs:
            response = self.request_reset()
        self.assertEqual(response.status_code, 303)
        self.assertEqual(len(self.db_execute("SELECT * FROM password_reset_tokens")), 0)
        log_text = " ".join(logs.output)
        self.assertIn("HTTP 401", log_text)
        self.assertNotIn("fake-key-for-tests-only", log_text)
        self.assertNotIn("private-provider-data", log_text)
        self.assertNotIn("alice@example.com", log_text)
        unknown = self.request_reset("missing@example.com")
        self.assertEqual((response.status_code, response.location), (unknown.status_code, unknown.location))

    def test_network_exception_is_sanitized(self):
        self.register()
        self.http.side_effect = requests.Timeout("PRIVATE_REQUEST_DATA")
        with self.assertLogs(self.app.logger, level="WARNING") as logs:
            response = self.request_reset()
        self.assertEqual(response.status_code, 303)
        self.assertNotIn("PRIVATE_REQUEST_DATA", " ".join(logs.output))
        self.assertEqual(len(self.db_execute("SELECT * FROM password_reset_tokens")), 0)

    def test_notification_failure_does_not_undo_completed_reset(self):
        self.register()
        self.request_reset()
        token = self.latest_token()
        self.http.return_value.status_code = 503
        with self.assertLogs(self.app.logger, level="WARNING"):
            response = self.finish(token)
        self.assertEqual(response.status_code, 303)
        self.assertTrue(check_password_hash(self.db_execute("SELECT password_hash FROM users")[0][0], NEW_PASSWORD))
        self.assertIsNotNone(self.db_execute("SELECT used_at FROM password_reset_tokens")[0][0])

    def test_only_one_simultaneous_redemption_succeeds(self):
        self.register()
        self.request_reset()
        token = self.latest_token()
        clients = [self.app.test_client(), self.app.test_client()]
        passwords = [NEW_PASSWORD, "another independent reset passphrase"]
        def reset(index):
            return self.finish(token, passwords[index], client=clients[index]).status_code
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(reset, range(2)))
        self.assertEqual(sorted(results), [303, 400])
        current = self.db_execute("SELECT password_hash FROM users")[0][0]
        self.assertEqual(sum(check_password_hash(current, password) for password in passwords), 1)

    def test_concurrent_block_prevents_reset_at_commit(self):
        self.register()
        self.request_reset()
        token = self.latest_token()
        before = self.db_execute("SELECT password_hash FROM users")[0][0]
        original = recovery.redeem_reset
        def block_before_commit(*args):
            self.db_execute("UPDATE users SET is_blocked = 1, session_version = session_version + 1")
            return original(*args)
        with patch("members.recovery.redeem_reset", side_effect=block_before_commit):
            response = self.finish(token)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.db_execute("SELECT password_hash FROM users")[0][0], before)

    def test_production_mail_and_public_origin_configuration_fail_closed(self):
        config = {**self.config, "APP_ENV": "production", "PUBLIC_BASE_URL": "https://member.pythonanywhere.com",
                  "BREVO_API_KEY": "", "MAIL_SENDER_EMAIL": ""}
        with self.assertRaisesRegex(ValueError, "BREVO_API_KEY"):
            create_app(config)
        for origin in ["http://example.com", "https://user:password@example.com", "https://example.com/path",
                       "https://example.com?next=evil", "https://example.com#secret", "https://localhost", "javascript:alert(1)"]:
            with self.assertRaises(ValueError):
                mail.canonical_base_url(origin, production=True)
        configured = create_app({**config, "BREVO_API_KEY": "fake-key", "MAIL_SENDER_EMAIL": "sender@example.com"})
        self.assertTrue(configured.config["SESSION_COOKIE_SECURE"])


if __name__ == "__main__":
    unittest.main()
