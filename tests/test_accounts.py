"""Account changes: ownership, reauthentication, revocation, and race guards."""

import hashlib
import re
import time
import unittest
from html.parser import HTMLParser
from unittest.mock import patch

from werkzeug.security import check_password_hash, generate_password_hash

import test_auth as auth_fixture
from members import accounts, auth

PASSWORD = auth_fixture.PASSWORD
NEW_PASSWORD = "my different long test passphrase"
BOB_PASSWORD = "bob has a different test passphrase"


class AccountSettingsTests(unittest.TestCase):
    # Reuse the established fixture/helpers without inheriting its test methods.
    csrf = auth_fixture.AuthenticationTests.csrf
    register = auth_fixture.AuthenticationTests.register
    login = auth_fixture.AuthenticationTests.login
    db_execute = auth_fixture.AuthenticationTests.db_execute

    def setUp(self):
        auth_fixture.AuthenticationTests.setUp(self)
        self.app.config.update(AUTH_ACCOUNT_IP_LIMIT=1000, AUTH_ACCOUNT_ACCOUNT_LIMIT=1000)

    def signed_in(self):
        self.assertEqual(self.register().status_code, 303)
        self.assertEqual(self.login().status_code, 303)
        return self.db_execute("SELECT id FROM users WHERE email = ?", ("alice@example.com",))[0][0]

    def change(self, action, client=None, **extra):
        client = client or self.client
        data = {"current_password": PASSWORD, "csrf_token": self.csrf(client, "/account")}
        if action == "email":
            data["new_email"] = "alice.updated@example.com"
        elif action == "password":
            data.update(new_password=NEW_PASSWORD, confirm_password=NEW_PASSWORD)
        elif action == "delete":
            data["confirm_delete"] = "y"
        data.update(extra)
        return client.post("/account/" + action, data=data)

    def add_reset(self, user_id, marker):
        self.db_execute(
            "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
            (user_id, hashlib.sha256(marker.encode()).hexdigest(), int(time.time()) + 3600),
        )

    def test_account_page_is_private_and_has_unique_field_ids(self):
        self.assertEqual(self.client.get("/account").status_code, 302)
        self.register("bob@example.com")
        self.signed_in()
        response = self.client.get("/account?user_id=1")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"alice@example.com", response.data)
        self.assertNotIn(b"bob@example.com", response.data)
        ids = re.findall(r'\bid="([^"]+)"', response.get_data(as_text=True))
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        for path in ["/account/email", "/account/password", "/account/delete"]:
            self.assertEqual(self.client.get(path).status_code, 405)

    def test_anonymous_and_csrf_requests_cannot_change_accounts(self):
        token = self.csrf(self.client, "/login")
        for action in ["email", "password", "delete"]:
            response = self.client.post("/account/" + action, data={"csrf_token": token})
            self.assertEqual(response.status_code, 302)
        user_id = self.signed_in()
        for action in ["email", "password", "delete"]:
            response = self.client.post("/account/" + action, data={"current_password": PASSWORD})
            self.assertEqual(response.status_code, 400)
        self.assertEqual(self.db_execute("SELECT id FROM users")[0][0], user_id)

    def test_wrong_current_password_rejects_all_actions(self):
        self.signed_in()
        before = dict(self.db_execute("SELECT * FROM users")[0])
        for action in ["email", "password", "delete"]:
            response = self.change(action, current_password="wrong password")
            self.assertEqual(response.status_code, 400)
            self.assertIn(b"The current password is incorrect.", response.data)
            self.assertNotIn(b"wrong password", response.data)
            self.assertEqual(dict(self.db_execute("SELECT * FROM users")[0]), before)
        self.assertEqual(self.client.get("/members").status_code, 200)

    def test_email_change_revokes_all_owner_sessions_and_reset_tokens(self):
        self.register("bob@example.com", BOB_PASSWORD)
        user_id = self.signed_in()
        bob_id = self.db_execute("SELECT id FROM users WHERE email = ?", ("bob@example.com",))[0][0]
        other = self.app.test_client()
        bob = self.app.test_client()
        self.login(client=other)
        self.login("bob@example.com", BOB_PASSWORD, client=bob)
        self.add_reset(user_id, "alice-reset")
        self.add_reset(bob_id, "bob-reset")
        response = self.change("email", new_email=" Alice.Updated@EXAMPLE.com ")
        self.assertEqual(response.status_code, 303)
        self.assertTrue(response.location.endswith("/login"))
        user = self.db_execute("SELECT * FROM users WHERE id = ?", (user_id,))[0]
        self.assertEqual(user["email"], "alice.updated@example.com")
        self.assertEqual(user["session_version"], 2)
        self.assertEqual(len(self.db_execute("SELECT * FROM member_sessions WHERE user_id = ?", (user_id,))), 0)
        self.assertEqual(len(self.db_execute("SELECT * FROM password_reset_tokens WHERE user_id = ?", (user_id,))), 0)
        self.assertEqual(len(self.db_execute("SELECT * FROM password_reset_tokens WHERE user_id = ?", (bob_id,))), 1)
        self.assertEqual(other.get("/members").status_code, 302)
        self.assertEqual(bob.get("/members").status_code, 200)
        self.assertEqual(self.login().status_code, 200)
        self.assertEqual(self.login("alice.updated@example.com").status_code, 303)

    def test_duplicate_email_rolls_back_without_revoking_session(self):
        self.register("bob@example.com", BOB_PASSWORD)
        user_id = self.signed_in()
        self.add_reset(user_id, "must-be-preserved")
        before = dict(self.db_execute("SELECT * FROM users WHERE id = ?", (user_id,))[0])
        response = self.change("email", new_email="BOB@EXAMPLE.COM")
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"That email address cannot be used", response.data)
        self.assertEqual(dict(self.db_execute("SELECT * FROM users WHERE id = ?", (user_id,))[0]), before)
        self.assertEqual(self.client.get("/members").status_code, 200)
        self.assertEqual(len(self.db_execute("SELECT * FROM password_reset_tokens WHERE user_id = ?", (user_id,))), 1)

    def test_same_or_invalid_email_is_rejected(self):
        self.signed_in()
        for email in ["invalid-address", " ALICE@EXAMPLE.COM "]:
            self.assertEqual(self.change("email", new_email=email).status_code, 400)
        self.assertEqual(self.db_execute("SELECT email FROM users")[0][0], "alice@example.com")

    def test_password_change_hashes_new_value_and_revokes_sessions(self):
        user_id = self.signed_in()
        old_hash = self.db_execute("SELECT password_hash FROM users")[0][0]
        other = self.app.test_client()
        self.login(client=other)
        self.add_reset(user_id, "old-password-reset")
        response = self.change("password")
        self.assertEqual(response.status_code, 303)
        current = self.db_execute("SELECT * FROM users")[0]
        self.assertNotEqual(current["password_hash"], old_hash)
        self.assertTrue(check_password_hash(current["password_hash"], NEW_PASSWORD))
        self.assertFalse(check_password_hash(current["password_hash"], PASSWORD))
        self.assertEqual(current["email"], "alice@example.com")
        self.assertEqual(current["session_version"], 2)
        self.assertEqual(len(self.db_execute("SELECT * FROM password_reset_tokens")), 0)
        self.assertEqual(other.get("/members").status_code, 302)
        self.assertEqual(self.login(password=PASSWORD).status_code, 200)
        self.assertEqual(self.login(password=NEW_PASSWORD).status_code, 303)

    def test_password_policy_confirmation_and_old_value(self):
        self.signed_in()
        for password in ["short", "x" * 129, PASSWORD]:
            response = self.change("password", new_password=password, confirm_password=password)
            self.assertEqual(response.status_code, 400)
        response = self.change("password", confirm_password="different confirmation")
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"The passwords must match.", response.data)
        self.assertNotIn(NEW_PASSWORD.encode(), response.data)
        self.assertTrue(check_password_hash(self.db_execute("SELECT password_hash FROM users")[0][0], PASSWORD))

    def test_account_deletion_requires_explicit_confirmation(self):
        self.signed_in()
        response = self.change("delete", confirm_delete="")
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Confirm that you want to permanently delete your account.", response.data)
        self.assertEqual(len(self.db_execute("SELECT * FROM users")), 1)
        self.assertEqual(self.client.get("/members").status_code, 200)

    def test_delete_cascades_only_owners_records_and_revokes_cookies(self):
        self.register("bob@example.com", BOB_PASSWORD)
        user_id = self.signed_in()
        bob_id = self.db_execute("SELECT id FROM users WHERE email = ?", ("bob@example.com",))[0][0]
        bob = self.app.test_client()
        self.login("bob@example.com", BOB_PASSWORD, client=bob)
        self.add_reset(user_id, "alice-to-remove")
        self.add_reset(bob_id, "bob-to-preserve")
        cookie_name = self.app.config["SESSION_COOKIE_NAME"]
        old_cookie = self.client.get_cookie(cookie_name).value
        response = self.change("delete")
        self.assertEqual(response.status_code, 303)
        self.assertTrue(response.location.endswith("/"))
        self.assertEqual([row["email"] for row in self.db_execute("SELECT * FROM users")], ["bob@example.com"])
        self.assertEqual([row["user_id"] for row in self.db_execute("SELECT * FROM member_sessions")], [bob_id])
        self.assertEqual([row["user_id"] for row in self.db_execute("SELECT * FROM password_reset_tokens")], [bob_id])
        self.assertEqual(bob.get("/members").status_code, 200)
        replay = self.app.test_client()
        replay.set_cookie(cookie_name, old_cookie)
        self.assertEqual(replay.get("/members").status_code, 302)
        self.assertEqual(self.login().status_code, 200)

    def assert_forged_target_is_ignored(self, action):
        self.register("bob@example.com", BOB_PASSWORD)
        user_id = self.signed_in()
        bob_before = dict(self.db_execute("SELECT * FROM users WHERE email = ?", ("bob@example.com",))[0])
        response = self.change(action, user_id=bob_before["id"], id=bob_before["id"],
                               is_admin="1", is_blocked="1", current_password=BOB_PASSWORD)
        self.assertEqual(response.status_code, 400)
        response = self.change(action, user_id=bob_before["id"], id=bob_before["id"],
                               is_admin="1", is_blocked="1")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(dict(self.db_execute("SELECT * FROM users WHERE id = ?", (bob_before["id"],))[0]), bob_before)
        owner_rows = self.db_execute("SELECT * FROM users WHERE id = ?", (user_id,))
        if action == "delete":
            self.assertEqual(len(owner_rows), 0)
        else:
            self.assertEqual((owner_rows[0]["is_admin"], owner_rows[0]["is_blocked"]), (0, 0))
            if action == "email":
                self.assertEqual(owner_rows[0]["email"], "alice.updated@example.com")
            else:
                self.assertTrue(check_password_hash(owner_rows[0]["password_hash"], NEW_PASSWORD))

    def test_email_change_cannot_target_another_member(self):
        self.assert_forged_target_is_ignored("email")

    def test_password_change_cannot_target_another_member(self):
        self.assert_forged_target_is_ignored("password")

    def test_deletion_cannot_target_another_member(self):
        self.assert_forged_target_is_ignored("delete")

    def test_account_throttle_is_shared_across_actions_and_browsers(self):
        self.signed_in()
        self.app.config.update(AUTH_ACCOUNT_IP_LIMIT=1000, AUTH_ACCOUNT_ACCOUNT_LIMIT=2)
        self.assertEqual(self.change("email", current_password="wrong password").status_code, 400)
        self.assertEqual(self.change("password", current_password="wrong password").status_code, 400)
        other = self.app.test_client()
        self.login(client=other)
        response = self.change("delete", client=other)
        self.assertEqual(response.status_code, 429)
        self.assertGreater(int(response.headers["Retry-After"]), 0)
        self.assertEqual(len(self.db_execute("SELECT * FROM users")), 1)

    def test_concurrent_blocking_prevents_change_after_password_check(self):
        user_id = self.signed_in()
        original = accounts.verify_current_password
        def concurrent_block(password):
            user = original(password)
            self.db_execute("UPDATE users SET is_blocked = 1, session_version = session_version + 1 WHERE id = ?", (user_id,))
            return user
        with patch("members.accounts.verify_current_password", side_effect=concurrent_block):
            response = self.change("email")
        self.assertEqual(response.status_code, 303)
        self.assertTrue(response.location.endswith("/login"))
        self.assertEqual(self.db_execute("SELECT email FROM users")[0][0], "alice@example.com")

    def test_concurrent_logout_prevents_change_after_password_check(self):
        user_id = self.signed_in()
        original = accounts.verify_current_password
        def concurrent_logout(password):
            user = original(password)
            self.db_execute("DELETE FROM member_sessions WHERE user_id = ?", (user_id,))
            return user
        with patch("members.accounts.verify_current_password", side_effect=concurrent_logout):
            response = self.change("delete")
        self.assertEqual(response.status_code, 303)
        self.assertTrue(response.location.endswith("/login"))
        self.assertEqual(len(self.db_execute("SELECT * FROM users")), 1)

    def test_inflight_login_cannot_attach_to_reused_deleted_user_id(self):
        self.register()
        user_id = self.db_execute("SELECT id FROM users")[0][0]
        replacement_hash = generate_password_hash(BOB_PASSWORD)
        original = auth.begin_session
        def delete_and_replace(user):
            self.db_execute("DELETE FROM users WHERE id = ?", (user_id,))
            self.db_execute("INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)",
                            (user_id, "replacement@example.com", replacement_hash))
            return original(user)
        with patch("members.auth.begin_session", side_effect=delete_and_replace):
            response = self.login()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Unable to log in with those details.", response.data)
        self.assertEqual(self.client.get("/members").status_code, 302)
        self.assertEqual(len(self.db_execute("SELECT * FROM member_sessions")), 0)


if __name__ == "__main__":
    unittest.main()
