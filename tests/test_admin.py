"""Administrator setup, role enforcement, private listing, and access changes."""

import hashlib
import re
import secrets
import time
import unittest
from unittest.mock import patch

from werkzeug.security import check_password_hash, generate_password_hash

import test_auth as auth_fixture
from members import admin

PASSWORD = auth_fixture.PASSWORD
ADMIN_EMAIL = "owner@example.com"
ADMIN_PASSWORD = "a private administrator test passphrase"


class AdministrationTests(unittest.TestCase):
    csrf = auth_fixture.AuthenticationTests.csrf
    register = auth_fixture.AuthenticationTests.register
    login = auth_fixture.AuthenticationTests.login
    db_execute = auth_fixture.AuthenticationTests.db_execute
    setUp = auth_fixture.AuthenticationTests.setUp

    def create_admin(self, email=ADMIN_EMAIL):
        result = self.app.test_cli_runner().invoke(
            args=["create-admin", "--email", email], input=ADMIN_PASSWORD + "\n" + ADMIN_PASSWORD + "\n",
        )
        self.assertEqual(result.exit_code, 0, (result.output, result.exception))
        return self.db_execute("SELECT id FROM users WHERE email = ?", (email,))[0][0]

    def admin_login(self):
        response = self.login(ADMIN_EMAIL, ADMIN_PASSWORD)
        self.assertEqual(response.status_code, 303)

    def action(self, target_id, blocked=True, **extra):
        data = {"csrf_token": self.csrf(self.client, "/admin/users")}
        data.update(extra)
        suffix = "block" if blocked else "unblock"
        return self.client.post(f"/admin/users/{target_id}/{suffix}", data=data)

    def seed_reset(self, user_id):
        token = secrets.token_urlsafe(32)
        self.db_execute(
            "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
            (user_id, hashlib.sha256(token.encode()).hexdigest(), int(time.time()) + 900),
        )
        return token

    def token_check(self, token, client=None):
        client = client or self.client
        csrf_token = self.csrf(client, "/reset-password")
        return client.post("/reset-password/check", data={"csrf_token": csrf_token, "token": token})

    def test_cli_creates_admin_with_hidden_hashed_password(self):
        result = self.app.test_cli_runner().invoke(
            args=["create-admin"], input=ADMIN_EMAIL + "\n" + ADMIN_PASSWORD + "\n" + ADMIN_PASSWORD + "\n",
        )
        self.assertEqual(result.exit_code, 0, (result.output, result.exception))
        self.assertNotIn(ADMIN_PASSWORD, result.output)
        user = self.db_execute("SELECT * FROM users")[0]
        self.assertEqual((user["email"], user["is_admin"], user["is_blocked"]), (ADMIN_EMAIL, 1, 0))
        self.assertTrue(check_password_hash(user["password_hash"], ADMIN_PASSWORD))
        self.admin_login()
        self.assertEqual(self.client.get("/admin/users").status_code, 200)

    def test_cli_promotes_existing_account_and_revokes_old_credentials(self):
        self.register()
        self.login()
        user = self.db_execute("SELECT * FROM users")[0]
        self.seed_reset(user["id"])
        result = self.app.test_cli_runner().invoke(
            args=["create-admin", "--email", " ALICE@EXAMPLE.COM "], input=PASSWORD + "\n",
        )
        self.assertEqual(result.exit_code, 0, (result.output, result.exception))
        current = self.db_execute("SELECT * FROM users")[0]
        self.assertEqual((current["is_admin"], current["session_version"]), (1, 2))
        self.assertEqual(current["password_hash"], user["password_hash"])
        self.assertEqual(len(self.db_execute("SELECT * FROM member_sessions")), 0)
        self.assertEqual(len(self.db_execute("SELECT * FROM password_reset_tokens")), 0)
        self.assertEqual(self.client.get("/members").status_code, 302)
        self.login()
        self.assertEqual(self.client.get("/admin/users").status_code, 200)

    def test_cli_rejects_wrong_password_blocked_account_and_weak_new_password(self):
        self.register()
        runner = self.app.test_cli_runner()
        result = runner.invoke(args=["create-admin", "--email", "alice@example.com"], input="incorrect password\n")
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(self.db_execute("SELECT is_admin FROM users")[0][0], 0)
        self.db_execute("UPDATE users SET is_blocked = 1")
        result = runner.invoke(args=["create-admin", "--email", "alice@example.com"], input=PASSWORD + "\n")
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(tuple(self.db_execute("SELECT is_admin, is_blocked FROM users")[0]), (0, 1))
        result = runner.invoke(args=["create-admin", "--email", "new@example.com"], input="short\nshort\n")
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(len(self.db_execute("SELECT * FROM users")), 1)
        self.assertEqual(runner.invoke(args=["create-admin", "--email", "invalid"]).exit_code, 1)
        self.assertEqual(runner.invoke(args=["create-admin", "--password", "not-a-real-secret"]).exit_code, 2)

    def test_existing_admin_command_is_idempotent(self):
        self.create_admin()
        self.admin_login()
        before = dict(self.db_execute("SELECT * FROM users")[0])
        result = self.app.test_cli_runner().invoke(args=["create-admin", "--email", ADMIN_EMAIL])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("already an active administrator", result.output)
        self.assertEqual(dict(self.db_execute("SELECT * FROM users")[0]), before)
        self.assertEqual(self.client.get("/admin/users").status_code, 200)

    def test_anonymous_and_members_cannot_read_or_change_admin_data(self):
        self.create_admin()
        self.register()
        self.register("private.member@example.com")
        target_id = self.db_execute("SELECT id FROM users WHERE email = ?", ("private.member@example.com",))[0][0]
        self.assertEqual(self.client.get("/admin/users").status_code, 302)
        csrf_token = self.csrf(self.client, "/login")
        response = self.client.post(f"/admin/users/{target_id}/block", data={"csrf_token": csrf_token})
        self.assertEqual(response.status_code, 302)
        self.login()
        response = self.client.get("/admin/users?is_admin=1")
        self.assertEqual(response.status_code, 403)
        self.assertNotIn(b"private.member@example.com", response.data)
        self.assertNotIn(ADMIN_EMAIL.encode(), response.data)
        self.assertNotIn(b'>Admin</a>', self.client.get("/members").data)
        for suffix in ["block", "unblock"]:
            response = self.client.post(f"/admin/users/{target_id}/{suffix}", data={
                "csrf_token": self.csrf(self.client, "/members"), "is_admin": "1", "user_id": target_id,
            })
            self.assertEqual(response.status_code, 403)
        self.assertEqual(self.db_execute("SELECT is_blocked FROM users WHERE id = ?", (target_id,))[0][0], 0)
        self.assertEqual(self.client.get("/create-admin").status_code, 404)

    def test_admin_list_includes_signup_metadata_but_never_hashes_or_tokens(self):
        self.create_admin()
        self.register()
        user = self.db_execute("SELECT * FROM users WHERE email = ?", ("alice@example.com",))[0]
        token = self.seed_reset(user["id"])
        self.admin_login()
        response = self.client.get("/admin/users")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"alice@example.com", response.data)
        self.assertIn(user["created_at"][:10].encode(), response.data)
        self.assertIn(b">Admin<", response.data)
        self.assertIn(b">Member<", response.data)
        self.assertNotIn(user["password_hash"].encode(), response.data)
        self.assertNotIn(token.encode(), response.data)
        self.assertNotIn(hashlib.sha256(token.encode()).hexdigest().encode(), response.data)
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_blocking_revokes_all_victim_sessions_and_reset_links(self):
        self.create_admin()
        self.register()
        self.register("bob@example.com")
        alice_id = self.db_execute("SELECT id FROM users WHERE email = ?", ("alice@example.com",))[0][0]
        bob_id = self.db_execute("SELECT id FROM users WHERE email = ?", ("bob@example.com",))[0][0]
        alice = self.app.test_client()
        alice_other = self.app.test_client()
        bob = self.app.test_client()
        self.login(client=alice)
        self.login(client=alice_other)
        self.login("bob@example.com", client=bob)
        alice_token = self.seed_reset(alice_id)
        self.seed_reset(bob_id)
        self.admin_login()
        response = self.action(alice_id, user_id=bob_id, is_blocked="0", is_admin="1")
        self.assertEqual(response.status_code, 303)
        current = self.db_execute("SELECT * FROM users WHERE id = ?", (alice_id,))[0]
        self.assertEqual((current["is_blocked"], current["is_admin"], current["session_version"]), (1, 0, 2))
        self.assertEqual(len(self.db_execute("SELECT * FROM member_sessions WHERE user_id = ?", (alice_id,))), 0)
        self.assertEqual(len(self.db_execute("SELECT * FROM password_reset_tokens WHERE user_id = ?", (alice_id,))), 0)
        self.assertEqual(len(self.db_execute("SELECT * FROM password_reset_tokens WHERE user_id = ?", (bob_id,))), 1)
        self.assertEqual(alice.get("/members").status_code, 302)
        self.assertEqual(alice_other.get("/account").status_code, 302)
        self.assertEqual(bob.get("/members").status_code, 200)
        self.assertEqual(self.login(client=alice).status_code, 200)
        self.assertEqual(self.token_check(alice_token, client=alice).status_code, 400)
        self.app.config.update(BREVO_API_KEY="fake-test-key", MAIL_SENDER_EMAIL="sender@example.com")
        with patch("members.mail.send_reset_email") as send:
            response = alice.post("/forgot-password", data={
                "csrf_token": self.csrf(alice, "/forgot-password"), "email": "alice@example.com",
            })
            self.assertEqual(response.status_code, 303)
            send.assert_not_called()

    def test_unblocking_does_not_restore_preblock_cookies_or_links(self):
        self.create_admin()
        self.register()
        alice_id = self.db_execute("SELECT id FROM users WHERE email = ?", ("alice@example.com",))[0][0]
        alice = self.app.test_client()
        self.login(client=alice)
        cookie_name = self.app.config["SESSION_COOKIE_NAME"]
        old_cookie = alice.get_cookie(cookie_name).value
        old_token = self.seed_reset(alice_id)
        self.admin_login()
        self.action(alice_id)
        self.assertEqual(self.action(alice_id, blocked=False).status_code, 303)
        self.assertEqual(tuple(self.db_execute("SELECT is_blocked, session_version FROM users WHERE id = ?", (alice_id,))[0]), (0, 3))
        replay = self.app.test_client()
        replay.set_cookie(cookie_name, old_cookie)
        self.assertEqual(replay.get("/members").status_code, 302)
        self.assertEqual(self.token_check(old_token, client=alice).status_code, 400)
        self.assertEqual(self.login(client=alice).status_code, 303)
        self.assertEqual(alice.get("/members").status_code, 200)

    def test_admin_cannot_change_own_status(self):
        owner_id = self.create_admin()
        self.admin_login()
        before = dict(self.db_execute("SELECT * FROM users")[0])
        for blocked in [True, False]:
            self.assertEqual(self.action(owner_id, blocked=blocked).status_code, 409)
        self.assertEqual(dict(self.db_execute("SELECT * FROM users")[0]), before)
        self.assertEqual(self.client.get("/admin/users").status_code, 200)

    def test_other_admin_can_be_blocked_without_demoting_them(self):
        self.create_admin()
        other_id = self.create_admin("second.owner@example.com")
        self.admin_login()
        self.assertEqual(self.action(other_id).status_code, 303)
        self.assertEqual(tuple(self.db_execute("SELECT is_admin, is_blocked FROM users WHERE id = ?", (other_id,))[0]), (1, 1))
        self.assertEqual(self.client.get("/admin/users").status_code, 200)

    def test_duplicate_actions_are_idempotent_and_preserve_fresh_login(self):
        self.create_admin()
        self.register()
        alice_id = self.db_execute("SELECT id FROM users WHERE email = ?", ("alice@example.com",))[0][0]
        self.admin_login()
        self.action(alice_id)
        self.action(alice_id)
        self.assertEqual(self.db_execute("SELECT session_version FROM users WHERE id = ?", (alice_id,))[0][0], 2)
        self.action(alice_id, blocked=False)
        alice = self.app.test_client()
        self.login(client=alice)
        self.action(alice_id, blocked=False)
        self.assertEqual(self.db_execute("SELECT session_version FROM users WHERE id = ?", (alice_id,))[0][0], 3)
        self.assertEqual(alice.get("/members").status_code, 200)

    def test_csrf_post_only_and_unknown_targets(self):
        self.create_admin()
        self.register()
        alice_id = self.db_execute("SELECT id FROM users WHERE email = ?", ("alice@example.com",))[0][0]
        self.admin_login()
        for suffix in ["block", "unblock"]:
            self.assertEqual(self.client.get(f"/admin/users/{alice_id}/{suffix}").status_code, 405)
            self.assertEqual(self.client.post(f"/admin/users/{alice_id}/{suffix}", data={}).status_code, 400)
        self.assertEqual(self.action(999999).status_code, 404)
        self.assertEqual(self.action(2**70).status_code, 404)
        self.assertEqual(self.db_execute("SELECT is_blocked FROM users WHERE id = ?", (alice_id,))[0][0], 0)

    def test_role_is_checked_on_every_request_and_ignores_cookie_flags(self):
        owner_id = self.create_admin()
        self.register()
        alice_id = self.db_execute("SELECT id FROM users WHERE email = ?", ("alice@example.com",))[0][0]
        self.admin_login()
        self.db_execute("UPDATE users SET is_admin = 0 WHERE id = ?", (owner_id,))
        with self.client.session_transaction() as data:
            data["is_admin"] = 1
            data["user_id"] = alice_id
        self.assertEqual(self.client.get("/admin/users").status_code, 403)
        response = self.client.post(f"/admin/users/{alice_id}/block", data={"csrf_token": self.csrf(self.client, "/members"), "is_admin": "1"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.db_execute("SELECT is_blocked FROM users WHERE id = ?", (alice_id,))[0][0], 0)

    def test_transaction_rechecks_actor_after_concurrent_demotion(self):
        owner_id = self.create_admin()
        self.register()
        alice_id = self.db_execute("SELECT id FROM users WHERE email = ?", ("alice@example.com",))[0][0]
        self.admin_login()
        original = admin.set_member_blocked
        def demote_then_act(*args):
            self.db_execute("UPDATE users SET is_admin = 0 WHERE id = ?", (owner_id,))
            return original(*args)
        with patch("members.admin.set_member_blocked", side_effect=demote_then_act):
            response = self.action(alice_id)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.db_execute("SELECT is_blocked FROM users WHERE id = ?", (alice_id,))[0][0], 0)

    def test_search_status_pagination_and_literal_sql_wildcards(self):
        self.create_admin()
        password_hash = generate_password_hash(PASSWORD)
        for number in range(30):
            self.db_execute("INSERT INTO users (email, password_hash, is_blocked) VALUES (?, ?, ?)",
                            (f"member{number:02d}@example.com", password_hash, int(number == 0)))
        self.db_execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", ("literal%marker@example.com", password_hash))
        self.admin_login()
        first = self.client.get("/admin/users")
        rows = re.findall(r'<td class="email-column">([^<]+)', first.get_data(as_text=True))
        self.assertEqual(len(rows), 25)
        last = self.client.get("/admin/users?page=999999999999999999999")
        self.assertIn(b"Page 2 of 2", last.data)
        self.assertEqual(len(re.findall(r'<td class="email-column">([^<]+)', last.get_data(as_text=True))), 7)
        filtered = self.client.get("/admin/users", query_string={"q": "member00", "status": "blocked"})
        self.assertIn(b"member00@example.com", filtered.data)
        self.assertNotIn(b"member01@example.com", filtered.data)
        literal = self.client.get("/admin/users", query_string={"q": "%"})
        self.assertIn(b"literal%marker@example.com", literal.data)
        self.assertNotIn(b"member01@example.com", literal.data)
        injection = self.client.get("/admin/users", query_string={"q": "' OR 1=1 --"})
        self.assertEqual(injection.status_code, 200)
        self.assertIn(b"No accounts match this search", injection.data)
        self.assertEqual(len(self.db_execute("SELECT * FROM users")), 32)

    def test_promotion_rechecks_blocked_status_after_password_check(self):
        self.register()
        original = admin.check_password_hash
        def block_during_check(*args):
            result = original(*args)
            self.db_execute("UPDATE users SET is_blocked = 1")
            return result
        with patch("members.admin.check_password_hash", side_effect=block_during_check):
            result = self.app.test_cli_runner().invoke(
                args=["create-admin", "--email", "alice@example.com"], input=PASSWORD + "\n",
            )
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(tuple(self.db_execute("SELECT is_admin, is_blocked FROM users")[0]), (0, 1))


if __name__ == "__main__":
    unittest.main()
