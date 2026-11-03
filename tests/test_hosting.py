"""Production configuration and trusted-proxy regression checks."""

import io
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from dotenv import dotenv_values

from configure_host import configure_host
from members import create_app
from members.security import consume_auth_attempt


class HostingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = {
            "TESTING": True,
            "SECRET_KEY": "hosting-test-key-" + "x" * 50,
            "DATABASE": str(self.root / "members.sqlite3"),
            "APP_ENV": "production",
            "PUBLIC_BASE_URL": "https://testmember.pythonanywhere.com",
            "BREVO_API_KEY": "fake-provider-key",
            "MAIL_SENDER_EMAIL": "sender@example.com",
            "PYTHONANYWHERE_PROXY": True,
            "AUTH_LOGIN_IP_LIMIT": 1,
            "AUTH_LOGIN_ACCOUNT_LIMIT": 1000,
        }
        self.app = create_app(self.config)
        self.assertEqual(self.app.test_cli_runner().invoke(args=["init-db"]).exit_code, 0)

    def attempt(self, headers=None):
        with self.app.test_request_context("/login", headers=headers or {},
                                           environ_base={"REMOTE_ADDR": "10.0.0.10"}):
            return consume_auth_attempt("login", "member@example.com")

    def test_different_visitors_behind_host_proxy_have_separate_ip_limits(self):
        self.assertEqual(self.attempt({"X-Real-IP": "198.51.100.1"}), 0)
        self.assertEqual(self.attempt({"X-Real-IP": "198.51.100.2"}), 0)
        self.assertGreater(self.attempt({"X-Real-IP": "198.51.100.1"}), 0)

    def test_forwarded_for_cannot_override_the_host_header(self):
        self.assertEqual(self.attempt({"X-Real-IP": "198.51.100.1"}), 0)
        self.assertGreater(self.attempt({"X-Real-IP": "198.51.100.1",
                                         "X-Forwarded-For": "203.0.113.99"}), 0)

    def test_headers_are_ignored_outside_explicit_production_host_mode(self):
        for name, value in [("PYTHONANYWHERE_PROXY", False), ("APP_ENV", "development")]:
            with self.subTest(name=name):
                self.app = create_app({**self.config, name: value,
                                       "DATABASE": str(self.root / (name + ".sqlite3"))})
                self.assertEqual(self.app.test_cli_runner().invoke(args=["init-db"]).exit_code, 0)
                self.assertEqual(self.attempt({"X-Real-IP": "198.51.100.1"}), 0)
                self.assertGreater(self.attempt({"X-Real-IP": "198.51.100.2"}), 0)

    def test_invalid_or_missing_host_header_cannot_split_fallback_bucket(self):
        self.assertEqual(self.attempt(), 0)
        for value in ["fake-ip", "198.51.100.1, 198.51.100.2", "198.51.100.1:1234", "fe80::1%eth0"]:
            self.assertGreater(self.attempt({"X-Real-IP": value}), 0)

    def test_equivalent_ipv6_addresses_share_one_limit(self):
        self.assertEqual(self.attempt({"X-Real-IP": "2001:db8::1"}), 0)
        self.assertGreater(self.attempt({"X-Real-IP": "2001:0db8:0:0:0:0:0:1"}), 0)

    def test_host_configuration_is_private_preserved_and_usable(self):
        output = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), redirect_stdout(output):
            with patch("builtins.input", side_effect=["testmember", "sender@example.com"]), \
                    patch("getpass.getpass", return_value="fake-private-api-key"):
                configure_host(self.root)
            first = dotenv_values(self.root / ".env")
            with patch("builtins.input", side_effect=["testmember", ""]), \
                    patch("getpass.getpass", return_value=""):
                configure_host(self.root)
        saved = dotenv_values(self.root / ".env")
        self.assertEqual(saved, first)
        self.assertEqual(len(saved["SECRET_KEY"]), 64)
        self.assertNotIn(saved["SECRET_KEY"], output.getvalue())
        self.assertNotIn(saved["BREVO_API_KEY"], output.getvalue())
        self.assertEqual(stat.S_IMODE((self.root / ".env").stat().st_mode), 0o600)
        with patch.dict(os.environ, saved, clear=True):
            app = create_app({"TESTING": True, "DATABASE": str(self.root / "deployed.sqlite3")})
            self.assertTrue(app.config["PYTHONANYWHERE_PROXY"])
            self.assertFalse(app.debug)
            response = app.test_client().get("/login", base_url=saved["PUBLIC_BASE_URL"])
            self.assertEqual(response.status_code, 200)
            self.assertIn("Secure", response.headers["Set-Cookie"])
            self.assertIn("Strict-Transport-Security", response.headers)

    def test_host_setup_preserves_local_configuration_and_rejects_invalid_values(self):
        path = self.root / ".env"
        original = "APP_ENV=development\nSECRET_KEY=local-only\n"
        path.write_text(original)
        with self.assertRaisesRegex(RuntimeError, "local configuration"), patch("builtins.input") as prompt:
            configure_host(self.root)
        prompt.assert_not_called()
        self.assertEqual(path.read_text(), original)
        path.unlink()
        with patch.dict(os.environ, {}, clear=True):
            with patch("builtins.input", return_value="https://wrong.example.com"), \
                    self.assertRaises(ValueError):
                configure_host(self.root)
            with patch("builtins.input", side_effect=["testmember", "bad-email"]), \
                    patch("getpass.getpass", return_value="fake-key"), self.assertRaises(ValueError):
                configure_host(self.root)
        self.assertFalse(path.exists())

    def test_environment_override_is_reported_without_changing_configuration(self):
        with patch.dict(os.environ, {"APP_ENV": "development"}, clear=True), \
                patch("builtins.input", side_effect=["testmember", "sender@example.com"]), \
                patch("getpass.getpass", return_value="fake-key"), \
                self.assertRaisesRegex(RuntimeError, "APP_ENV"):
            configure_host(self.root)
        self.assertFalse((self.root / ".env").exists())


if __name__ == "__main__":
    unittest.main()
