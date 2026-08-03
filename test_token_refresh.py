import io
import json
import logging
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from google.auth.exceptions import RefreshError

import google_ads_server as server


class FakeCredentials:
    def __init__(self, *, valid=True, expired=False, token="access-value", refresh_token="refresh-value"):
        self.valid = valid
        self.expired = expired
        self.token = token
        self.refresh_token = refresh_token

    def refresh(self, _request):
        self.valid = True
        self.expired = False

    def to_json(self):
        return json.dumps({"token": self.token, "refresh_token": self.refresh_token})


class FailingRefreshCredentials(FakeCredentials):
    def refresh(self, _request):
        raise RefreshError("developer-token=developer-value bearer access-value")


class FakeOAuthFlow:
    def __init__(self, credentials):
        self.credentials = credentials
        self.called = False

    def run_local_server(self, port):
        self.called = True
        self.port = port
        return self.credentials


class AuthenticationSecurityTests(unittest.TestCase):
    def capture_server_logs(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        server.logger.addHandler(handler)
        self.addCleanup(server.logger.removeHandler, handler)
        return stream

    def test_headers_are_built_without_logging_credentials(self):
        logs = self.capture_server_logs()
        credentials = FakeCredentials(token="access-value")
        with patch.object(server, "GOOGLE_ADS_DEVELOPER_TOKEN", "developer-value"):
            headers = server.get_headers(credentials)

        self.assertEqual(headers["Authorization"], "Bearer access-value")
        self.assertEqual(headers["developer-token"], "developer-value")
        self.assertNotIn("access-value", logs.getvalue())
        self.assertNotIn("developer-value", logs.getvalue())

    def test_refresh_failure_never_logs_or_returns_secret_fragments(self):
        logs = self.capture_server_logs()
        credentials = FailingRefreshCredentials(valid=False, expired=True)
        with patch.object(server, "GOOGLE_ADS_DEVELOPER_TOKEN", "developer-value"):
            with self.assertRaises(server.AuthenticationError) as raised:
                server.get_headers(credentials)

        combined = logs.getvalue() + str(raised.exception)
        self.assertNotIn("access-value", combined)
        self.assertNotIn("developer-value", combined)
        self.assertNotIn("refresh-value", combined)
        self.assertIn("RefreshError", logs.getvalue())

    def test_client_configuration_is_never_overwritten_by_user_token(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            client_path = root / "oauth-client.json"
            token_path = root / "oauth-token.json"
            client_config = {
                "installed": {
                    "client_id": "client-value",
                    "client_secret": "client-secret-value",
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            }
            original = json.dumps(client_config, sort_keys=True)
            client_path.write_text(original, encoding="utf-8")
            flow = FakeOAuthFlow(FakeCredentials())

            with (
                patch.object(server, "GOOGLE_ADS_OAUTH_CLIENT_PATH", str(client_path)),
                patch.object(server, "GOOGLE_ADS_OAUTH_TOKEN_PATH", str(token_path)),
                patch.object(server, "GOOGLE_ADS_CREDENTIALS_PATH", None),
                patch.object(server, "GOOGLE_ADS_ALLOW_INTERACTIVE_OAUTH", True),
                patch.object(server.InstalledAppFlow, "from_client_config", return_value=flow),
            ):
                credentials = server.get_oauth_credentials()

            self.assertTrue(credentials.valid)
            self.assertTrue(flow.called)
            self.assertEqual(client_path.read_text(encoding="utf-8"), original)
            self.assertTrue(token_path.exists())
            self.assertEqual(stat.S_IMODE(token_path.stat().st_mode), 0o600)

    def test_legacy_client_config_gets_a_distinct_token_path(self):
        with tempfile.TemporaryDirectory() as directory:
            client_path = Path(directory) / "credentials.json"
            client_path.write_text(json.dumps({"installed": {"client_id": "placeholder"}}), encoding="utf-8")
            with (
                patch.object(server, "GOOGLE_ADS_OAUTH_CLIENT_PATH", None),
                patch.object(server, "GOOGLE_ADS_OAUTH_TOKEN_PATH", None),
                patch.object(server, "GOOGLE_ADS_CREDENTIALS_PATH", str(client_path)),
            ):
                resolved_client, resolved_token, _ = server.resolve_oauth_paths()

            self.assertEqual(resolved_client, client_path)
            self.assertNotEqual(resolved_client, resolved_token)
            self.assertEqual(resolved_token.name, "google_ads_token.json")

    def test_identical_client_and_token_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "oauth.json")
            with (
                patch.object(server, "GOOGLE_ADS_OAUTH_CLIENT_PATH", path),
                patch.object(server, "GOOGLE_ADS_OAUTH_TOKEN_PATH", path),
                patch.object(server, "GOOGLE_ADS_CREDENTIALS_PATH", None),
            ):
                with self.assertRaises(server.AuthenticationError):
                    server.resolve_oauth_paths()

    def test_interactive_oauth_is_disabled_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            client_path = Path(directory) / "oauth-client.json"
            token_path = Path(directory) / "oauth-token.json"
            client_path.write_text(
                json.dumps({"installed": {"client_id": "placeholder", "client_secret": "placeholder"}}),
                encoding="utf-8",
            )
            with (
                patch.object(server, "GOOGLE_ADS_OAUTH_CLIENT_PATH", str(client_path)),
                patch.object(server, "GOOGLE_ADS_OAUTH_TOKEN_PATH", str(token_path)),
                patch.object(server, "GOOGLE_ADS_CREDENTIALS_PATH", None),
                patch.object(server, "GOOGLE_ADS_ALLOW_INTERACTIVE_OAUTH", False),
                patch.object(server.InstalledAppFlow, "from_client_config") as flow_factory,
            ):
                with self.assertRaisesRegex(server.AuthenticationError, "Interactive OAuth is disabled"):
                    server.get_oauth_credentials()
            flow_factory.assert_not_called()

    def test_public_errors_do_not_echo_unknown_exception_messages(self):
        secret = "developer-token=developer-value bearer access-value"
        self.assertEqual(server.public_error_message(ValueError(secret)), "ValueError")


if __name__ == "__main__":
    unittest.main()
