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

    def _write_token(self, path, mode=0o600):
        path.write_text(json.dumps({"token": "access-value", "refresh_token": "refresh-value"}), encoding="utf-8")
        path.chmod(mode)

    def test_an_existing_world_readable_token_is_narrowed_before_it_is_read(self):
        # The 0600 chmod only ran when THIS process wrote the token. A token left behind by an
        # older version, a backup or a manual copy stayed readable by everyone for its whole life.
        with tempfile.TemporaryDirectory() as directory:
            token_path = Path(directory) / "oauth-token.json"
            self._write_token(token_path, mode=0o644)

            with (
                patch.object(server, "GOOGLE_ADS_OAUTH_CLIENT_PATH", None),
                patch.object(server, "GOOGLE_ADS_OAUTH_TOKEN_PATH", str(token_path)),
                patch.object(server, "GOOGLE_ADS_CREDENTIALS_PATH", None),
                patch.object(server.Credentials, "from_authorized_user_info", return_value=FakeCredentials()),
            ):
                server.get_oauth_credentials()

            self.assertEqual(stat.S_IMODE(token_path.stat().st_mode), 0o600)

    def test_an_unsecurable_token_is_refused_rather_than_read(self):
        with tempfile.TemporaryDirectory() as directory:
            token_path = Path(directory) / "oauth-token.json"
            self._write_token(token_path, mode=0o644)

            with (
                patch.object(server, "GOOGLE_ADS_OAUTH_CLIENT_PATH", None),
                patch.object(server, "GOOGLE_ADS_OAUTH_TOKEN_PATH", str(token_path)),
                patch.object(server, "GOOGLE_ADS_CREDENTIALS_PATH", None),
                patch.object(server.os, "chmod", side_effect=OSError("read-only filesystem")),
            ):
                with self.assertRaisesRegex(server.AuthenticationError, "could not be secured"):
                    server.get_oauth_credentials()

    def test_a_corrupt_token_blocks_by_default_but_reauthorizes_when_explicitly_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            client_path = Path(directory) / "oauth-client.json"
            token_path = Path(directory) / "oauth-token.json"
            client_path.write_text(
                json.dumps({"installed": {"client_id": "placeholder", "client_secret": "placeholder"}}),
                encoding="utf-8",
            )
            token_path.write_text("{ this is not json", encoding="utf-8")
            token_path.chmod(0o600)

            # Default: fail closed, exactly as before.
            with (
                patch.object(server, "GOOGLE_ADS_OAUTH_CLIENT_PATH", str(client_path)),
                patch.object(server, "GOOGLE_ADS_OAUTH_TOKEN_PATH", str(token_path)),
                patch.object(server, "GOOGLE_ADS_CREDENTIALS_PATH", None),
                patch.object(server, "GOOGLE_ADS_ALLOW_INTERACTIVE_OAUTH", False),
            ):
                with self.assertRaises(server.AuthenticationError):
                    server.get_oauth_credentials()

            # Explicitly supervised: the documented reauthorization can actually run.
            flow = FakeOAuthFlow(FakeCredentials())
            with (
                patch.object(server, "GOOGLE_ADS_OAUTH_CLIENT_PATH", str(client_path)),
                patch.object(server, "GOOGLE_ADS_OAUTH_TOKEN_PATH", str(token_path)),
                patch.object(server, "GOOGLE_ADS_CREDENTIALS_PATH", None),
                patch.object(server, "GOOGLE_ADS_ALLOW_INTERACTIVE_OAUTH", True),
                patch.object(server.InstalledAppFlow, "from_client_config", return_value=flow),
            ):
                credentials = server.get_oauth_credentials()

            self.assertTrue(flow.called)
            self.assertTrue(credentials.valid)

    def test_a_token_path_pointing_at_the_client_file_is_never_reauthorized_over(self):
        # This one must stay fatal even with the interactive flag on: recovering would send the
        # flow into _write_oauth_token and overwrite the OAuth CLIENT file with a user token.
        with tempfile.TemporaryDirectory() as directory:
            token_path = Path(directory) / "looks-like-a-token.json"
            original = json.dumps({"installed": {"client_id": "placeholder", "client_secret": "placeholder"}})
            token_path.write_text(original, encoding="utf-8")
            token_path.chmod(0o600)

            with (
                patch.object(server, "GOOGLE_ADS_OAUTH_CLIENT_PATH", None),
                patch.object(server, "GOOGLE_ADS_OAUTH_TOKEN_PATH", str(token_path)),
                patch.object(server, "GOOGLE_ADS_CREDENTIALS_PATH", None),
                patch.object(server, "GOOGLE_ADS_ALLOW_INTERACTIVE_OAUTH", True),
                patch.object(server.InstalledAppFlow, "from_client_config") as flow_factory,
            ):
                with self.assertRaisesRegex(server.AuthenticationError, "cannot be used as the token file"):
                    server.get_oauth_credentials()

            flow_factory.assert_not_called()
            self.assertEqual(token_path.read_text(encoding="utf-8"), original)


if __name__ == "__main__":
    unittest.main()
