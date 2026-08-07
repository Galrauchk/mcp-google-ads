import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).parent


class RepositorySecurityTests(unittest.TestCase):
    def git(self, *args):
        return subprocess.run(
            ["git", *args], cwd=ROOT, check=False, capture_output=True, text=True
        )

    def test_sensitive_local_filenames_are_ignored(self):
        candidates = [
            "credentials.json.bak",
            "credentials-local.json",
            "client_secret_desktop.json",
            "oauth-client.json",
            "oauth_token.json",
            "authorized_user.json",
            "service-account-local.json",
            "google-ads-private-key.pem",
            "google-ads-private-key.p12",
            "google-ads-private.key",
            ".secrets/google-ads.json",
            "reauth.py",
        ]
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                result = self.git("check-ignore", "-q", candidate)
                self.assertEqual(result.returncode, 0)

    def test_public_environment_example_remains_trackable(self):
        result = self.git("check-ignore", "-q", ".env.example")
        self.assertEqual(result.returncode, 1)

    def test_no_sensitive_filename_is_tracked(self):
        result = self.git("ls-files", "-z")
        self.assertEqual(result.returncode, 0)
        tracked = [name for name in result.stdout.split("\0") if name]
        forbidden = [
            name for name in tracked
            if name.endswith((".bak", ".backup"))
            or name == "reauth.py"
            or ("credentials" in name.lower() and name != ".env.example")
            # Both halves must judge the SAME string. Comparing "token" against the basename while
            # exempting test files by the full repo-relative path made any nested test file a false
            # positive: tests/auth/test_token.py does not start with "test_", so the guard would
            # have called a legitimate test a committed secret and failed CI.
            or ("token" in Path(name).name.lower() and not Path(name).name.startswith("test_"))
        ]
        self.assertEqual(forbidden, [])

    def test_logging_and_tests_never_slice_or_print_secret_values(self):
        sources = [
            ROOT / "google_ads_server.py",
            ROOT / "test_google_ads_mcp.py",
            ROOT / "test_token_refresh.py",
        ]
        forbidden_fragments = [
            "token[:",
            "safe_headers",
            "print(headers",
            "print(safe_headers",
            "logger.info(headers",
            "logger.debug(headers",
        ]
        combined = "\n".join(path.read_text(encoding="utf-8") for path in sources)
        for fragment in forbidden_fragments:
            with self.subTest(fragment=fragment):
                self.assertNotIn(fragment, combined)

        server_source = (ROOT / "google_ads_server.py").read_text(encoding="utf-8")
        self.assertNotIn("response.text", server_source)
        self.assertIsNone(re.search(r"logger\.[a-z]+\(f[\"']", server_source))


if __name__ == "__main__":
    unittest.main()
