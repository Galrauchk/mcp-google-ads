import unittest
from unittest.mock import patch

import google_ads_server as server


class FakeCredentials:
    valid = True
    expired = False
    refresh_token = "unused"
    token = "access-value"


class FakeResponse:
    def __init__(self, status_code, payload=None, text="", headers=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text
        self.headers = headers or {}

    def json(self):
        return self._payload


class FormatCustomerIdTests(unittest.TestCase):
    def test_supported_customer_id_formats(self):
        cases = [
            ("9873186703", "9873186703"),
            ("987-318-6703", "9873186703"),
            ('"9873186703"', "9873186703"),
            ("{9873186703}", "9873186703"),
            ("12345", "0000012345"),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(server.format_customer_id(raw), expected)


class GoogleAdsToolTests(unittest.IsolatedAsyncioTestCase):
    async def test_list_accounts_uses_v25_without_real_network(self):
        response = FakeResponse(
            200,
            {"resourceNames": ["customers/1234567890"]},
        )
        with (
            patch.object(server, "get_credentials", return_value=FakeCredentials()),
            patch.object(
                server,
                "get_headers",
                return_value={"Authorization": "Bearer access-value", "developer-token": "developer-value"},
            ),
            patch.object(server.requests, "get", return_value=response) as request,
        ):
            result = await server.list_accounts()

        called_url = request.call_args.args[0]
        self.assertEqual(called_url, "https://googleads.googleapis.com/v25/customers:listAccessibleCustomers")
        self.assertIn("1234567890", result)

    async def test_provider_error_body_cannot_echo_credentials(self):
        response = FakeResponse(
            401,
            text="developer-token=developer-value Authorization: Bearer access-value",
            headers={"request-id": "safe_request_123"},
        )
        with (
            patch.object(server, "get_credentials", return_value=FakeCredentials()),
            patch.object(server, "get_headers", return_value={"Authorization": "Bearer access-value"}),
            patch.object(server.requests, "post", return_value=response),
        ):
            result = await server.execute_gaql_query(
                "1234567890", "SELECT campaign.id FROM campaign LIMIT 1"
            )

        self.assertIn("HTTP 401", result)
        self.assertIn("safe_request_123", result)
        self.assertNotIn("developer-value", result)
        self.assertNotIn("access-value", result)

    def test_invalid_request_id_is_not_exposed(self):
        response = FakeResponse(500, headers={"request-id": "unsafe\nBearer access-value"})
        result = server.google_ads_http_error("Request failed", response)
        self.assertEqual(result, "Request failed: Google Ads API returned HTTP 500")

    def test_non_string_request_id_is_not_exposed(self):
        response = FakeResponse(500, headers={"request-id": object()})
        result = server.google_ads_http_error("Request failed", response)
        self.assertEqual(result, "Request failed: Google Ads API returned HTTP 500")


if __name__ == "__main__":
    unittest.main()
