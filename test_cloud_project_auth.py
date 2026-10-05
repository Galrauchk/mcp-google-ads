"""Régressions hors réseau pour l'accès Ads porté par le projet Cloud."""
import os
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import google_ads_server as server


class CloudProjectAuthTests(unittest.TestCase):
    def test_oauth_without_developer_token(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(server, 'GOOGLE_ADS_LOGIN_CUSTOMER_ID', ''):
            headers = server.get_headers(SimpleNamespace(valid=True, token='test-only'))
        self.assertEqual(headers, {'Authorization': 'Bearer test-only', 'content-type': 'application/json'})

    def test_legacy_secret_is_not_transmitted(self):
        with patch.dict(os.environ, {'GOOGLE_ADS_DEVELOPER_TOKEN': 'legacy-test-only'}), patch.object(server, 'GOOGLE_ADS_LOGIN_CUSTOMER_ID', '123-456-7890'):
            headers = server.get_headers(SimpleNamespace(valid=True, token='test-only'))
        self.assertNotIn('developer-token', headers)
        self.assertEqual(headers['login-customer-id'], '1234567890')

    def test_service_account_refresh_is_preserved(self):
        creds = Mock(spec=server.service_account.Credentials)
        creds.token = 'test-only'
        with patch.object(server, 'GOOGLE_ADS_LOGIN_CUSTOMER_ID', ''):
            headers = server.get_headers(creds)
        creds.refresh.assert_called_once()
        self.assertNotIn('developer-token', headers)
        self.assertEqual(headers['Authorization'], 'Bearer test-only')


if __name__ == '__main__':
    unittest.main()
