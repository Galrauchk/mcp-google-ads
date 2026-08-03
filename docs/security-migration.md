# Google Ads security migration

## API version

The MCP targets Google Ads API `v25`. Google released `v25` on 22 July 2026 and lists its
sunset for August 2027. Google recommends upgrading integrations to the newest major version.

Official references:

- https://developers.google.com/google-ads/api/docs/sunset-dates
- https://developers.google.com/google-ads/api/docs/release-notes
- https://developers.google.com/google-ads/api/docs/upgrade
- https://developers.google.com/google-ads/api/rest/common/search

The server uses the documented REST endpoints:

- `GET /v25/customers:listAccessibleCustomers`
- `POST /v25/customers/{customer_id}/googleAds:search`

The current queries do not use the fields or resources removed between `v24.2` and `v25`.

## Credential file separation

OAuth client configuration and authorized-user tokens now have separate paths:

```text
GOOGLE_ADS_OAUTH_CLIENT_PATH=/absolute/path/outside/repository/oauth-client.json
GOOGLE_ADS_OAUTH_TOKEN_PATH=/absolute/path/outside/repository/google-ads-token.json
```

The client configuration is read-only. Refreshed credentials are written atomically to the token
path with permissions `0600`. The process refuses a configuration where both paths are identical.

For service accounts, use:

```text
GOOGLE_ADS_AUTH_TYPE=service_account
GOOGLE_ADS_SERVICE_ACCOUNT_PATH=/absolute/path/outside/repository/service-account.json
```

`GOOGLE_ADS_CREDENTIALS_PATH` remains supported only as a migration bridge. When it points to an
OAuth client configuration, the token is written to a distinct sibling file. New installations
should not use the legacy variable.

## Interactive OAuth

Normal MCP execution never opens a browser. A supervised initial authorization requires the
explicit temporary setting:

```text
GOOGLE_ADS_ALLOW_INTERACTIVE_OAUTH=1
```

Restore it to `0` immediately after the token file has been created. Never place developer tokens,
client secrets, authorized-user tokens, backups, or one-off reauthorization scripts in Git.

## Safe validation

The repository tests are hermetic. They use placeholder credentials, mock every HTTP call and
verify that logs and public errors do not expose secret values:

```bash
python -m unittest discover -v
```

This command does not contact Google and does not start an OAuth flow.
