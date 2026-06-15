# KSwitch CLI — Developer Edition

The KSwitch developer-workstation CLI auth helper. Implements
OAuth 2.1 + PKCE (browser + device-code flow) so a developer can
acquire a KSwitch session token from a workstation without copying
secrets out of the Keycloak console.

Source: `kswitch_platform/cli/auth/` in the platform repo. Pinned to the
Developer Edition image release tag and refreshed alongside the platform images.

## Files

| File | Purpose |
|---|---|
| `pkce.py` | OAuth 2.1 PKCE client (S256 challenge). Browser flow + device-code flow. |
| `__init__.py` | Package init — `from cli.auth import pkce`. |

## Usage

```bash
# From the workstation (NOT inside the bundle's docker network)
python3 -m cli.pkce \
    --issuer https://localhost:3001/realms/kswitch \
    --client-id kswitch-ui \
    --redirect-uri http://127.0.0.1:8765/callback
```

The CLI opens a browser, completes the auth code + PKCE exchange,
and prints the access token to stdout. The developer then uses that
token with any of the bundled SDKs (`pip install ./sdks/python/`).

## Pre-flight

- Python 3.10+ on the workstation.
- A network path from the workstation to the bundle host (TLS via the
  bundle's self-signed cert, or your CA-signed cert if you provided
  one to `make tls`).
- The bundled admin user must have logged in once (so the realm-export
  seed has provisioned the OIDC client).
