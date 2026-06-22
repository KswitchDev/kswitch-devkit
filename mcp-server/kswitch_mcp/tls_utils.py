"""Shared TLS verification helper for KSwitch MCP proxy and CLI tools."""
from __future__ import annotations

import os


def resolve_tls_verify(verify_ssl: bool | str = True) -> bool | str:
    """Resolve the TLS verification setting for control-plane HTTP calls.

    Resolution order:
    1. An explicit CA path string is returned as-is.
    2. ``False`` disables verification (dev bypass only — never in production).
    3. ``KSWITCH_CA_FILE`` env var — enterprise / internal CA bundle path.
    4. Common mkcert roots for local development.
    5. Fall back to ``True`` (system bundle).
    """
    if isinstance(verify_ssl, str):
        return verify_ssl
    if not verify_ssl:
        return False

    ca_file = os.environ.get("KSWITCH_CA_FILE", "")
    if ca_file and os.path.exists(os.path.expanduser(ca_file)):
        return os.path.expanduser(ca_file)

    for ca in [
        os.path.expanduser("~/.mkcert-ca.pem"),
        os.path.expanduser("~/Library/Application Support/mkcert/rootCA.pem"),
        "/etc/ssl/certs/mkcert-ca.pem",
    ]:
        if os.path.exists(ca):
            return ca

    return True
