from __future__ import annotations
"""
CLI OAuth 2.1 + PKCE authentication.
Two paths:
  - System browser + localhost callback (interactive)
  - Device code flow (headless/CI: kswitch login --device-code)

Dependencies: stdlib + requests + keyring (no heavy deps).
"""
import base64
import hashlib
import http.server
import json
import os
import secrets
import threading
import time
import webbrowser
from pathlib import Path
from urllib.parse import parse_qs, urlparse, urlencode

import requests

try:
    import keyring
    import keyring.errors
except ImportError:
    keyring = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

KEYCLOAK_BASE = os.environ.get(
    "KSWITCH_IDP_URL", "https://keycloak.internal/realms/kswitch"
)
CLIENT_ID = "kswitch-cli"
REDIRECT_URI = "http://localhost:9999/callback"  # default; overridden at runtime
SCOPES = "openid kswitch:read"

# ---------------------------------------------------------------------------
# PKCE generation (RFC 7636, S256)
# ---------------------------------------------------------------------------


def generate_pkce_pair() -> tuple[str, str]:
    """Generate code_verifier (>=43 chars) and code_challenge (S256).

    Returns:
        (code_verifier, code_challenge) tuple.
    """
    verifier = secrets.token_urlsafe(64)  # 86 URL-safe chars, well above 43 min
    assert len(verifier) >= 43, "code_verifier must be >= 43 characters (RFC 7636)"
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    return verifier, challenge


# ---------------------------------------------------------------------------
# Device fingerprint (WEAK binding -- see docstring)
# ---------------------------------------------------------------------------


def generate_device_id(user_agent: str, client_ip: str = "127.0.0.1") -> str:
    """
    Lightweight device fingerprint: SHA256(user_agent + client_ip).

    BINDING STRENGTH: WEAK -- treat as a soft contextual signal, not a
    cryptographic assurance mechanism. This fingerprint will drift under:
      - NAT or proxy IP changes
      - user-agent string changes (browser updates, terminal relay tools)
      - VPN reconnect to a different egress IP
      - mobile network handoff

    It is NOT a substitute for strong binding mechanisms. The real hard
    controls that provide session security in this model are:
      1. Refresh token family model (rotation + replay detection)
      2. Redis session store (session_id lifecycle + revocation)
      3. ACR / auth_time checks (step-up assurance at the gateway)
      4. Scope ceiling enforcement (gateway-independent of IdP)

    device_id is used as a secondary trip-wire: if it changes mid-session,
    the gateway challenges the user to re-authenticate rather than silently
    accepting the request. It does not prevent a determined attacker who
    controls the user's network environment.

    Future strong binding options: mTLS client certificate (DPoP is
    defined in RFC 9449 -- adds client key material to token binding, works
    in all flows including device code). Evaluate for v1.28.
    """
    raw = f"{user_agent}:{client_ip}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Token storage (OS keychain primary, file fallback)
# ---------------------------------------------------------------------------

_TOKEN_DIR = Path.home() / ".kswitch"
_TOKEN_FILE = _TOKEN_DIR / "tokens"


def store_tokens(tokens: dict, device_id: str) -> None:
    """Store tokens in OS keychain (primary) or ~/.kswitch/tokens (fallback)."""
    access_token = tokens.get("access_token", "")
    refresh_token = tokens.get("refresh_token", "")

    if keyring is not None:
        try:
            keyring.set_password("kswitch", f"access_token:{device_id}", access_token)
            keyring.set_password("kswitch", f"refresh_token:{device_id}", refresh_token)
            return
        except Exception:
            pass  # fall through to file storage

    _store_tokens_file(tokens, device_id)


def _store_tokens_file(tokens: dict, device_id: str) -> None:
    """Fallback: store in ~/.kswitch/tokens (chmod 600)."""
    _TOKEN_DIR.mkdir(parents=True, exist_ok=True)
    with open(_TOKEN_FILE, "w") as f:
        json.dump({"tokens": tokens, "device_id": device_id}, f)
    os.chmod(_TOKEN_FILE, 0o600)


def load_tokens(device_id: str) -> dict | None:
    """Load tokens from OS keychain or file fallback.

    Returns:
        Token dict with access_token/refresh_token, or None if not found.
    """
    if keyring is not None:
        try:
            access_token = keyring.get_password("kswitch", f"access_token:{device_id}")
            refresh_token = keyring.get_password("kswitch", f"refresh_token:{device_id}")
            if access_token:
                return {
                    "access_token": access_token,
                    "refresh_token": refresh_token or "",
                }
        except Exception:
            pass  # fall through to file

    return _load_tokens_file(device_id)


def _load_tokens_file(device_id: str) -> dict | None:
    """Load tokens from ~/.kswitch/tokens file."""
    if not _TOKEN_FILE.exists():
        return None
    try:
        with open(_TOKEN_FILE) as f:
            data = json.load(f)
        if data.get("device_id") == device_id:
            return data.get("tokens")
    except (json.JSONDecodeError, KeyError):
        pass
    return None


def clear_tokens(device_id: str) -> None:
    """Remove stored tokens from keychain and file."""
    if keyring is not None:
        try:
            keyring.delete_password("kswitch", f"access_token:{device_id}")
        except Exception:
            pass
        try:
            keyring.delete_password("kswitch", f"refresh_token:{device_id}")
        except Exception:
            pass

    if _TOKEN_FILE.exists():
        _TOKEN_FILE.unlink()


# ---------------------------------------------------------------------------
# Auth flows
# ---------------------------------------------------------------------------


def login_browser(
    scope: str = SCOPES,
    device_code: bool = False,
    extra_auth_params: dict | None = None,
) -> dict:
    """Full PKCE login flow.

    Args:
        scope: OAuth scopes to request. Must not be empty.
        device_code: If True, use RFC 8628 device code flow instead of browser.
        extra_auth_params: Additional parameters for the authorization request
            (e.g. acr_values, max_age for step-up authentication).

    Returns:
        Token response dict with access_token, refresh_token, etc.

    Raises:
        ValueError: If scope is empty/blank.
        RuntimeError: On authentication failure or timeout.
    """
    if not scope or not scope.strip():
        raise ValueError("scope must not be empty")

    if device_code:
        return _device_code_flow(scope)
    return _browser_pkce_flow(scope, extra_auth_params=extra_auth_params)


def _browser_pkce_flow(scope: str, extra_auth_params: dict | None = None) -> dict:
    """Launch system browser to ephemeral localhost callback, exchange auth code."""
    code_verifier, code_challenge = generate_pkce_pair()
    auth_code_holder: dict[str, str] = {}
    callback_received = threading.Event()

    class CallbackHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            params = parse_qs(urlparse(self.path).query)
            if "code" in params:
                auth_code_holder["code"] = params["code"][0]
            elif "error" in params:
                auth_code_holder["error"] = params.get(
                    "error_description", ["Unknown error"]
                )[0]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Authentication complete. You can close this tab.")
            callback_received.set()

        def log_message(self, format, *args):
            pass  # suppress access logs

    # Bind to port 0 (ephemeral) to avoid "port already in use" failures.
    # After binding, read the actual port and use it in redirect_uri.
    server = http.server.HTTPServer(("127.0.0.1", 0), CallbackHandler)
    actual_port = server.server_address[1]
    redirect_uri = f"http://localhost:{actual_port}/callback"

    threading.Thread(target=server.handle_request, daemon=True).start()

    state = secrets.token_urlsafe(16)
    auth_params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    if extra_auth_params:
        auth_params.update(extra_auth_params)
    auth_url = (
        f"{KEYCLOAK_BASE}/protocol/openid-connect/auth?{urlencode(auth_params)}"
    )
    webbrowser.open(auth_url)
    print(f"Opening browser... if it doesn't open, visit:\n{auth_url}")

    callback_received.wait(timeout=300)
    server.server_close()

    if "error" in auth_code_holder:
        raise RuntimeError(f"Authentication failed: {auth_code_holder['error']}")
    if "code" not in auth_code_holder:
        raise RuntimeError("Authentication timed out -- no code received")

    # Exchange authorization code for tokens
    token_response = requests.post(
        f"{KEYCLOAK_BASE}/protocol/openid-connect/token",
        data={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": auth_code_holder["code"],
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        },
    )
    token_response.raise_for_status()
    return token_response.json()


def _device_code_flow(scope: str) -> dict:
    """RFC 8628 device authorization grant for headless/CI environments."""
    init = requests.post(
        f"{KEYCLOAK_BASE}/protocol/openid-connect/auth/device",
        data={"client_id": CLIENT_ID, "scope": scope},
    )
    init.raise_for_status()
    data = init.json()
    print(f"\nGo to: {data['verification_uri_complete']}")
    print(
        f"Or visit {data['verification_uri']} and enter code: {data['user_code']}"
    )
    print(f"Expires in {data['expires_in']}s\n")

    interval = data.get("interval", 5)
    deadline = time.time() + data["expires_in"]
    while time.time() < deadline:
        time.sleep(interval)
        poll = requests.post(
            f"{KEYCLOAK_BASE}/protocol/openid-connect/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": CLIENT_ID,
                "device_code": data["device_code"],
            },
        )
        if poll.status_code == 200:
            return poll.json()
        error = poll.json().get("error", "")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval += 5
            continue
        raise RuntimeError(f"Device code flow failed: {error}")
    raise RuntimeError("Device code flow timed out")
