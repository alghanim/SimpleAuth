"""
service_client.py -- Service-to-service authentication with SimpleAuth.

Demonstrates:
  - Service-account login (machine-to-machine using a dedicated user)
  - Requests session with automatic Bearer token injection
  - Auto-refresh: re-login transparently when the token is about to expire
  - Making authenticated calls to another internal service

SimpleAuth's recommended machine-to-machine pattern is a dedicated service
*user* that logs in with a username and password, rather than the OAuth2
client-credentials grant (which is confidential, disabled by default, and not
exposed by the other-language SDKs). This example standardizes on login.

Prerequisites:
  pip install simpleauth requests

Configuration (all via environment variables -- no secrets in code):
  SIMPLEAUTH_URL              Server base URL, INCLUDING the base path
                              (e.g. https://auth.example.com/sauth).
  SIMPLEAUTH_SERVICE_USER     Username of the dedicated service account.
  SIMPLEAUTH_SERVICE_PASSWORD Password of the dedicated service account.
  SIMPLEAUTH_INSECURE         Set to "true" to disable TLS verification
                              (development only; defaults to verifying).
  SIMPLEAUTH_ADMIN_KEY        Optional admin key, only needed for the admin
                              API demo at the end.

Usage:
  export SIMPLEAUTH_SERVICE_USER=inventory-service
  export SIMPLEAUTH_SERVICE_PASSWORD=...   # from your secret store
  python service_client.py
"""

import os
import sys
import time
import threading

import requests

from simpleauth.client import SimpleAuth, AuthenticationError, TokenResponse


# ---------------------------------------------------------------------------
# Configuration -- read everything from the environment
# ---------------------------------------------------------------------------

# Server URL must include the base path (the stock server mounts at /sauth).
SIMPLEAUTH_URL = os.environ.get("SIMPLEAUTH_URL", "https://auth.example.com/sauth")

# Credentials for the dedicated service account. Never hardcode these.
SERVICE_USER = os.environ.get("SIMPLEAUTH_SERVICE_USER")
SERVICE_PASSWORD = os.environ.get("SIMPLEAUTH_SERVICE_PASSWORD")

# TLS verification stays ON by default. Only set SIMPLEAUTH_INSECURE=true for
# local development against a self-signed certificate.
VERIFY_SSL = os.environ.get("SIMPLEAUTH_INSECURE") != "true"

# The downstream API this service needs to call
ORDERS_API_BASE = "https://api.internal.example.com/orders"


def _require_credentials() -> None:
    """Exit with a clear message if the service credentials are not set."""
    missing = []
    if not SERVICE_USER:
        missing.append("SIMPLEAUTH_SERVICE_USER")
    if not SERVICE_PASSWORD:
        missing.append("SIMPLEAUTH_SERVICE_PASSWORD")
    if missing:
        print(
            "Error: missing required environment variable(s): "
            + ", ".join(missing)
            + "\nSet the service account credentials and try again, e.g.:\n"
            "  export SIMPLEAUTH_SERVICE_USER=inventory-service\n"
            "  export SIMPLEAUTH_SERVICE_PASSWORD=...   # from your secret store"
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# ServiceAuthSession -- requests.Session with auto-refreshing Bearer token
# ---------------------------------------------------------------------------

class ServiceAuthSession(requests.Session):
    """A requests.Session that logs in as a service account and keeps a fresh
    Bearer token.

    The token is obtained via ``SimpleAuth.login`` (service-account login) and
    cached. When it nears expiry the session logs in again automatically.

    Usage:
        session = ServiceAuthSession(
            auth_url="https://auth.example.com/sauth",
            service_user="inventory-service",
            service_password=...,   # from your secret store
        )

        # Tokens are fetched and refreshed automatically
        resp = session.get("https://api.internal/orders")
    """

    # Re-login this many seconds before the token actually expires
    REFRESH_MARGIN_SECONDS = 60

    def __init__(
        self,
        auth_url: str,
        service_user: str,
        service_password: str,
        verify_ssl: bool = True,
    ):
        super().__init__()

        self._auth_client = SimpleAuth(
            url=auth_url,
            verify_ssl=verify_ssl,
        )
        self._service_user = service_user
        self._service_password = service_password

        self._token: str | None = None
        self._expires_at: float = 0.0
        self._lock = threading.Lock()

    def _ensure_token(self) -> str:
        """Obtain or refresh the access token (thread-safe)."""
        with self._lock:
            if self._token and time.time() < self._expires_at:
                return self._token

            tokens: TokenResponse = self._auth_client.login(
                self._service_user, self._service_password
            )
            self._token = tokens.access_token
            self._expires_at = time.time() + tokens.expires_in - self.REFRESH_MARGIN_SECONDS

            return self._token

    def request(self, method, url, **kwargs):
        """Override to inject the Bearer token into every request."""
        token = self._ensure_token()

        headers = kwargs.pop("headers", {}) or {}
        headers["Authorization"] = f"Bearer {token}"
        kwargs["headers"] = headers

        return super().request(method, url, **kwargs)


# ---------------------------------------------------------------------------
# Example usage
# ---------------------------------------------------------------------------

def main() -> None:
    _require_credentials()

    # ------------------------------------------------------------------
    # Option 1: Quick one-off service-account login
    # ------------------------------------------------------------------
    auth = SimpleAuth(
        url=SIMPLEAUTH_URL,
        verify_ssl=VERIFY_SSL,
    )

    print("Obtaining service token via service-account login...")
    try:
        tokens = auth.login(SERVICE_USER, SERVICE_PASSWORD)
    except AuthenticationError as exc:
        print(f"Failed to obtain service token: {exc}")
        return

    # Never print the full token -- truncate it.
    print(f"  Access token: {tokens.access_token[:12]}...")
    print(f"  Expires in:   {tokens.expires_in} seconds")
    print(f"  Scope:        {tokens.scope}")

    # Verify our own token to see its claims
    user = auth.verify(tokens.access_token)
    print(f"  Service sub:  {user.sub}")
    print(f"  Roles:        {user.roles}")

    # ------------------------------------------------------------------
    # Option 2: Long-lived session with auto-refresh (recommended)
    # ------------------------------------------------------------------
    print("\nCreating auto-refreshing service session...")
    session = ServiceAuthSession(
        auth_url=SIMPLEAUTH_URL,
        service_user=SERVICE_USER,
        service_password=SERVICE_PASSWORD,
        verify_ssl=VERIFY_SSL,
    )

    # Every request through this session automatically includes a valid
    # Bearer token. The session logs in again transparently when the token
    # nears expiration.

    # Example: call the orders API
    print(f"Calling {ORDERS_API_BASE}...")
    try:
        resp = session.get(f"{ORDERS_API_BASE}", timeout=10)
        resp.raise_for_status()
        print(f"  Status: {resp.status_code}")
        print(f"  Body:   {resp.json()}")
    except requests.RequestException as exc:
        print(f"  Request failed (expected if server is not running): {exc}")

    # Example: create an order
    print(f"\nPOSTing to {ORDERS_API_BASE}...")
    try:
        resp = session.post(
            ORDERS_API_BASE,
            json={"item": "Widget", "quantity": 10},
            timeout=10,
        )
        print(f"  Status: {resp.status_code}")
    except requests.RequestException as exc:
        print(f"  Request failed (expected if server is not running): {exc}")

    # ------------------------------------------------------------------
    # Option 3: Using admin APIs to manage user roles
    # ------------------------------------------------------------------
    admin_key = os.environ.get("SIMPLEAUTH_ADMIN_KEY")
    if not admin_key:
        print("\nSkipping admin API demo (set SIMPLEAUTH_ADMIN_KEY to enable).")
        return

    print("\nManaging user roles via admin API...")
    admin = SimpleAuth(
        url=SIMPLEAUTH_URL,
        admin_key=admin_key,
        verify_ssl=VERIFY_SSL,
    )
    user_guid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

    try:
        roles = admin.get_user_roles(user_guid)
        print(f"  Current roles for {user_guid}: {roles}")

        admin.set_user_roles(user_guid, ["viewer", "analyst"])
        print("  Updated roles to: ['viewer', 'analyst']")

        permissions = admin.get_user_permissions(user_guid)
        print(f"  Current permissions: {permissions}")

        admin.set_user_permissions(user_guid, ["reports:read", "data:export"])
        print("  Updated permissions to: ['reports:read', 'data:export']")

    except Exception as exc:
        print(f"  Admin API call failed (expected if server is not running): {exc}")


if __name__ == "__main__":
    main()
