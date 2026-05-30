"""
app_integration.py -- v2 per-app management with SimpleAuth.

In SimpleAuth v2 an *app* is an OAuth client (``app_id`` + ``app_secret``) that
self-manages its own authorization: its roles, permissions, and which directory
users / AD groups are assigned to it. Tokens are scoped to the app via the
``aud`` claim, so a token minted for app A is rejected by app B.

A developer's whole integration is:

  1. Get ``app_id`` / ``app_secret`` from the SimpleAuth admin.
  2. Declare the app's roles + assignments on deploy with ``app_bootstrap``
     (idempotent -- safe to run on every startup).
  3. Point the SDK at SimpleAuth with ``audience`` set to the app, then
     ``verify()`` incoming tokens -- foreign-app tokens are rejected because
     their ``aud`` won't match.

This example does (1)-(3): it bootstraps roles + a group assignment on startup
and then verifies a token, reading the per-app roles it carries.

Authentication to ``/api/app/*`` uses HTTP Basic ``app_id:app_secret`` under the
hood; the ``app_id`` is derived from the credential, so this app can only ever
touch its own scope.

Prerequisites:
  pip install simpleauth

Configuration (all via environment variables -- no secrets in code):
  SIMPLEAUTH_URL          Server base URL, INCLUDING the base path
                          (e.g. https://auth.example.com/sauth).
  SIMPLEAUTH_APP_ID       This app's id (OAuth client id).
  SIMPLEAUTH_APP_SECRET   This app's secret (from your secret store).
  SIMPLEAUTH_AUDIENCE     Optional. The audience verify() must find in a
                          token's `aud`. Defaults to SIMPLEAUTH_APP_ID, which
                          is the right value for most deployments.
  SIMPLEAUTH_GROUP        Optional. A directory group (sAMAccountName by
                          default) to assign the "admin" role to. Defaults to
                          "Finance".
  SIMPLEAUTH_TOKEN        Optional. An access token to verify at the end of the
                          demo. If unset, the verify step is skipped.
  SIMPLEAUTH_INSECURE     Set to "true" to disable TLS verification
                          (development only; defaults to verifying).

Usage:
  export SIMPLEAUTH_URL=https://auth.example.com/sauth
  export SIMPLEAUTH_APP_ID=billing
  export SIMPLEAUTH_APP_SECRET=...        # from your secret store
  python app_integration.py
"""

import os
import sys

from simpleauth.client import (
    SimpleAuth,
    AppError,
    TokenVerificationError,
)


# ---------------------------------------------------------------------------
# Configuration -- read everything from the environment
# ---------------------------------------------------------------------------

# Server URL must include the base path (the stock server mounts at /sauth).
SIMPLEAUTH_URL = os.environ.get("SIMPLEAUTH_URL", "https://auth.example.com/sauth")

# The app credential. Never hardcode these.
APP_ID = os.environ.get("SIMPLEAUTH_APP_ID")
APP_SECRET = os.environ.get("SIMPLEAUTH_APP_SECRET")

# The audience verify() requires. Defaults to the app id, which is what the
# server stamps into `aud` for this app in most deployments.
AUDIENCE = os.environ.get("SIMPLEAUTH_AUDIENCE") or APP_ID

# A directory group to grant the "admin" role to (sAMAccountName by default).
GROUP = os.environ.get("SIMPLEAUTH_GROUP", "Finance")

# Optionally verify a real token at the end of the run.
TOKEN = os.environ.get("SIMPLEAUTH_TOKEN")

# TLS verification stays ON by default. Only set SIMPLEAUTH_INSECURE=true for
# local development against a self-signed certificate.
VERIFY_SSL = os.environ.get("SIMPLEAUTH_INSECURE") != "true"


def _require_app_credentials() -> None:
    """Exit with a clear message if the app credentials are not set."""
    missing = []
    if not APP_ID:
        missing.append("SIMPLEAUTH_APP_ID")
    if not APP_SECRET:
        missing.append("SIMPLEAUTH_APP_SECRET")
    if missing:
        print(
            "Error: missing required environment variable(s): "
            + ", ".join(missing)
            + "\nSet this app's credentials and try again, e.g.:\n"
            "  export SIMPLEAUTH_APP_ID=billing\n"
            "  export SIMPLEAUTH_APP_SECRET=...   # from your secret store"
        )
        sys.exit(1)


def main() -> None:
    _require_app_credentials()

    # Construct the client as an *app*: app_id/app_secret authenticate the
    # /api/app/* calls, and audience makes verify() reject other apps' tokens.
    auth = SimpleAuth(
        url=SIMPLEAUTH_URL,
        app_id=APP_ID,
        app_secret=APP_SECRET,
        audience=AUDIENCE,
        verify_ssl=VERIFY_SSL,
    )

    # ------------------------------------------------------------------
    # Step 1: Bootstrap this app's authorization on startup (idempotent)
    # ------------------------------------------------------------------
    # Declare the roles this app understands, what each role can do, and who is
    # assigned. This is safe to run on every deploy -- it upserts.
    print(f"Bootstrapping app '{APP_ID}' authorization...")
    try:
        auth.app_bootstrap(
            roles=["admin", "viewer"],
            role_permissions={
                "admin": ["invoice:write", "invoice:read"],
                "viewer": ["invoice:read"],
            },
            assignments=[
                # Grant everyone in the directory group the "admin" role.
                {"group": GROUP, "roles": ["admin"]},
                # And assign one named user the "viewer" role.
                {"user": "jsmith", "roles": ["viewer"]},
            ],
        )
        print("  Bootstrap complete.")
    except AppError as exc:
        print(f"  Bootstrap failed: {exc}")
        print(f"  HTTP status: {exc.status_code}")
        print(f"  Detail:      {exc.detail}")
        sys.exit(1)

    # Read the app's authorization back to confirm what the server now stores.
    try:
        authz = auth.get_app_authz()
        print(f"  Roles:             {authz.roles}")
        print(f"  Role permissions:  {authz.role_permissions}")
        print(f"  User assignments:  {authz.user_assignments}")
        print(f"  Group assignments: {authz.group_assignments}")
    except AppError as exc:
        print(f"  Could not read authz: {exc}")

    # The app's own settings (no secret) -- e.g. require_assignment.
    try:
        settings = auth.app_settings()
        print(f"  Settings:          {settings}")
    except AppError as exc:
        print(f"  Could not read settings: {exc}")

    # ------------------------------------------------------------------
    # Step 2: Verify an incoming token and read its per-app roles
    # ------------------------------------------------------------------
    # In a real service this token arrives on each request (Authorization:
    # Bearer ...). Because the client was built with `audience`, verify()
    # rejects any token whose `aud` is a different app.
    if not TOKEN:
        print(
            "\nSet SIMPLEAUTH_TOKEN to a token issued for this app to see "
            "verify() read its per-app roles."
        )
        return

    print("\nVerifying an incoming access token...")
    try:
        user = auth.verify(TOKEN)
    except TokenVerificationError as exc:
        # This is what a foreign-app token (wrong `aud`) looks like, too.
        print(f"  Token rejected: {exc}")
        sys.exit(1)

    print("  Token verified.")
    print(f"  Subject (GUID): {user.sub}")
    print(f"  Username:       {user.preferred_username}")
    # roles/permissions here are this app's, resolved per app at issuance.
    print(f"  App roles:      {user.roles}")
    print(f"  App perms:      {user.permissions}")

    if user.has_role("admin"):
        print("  -> user is an admin in this app")
    elif user.has_role("viewer"):
        print("  -> user is a viewer in this app")
    else:
        print("  -> user has no role in this app")


if __name__ == "__main__":
    main()
