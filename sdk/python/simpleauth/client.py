"""SimpleAuth client.

The :class:`SimpleAuth` client handles credential exchange (login, refresh,
client-credentials), the OIDC userinfo endpoint, admin role/permission
management, v2 **per-app self-management** (``/api/app/*``, authenticated with
the app credential), and — most importantly — **offline** RS256 JWT
verification against the server's JWKS.

No JWT library is used. Tokens are parsed manually (base64url-decode the header
and payload) and RS256 signatures are verified directly with ``cryptography``.

Verification policy (see :meth:`SimpleAuth.verify`):

* The algorithm is pinned to ``RS256``. ``alg=none`` and every non-RS256
  algorithm are rejected, preventing algorithm-confusion attacks.
* ``exp`` is **always** enforced. A missing or malformed ``exp`` claim is
  treated as invalid (fail closed).
* Issuer validation is opt-in via ``expected_issuer`` (default ``None`` = do
  not check). This is required for usability: the SimpleAuth server signs
  direct login/refresh tokens with issuer ``"simpleauth"`` but signs OIDC /
  client-credentials tokens with a URL issuer, so a hardcoded issuer would
  reject one or the other. Strict deployments can pin the value they expect.
* Audience validation is opt-in via ``audience`` (default ``None`` = skip).
* Token contents are never logged.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Dict, List, Mapping, Optional

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from .errors import (
    AdminError,
    AppError,
    AuthenticationError,
    SimpleAuthError,
    TokenVerificationError,
)
from .jwks import JWKSCache
from .models import AppAuthz, TokenResponse, User, UserInfo

__all__ = [
    "SimpleAuth",
    "TokenResponse",
    "User",
    "UserInfo",
    "AppAuthz",
    "SimpleAuthError",
    "AuthenticationError",
    "TokenVerificationError",
    "AdminError",
    "AppError",
]

#: Default issuer the SimpleAuth server uses for direct login/refresh tokens.
DEFAULT_REALM = "simpleauth"


def _b64url_decode(segment: str) -> bytes:
    """Decode a base64url (unpadded) JWT segment to bytes."""
    padding_len = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding_len)


class SimpleAuth:
    """Client for a SimpleAuth authentication server.

    Args:
        url: Base URL of the server, **including** the base path (for the stock
            server this is ``/sauth``, e.g. ``https://auth.example.com/sauth``).
            A trailing slash is stripped.
        admin_key: Admin API key. Required only for admin operations; sent as a
            Bearer token to the admin API.
        verify_ssl: Whether to verify TLS certificates. Defaults to ``True``;
            set ``False`` for development with self-signed certificates.
        client_id: OAuth2 client id, used by the client-credentials grant.
        client_secret: OAuth2 client secret, used by the client-credentials
            grant.
        app_id: v2 app id (an OAuth client id). Required only for the app
            self-management helpers (``app_bootstrap``, ``get_app_authz``, …),
            which authenticate to ``/api/app/*`` with HTTP Basic
            ``app_id:app_secret``. Also commonly used as the ``audience`` so
            ``verify`` rejects other apps' tokens.
        app_secret: v2 app secret, paired with ``app_id`` for the app
            self-management helpers. Never sent except as the Basic-auth
            password to this server.
        realm: The server realm/issuer name, used to build the OIDC token
            endpoint for the client-credentials grant. Defaults to
            ``"simpleauth"``.
        expected_issuer: If set, :meth:`verify` requires the token ``iss`` claim
            to equal this value. Defaults to ``None`` (issuer not checked).
        audience: If set, :meth:`verify` requires the token ``aud`` claim to
            contain this value. Defaults to ``None`` (audience not checked).
        timeout: Per-request HTTP timeout in seconds.
        jwks_ttl: JWKS cache lifetime in seconds (default one hour).
        leeway: Clock-skew allowance in seconds applied to ``exp`` checks.
    """

    def __init__(
        self,
        url: str,
        *,
        admin_key: Optional[str] = None,
        verify_ssl: bool = True,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        app_id: Optional[str] = None,
        app_secret: Optional[str] = None,
        realm: str = DEFAULT_REALM,
        expected_issuer: Optional[str] = None,
        audience: Optional[str] = None,
        timeout: float = 30.0,
        jwks_ttl: float = 3600.0,
        leeway: float = 0.0,
    ) -> None:
        if not url:
            raise ValueError("url is required")

        self.base_url = url.rstrip("/")
        self.admin_key = admin_key
        self.verify_ssl = verify_ssl
        self.client_id = client_id
        self.client_secret = client_secret
        self.app_id = app_id
        self.app_secret = app_secret
        self.realm = realm
        self.expected_issuer = expected_issuer
        self.audience = audience
        self.timeout = timeout
        self.leeway = leeway

        self._session = requests.Session()
        self._jwks = JWKSCache(
            jwks_url=f"{self.base_url}/.well-known/jwks.json",
            session=self._session,
            ttl=jwks_ttl,
            verify_ssl=verify_ssl,
            timeout=timeout,
        )

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _extract_error(self, resp: requests.Response) -> tuple[str, Optional[str], Optional[str]]:
        """Pull a (message, detail, code) tuple from a JSON error response."""
        message: str = f"request failed with HTTP {resp.status_code}"
        detail: Optional[str] = None
        code: Optional[str] = None
        try:
            body = resp.json()
        except ValueError:
            body = None
        if isinstance(body, Mapping):
            code = body.get("error")
            detail = body.get("error_description") or body.get("detail") or body.get("error")
            message = body.get("error_description") or body.get("error") or message
        return message, detail, code

    def _post_json(self, path: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """POST a JSON body and return the decoded response, raising on error."""
        try:
            resp = self._session.post(
                f"{self.base_url}{path}",
                json=payload,
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise AuthenticationError(f"request to {path} failed: {exc}") from exc

        if resp.status_code != 200:
            message, detail, code = self._extract_error(resp)
            raise AuthenticationError(
                message, status_code=resp.status_code, detail=detail, code=code
            )
        return resp.json()

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def login(self, username: str, password: str) -> TokenResponse:
        """Authenticate with a username and password.

        Sends ``POST {base}/api/auth/login``. The returned
        :class:`~simpleauth.models.TokenResponse` may have
        ``force_password_change`` set, in which case the user must change their
        password before continuing.

        Raises:
            AuthenticationError: If the credentials are rejected or the request
                fails. ``status_code`` and ``detail`` carry server context.
        """
        data = self._post_json(
            "/api/auth/login", {"username": username, "password": password}
        )
        return TokenResponse.from_dict(data)

    def refresh(self, refresh_token: str) -> TokenResponse:
        """Exchange a refresh token for a new token set.

        Sends ``POST {base}/api/auth/refresh``. The server rotates refresh
        tokens, so callers should persist the new ``refresh_token``.

        Raises:
            AuthenticationError: If the refresh token is invalid/expired.
        """
        data = self._post_json("/api/auth/refresh", {"refresh_token": refresh_token})
        return TokenResponse.from_dict(data)

    def client_credentials(self, scope: Optional[str] = None) -> TokenResponse:
        """Obtain a service token via the OAuth2 client-credentials grant.

        Requires ``client_id`` and ``client_secret`` to have been supplied to
        the constructor. Posts a form-encoded request to the OIDC token
        endpoint ``{base}/realms/{realm}/protocol/openid-connect/token``.

        Note: client-credentials tokens carry no refresh token and are signed
        with the server's URL issuer (not ``"simpleauth"``).

        Raises:
            AuthenticationError: If credentials are missing or the grant fails.
        """
        if not self.client_id or not self.client_secret:
            raise AuthenticationError(
                "client_id and client_secret are required for client_credentials"
            )

        form: Dict[str, str] = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        if scope:
            form["scope"] = scope

        url = f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/token"
        try:
            resp = self._session.post(
                url, data=form, verify=self.verify_ssl, timeout=self.timeout
            )
        except requests.RequestException as exc:
            raise AuthenticationError(f"client_credentials request failed: {exc}") from exc

        if resp.status_code != 200:
            message, detail, code = self._extract_error(resp)
            raise AuthenticationError(
                message, status_code=resp.status_code, detail=detail, code=code
            )
        return TokenResponse.from_dict(resp.json())

    # ------------------------------------------------------------------
    # User info
    # ------------------------------------------------------------------

    def userinfo(self, access_token: str) -> UserInfo:
        """Fetch profile data from ``GET {base}/api/auth/userinfo``.

        Requires a valid access token (sent as a Bearer credential). Returns a
        :class:`~simpleauth.models.UserInfo` (a ``dict`` subclass), so callers
        can iterate ``.items()`` or read attributes like ``.sub``.

        Raises:
            SimpleAuthError: If the request fails or the token is rejected.
        """
        try:
            resp = self._session.get(
                f"{self.base_url}/api/auth/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise SimpleAuthError(f"userinfo request failed: {exc}") from exc

        if resp.status_code != 200:
            message, detail, code = self._extract_error(resp)
            raise SimpleAuthError(
                message, status_code=resp.status_code, detail=detail, code=code
            )
        return UserInfo(resp.json())

    # ------------------------------------------------------------------
    # JWT verification (offline, RS256)
    # ------------------------------------------------------------------

    def verify(self, token: str) -> User:
        """Verify an access token offline and return its claims as a :class:`User`.

        The verification policy is described in the module docstring: RS256 is
        pinned, ``exp`` is always enforced (fail closed), and issuer/audience
        checks are applied only when ``expected_issuer`` / ``audience`` were
        configured.

        Raises:
            TokenVerificationError: If the token is malformed, uses a forbidden
                algorithm, is signed by an unknown key, has an invalid
                signature, is expired, lacks a valid ``exp``, or fails an
                enabled issuer/audience check.
        """
        parts = token.split(".")
        if len(parts) != 3:
            raise TokenVerificationError("malformed JWT: expected 3 segments")

        header_segment, payload_segment, signature_segment = parts

        # --- Header: pin algorithm to RS256, require a kid. ---
        try:
            header = json.loads(_b64url_decode(header_segment))
        except (ValueError, json.JSONDecodeError) as exc:
            raise TokenVerificationError("malformed JWT header") from exc

        alg = header.get("alg")
        if alg != "RS256":
            # Reject alg=none and any non-RS256 algorithm (no alg confusion).
            raise TokenVerificationError(
                f"unsupported JWT algorithm: {alg!r} (only RS256 is accepted)",
                status_code=401,
            )

        kid = header.get("kid")
        if not kid:
            raise TokenVerificationError("JWT header is missing 'kid'", status_code=401)

        # --- Signature verification against the JWKS public key. ---
        public_key = self._jwks.get_key(kid)
        try:
            signature = _b64url_decode(signature_segment)
        except ValueError as exc:
            raise TokenVerificationError("malformed JWT signature") from exc

        signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
        try:
            public_key.verify(
                signature,
                signing_input,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except InvalidSignature as exc:
            raise TokenVerificationError("invalid JWT signature", status_code=401) from exc

        # --- Payload / claims. ---
        try:
            claims: Dict[str, Any] = json.loads(_b64url_decode(payload_segment))
        except (ValueError, json.JSONDecodeError) as exc:
            raise TokenVerificationError("malformed JWT payload") from exc

        self._verify_claims(claims)
        return User.from_claims(claims)

    def _verify_claims(self, claims: Mapping[str, Any]) -> None:
        """Validate token type, exp (always), and issuer/audience (when set)."""
        # Reject non-access token classes. The server signs several token
        # classes with the same key, distinguished by claims: access tokens
        # carry no ``family_id`` and either no ``typ`` (direct-login) or
        # ``typ="Bearer"`` (OIDC and client_credentials service tokens); refresh
        # tokens carry a ``family_id``; OIDC ID tokens carry ``typ="ID"``;
        # app-management tokens carry ``typ="app-mgmt"``. Reject refresh/ID/
        # app-mgmt so none can be replayed as a bearer credential, while still
        # accepting both access-token shapes ("" and "Bearer").
        if claims.get("family_id"):
            raise TokenVerificationError(
                "refresh token presented as access token", status_code=401
            )
        typ = claims.get("typ")
        if typ in ("ID", "app-mgmt"):
            raise TokenVerificationError(
                f"token type {typ!r} is not a user access token", status_code=401
            )

        # exp is mandatory and must be a number. Fail closed on missing/bad exp.
        exp = claims.get("exp")
        if not isinstance(exp, (int, float)) or isinstance(exp, bool):
            raise TokenVerificationError(
                "token is missing a valid 'exp' claim", status_code=401
            )
        if time.time() > float(exp) + self.leeway:
            raise TokenVerificationError("token has expired", status_code=401)

        if self.expected_issuer is not None:
            iss = claims.get("iss")
            if iss != self.expected_issuer:
                raise TokenVerificationError(
                    "invalid token issuer", status_code=401
                )

        if self.audience is not None:
            aud = claims.get("aud")
            audiences: List[str]
            if aud is None:
                audiences = []
            elif isinstance(aud, str):
                audiences = [aud]
            elif isinstance(aud, (list, tuple)):
                audiences = [str(a) for a in aud]
            else:
                audiences = []
            if self.audience not in audiences:
                raise TokenVerificationError(
                    "invalid token audience", status_code=401
                )

    # ------------------------------------------------------------------
    # Admin: roles & permissions
    # ------------------------------------------------------------------

    def _admin_request(
        self,
        method: str,
        path: str,
        payload: Optional[Any] = None,
    ) -> Optional[Any]:
        """Issue an admin API request with the admin key as a Bearer token."""
        if not self.admin_key:
            raise AdminError("admin_key is required for admin operations")

        headers = {"Authorization": f"Bearer {self.admin_key}"}
        try:
            resp = self._session.request(
                method,
                f"{self.base_url}{path}",
                json=payload if payload is not None else None,
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise AdminError(f"admin request to {path} failed: {exc}") from exc

        if not (200 <= resp.status_code < 300):
            message, detail, code = self._extract_error(resp)
            raise AdminError(
                message, status_code=resp.status_code, detail=detail, code=code
            )

        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return None

    def get_user_roles(self, guid: str) -> List[str]:
        """Return the roles assigned to the user with the given GUID.

        Sends ``GET {base}/api/admin/users/{guid}/roles``. Requires
        ``admin_key``.
        """
        result = self._admin_request("GET", f"/api/admin/users/{guid}/roles")
        return list(result or [])

    def set_user_roles(self, guid: str, roles: List[str]) -> None:
        """Replace the roles for the user with the given GUID.

        Sends ``PUT {base}/api/admin/users/{guid}/roles``. Requires
        ``admin_key``. Roles must already be defined on the server.
        """
        self._admin_request("PUT", f"/api/admin/users/{guid}/roles", list(roles))

    def get_user_permissions(self, guid: str) -> List[str]:
        """Return the permissions assigned to the user with the given GUID.

        Sends ``GET {base}/api/admin/users/{guid}/permissions``. Requires
        ``admin_key``.
        """
        result = self._admin_request("GET", f"/api/admin/users/{guid}/permissions")
        return list(result or [])

    def set_user_permissions(self, guid: str, permissions: List[str]) -> None:
        """Replace the permissions for the user with the given GUID.

        Sends ``PUT {base}/api/admin/users/{guid}/permissions``. Requires
        ``admin_key``. Permissions must already be defined on the server.
        """
        self._admin_request(
            "PUT", f"/api/admin/users/{guid}/permissions", list(permissions)
        )

    # ------------------------------------------------------------------
    # App self-management (v2: /api/app/*, HTTP Basic app_id:app_secret)
    # ------------------------------------------------------------------

    def _app_request(
        self,
        method: str,
        path: str,
        payload: Optional[Any] = None,
    ) -> Optional[Any]:
        """Issue a ``/api/app/*`` request authenticated as the app.

        Uses HTTP Basic ``app_id:app_secret`` (the server also derives the
        ``app_id`` from the credential, so it is never placed in the path).

        Raises:
            AppError: If ``app_id`` / ``app_secret`` are missing, the request
                fails, or the server returns a non-2xx status.
        """
        if not self.app_id or not self.app_secret:
            raise AppError(
                "app_id and app_secret are required for app self-management operations"
            )

        try:
            resp = self._session.request(
                method,
                f"{self.base_url}{path}",
                json=payload if payload is not None else None,
                auth=(self.app_id, self.app_secret),
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise AppError(f"app request to {path} failed: {exc}") from exc

        if not (200 <= resp.status_code < 300):
            message, detail, code = self._extract_error(resp)
            raise AppError(
                message, status_code=resp.status_code, detail=detail, code=code
            )

        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return None

    def app_bootstrap(
        self,
        *,
        roles: Optional[List[str]] = None,
        permissions: Optional[List[str]] = None,
        role_permissions: Optional[Mapping[str, List[str]]] = None,
        assignments: Optional[List[Mapping[str, Any]]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Declare this app's authorization as code (idempotent).

        Sends ``POST {base}/api/app/bootstrap`` with the app credential. Safe to
        call on every deploy: it upserts the app's roles, permissions, the
        role→permission map, and the user/group assignments.

        Args:
            roles: Roles to define inside this app.
            permissions: Permissions to define inside this app.
            role_permissions: Map of role -> the permissions it grants.
            assignments: List of assignment entries, each either
                ``{"user": "<ref>", "roles": [...]}`` (ref = GUID,
                sAMAccountName, or username) or
                ``{"group": "<sAMAccountName>", "roles": [...]}``.

        Raises:
            AppError: If app credentials are missing or the request fails.
        """
        body: Dict[str, Any] = {
            "roles": list(roles or []),
            "permissions": list(permissions or []),
            "role_permissions": {
                k: list(v) for k, v in (role_permissions or {}).items()
            },
            "assignments": [dict(a) for a in (assignments or [])],
        }
        result = self._app_request("POST", "/api/app/bootstrap", body)
        return result if isinstance(result, dict) else None

    def get_app_authz(self) -> AppAuthz:
        """Read this app's per-app authorization.

        Sends ``GET {base}/api/app/authz`` and returns an
        :class:`~simpleauth.models.AppAuthz` (roles, permissions,
        role_permissions, and user/group assignments).

        Raises:
            AppError: If app credentials are missing or the request fails.
        """
        result = self._app_request("GET", "/api/app/authz")
        return AppAuthz.from_dict(result if isinstance(result, Mapping) else {})

    def set_app_authz(
        self,
        authz: Optional[AppAuthz] = None,
        *,
        roles: Optional[List[str]] = None,
        permissions: Optional[List[str]] = None,
        role_permissions: Optional[Mapping[str, List[str]]] = None,
        user_assignments: Optional[Mapping[str, List[str]]] = None,
        group_assignments: Optional[Mapping[str, List[str]]] = None,
    ) -> AppAuthz:
        """Replace this app's per-app authorization.

        Sends ``PUT {base}/api/app/authz``. Pass an
        :class:`~simpleauth.models.AppAuthz` (e.g. one returned by
        :meth:`get_app_authz`) as the positional argument, or supply the
        individual fields as keywords. Any ``app_id`` is ignored — the server
        derives it from the credential.

        Returns the app's authorization as the server reports it after the
        update.

        Raises:
            AppError: If app credentials are missing or the request fails.
        """
        if authz is not None:
            body = authz.to_dict()
        else:
            body = AppAuthz(
                roles=list(roles or []),
                permissions=list(permissions or []),
                role_permissions={k: list(v) for k, v in (role_permissions or {}).items()},
                user_assignments={k: list(v) for k, v in (user_assignments or {}).items()},
                group_assignments={k: list(v) for k, v in (group_assignments or {}).items()},
            ).to_dict()

        result = self._app_request("PUT", "/api/app/authz", body)
        # The endpoint may echo the stored authz; fall back to a read otherwise.
        if isinstance(result, Mapping) and result:
            return AppAuthz.from_dict(result)
        return self.get_app_authz()

    def app_settings(self) -> Dict[str, Any]:
        """Return this app's settings (read-only, no secret).

        Sends ``GET {base}/api/app/settings``. Useful to learn whether this app
        has ``require_assignment`` or ``allow_local_users`` enabled.

        Raises:
            AppError: If app credentials are missing or the request fails.
        """
        result = self._app_request("GET", "/api/app/settings")
        return result if isinstance(result, dict) else {}

    def create_local_user(
        self,
        username: str,
        password: str,
        *,
        display_name: Optional[str] = None,
        email: Optional[str] = None,
        roles: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Provision an app-local user owned by this app.

        Sends ``POST {base}/api/app/users``. Requires the app's
        ``allow_local_users`` flag. The created user authenticates locally, only
        ever receives ``aud = <this app>`` tokens, and is unique **within this
        app** (it shadows a directory user of the same name at this app).

        Returns the created user record (which includes the assigned ``guid``).

        Raises:
            AppError: If app credentials are missing, local users are not
                allowed for this app, or the request fails.
        """
        body: Dict[str, Any] = {"username": username, "password": password}
        if display_name is not None:
            body["display_name"] = display_name
        if email is not None:
            body["email"] = email
        if roles is not None:
            body["roles"] = list(roles)
        result = self._app_request("POST", "/api/app/users", body)
        return result if isinstance(result, dict) else {}

    def list_local_users(self) -> List[Dict[str, Any]]:
        """List this app's app-local users.

        Sends ``GET {base}/api/app/users``.

        Raises:
            AppError: If app credentials are missing or the request fails.
        """
        result = self._app_request("GET", "/api/app/users")
        return list(result or [])

    def delete_local_user(self, guid: str) -> None:
        """Delete an app-local user owned by this app.

        Sends ``DELETE {base}/api/app/users/{guid}``. The user must be owned by
        this app.

        Raises:
            AppError: If app credentials are missing or the request fails.
        """
        self._app_request("DELETE", f"/api/app/users/{guid}")

    def set_local_user_password(self, guid: str, password: str) -> None:
        """Reset an app-local user's password.

        Sends ``PUT {base}/api/app/users/{guid}/password`` with ``{password}``.
        The user must be owned by this app.

        Raises:
            AppError: If app credentials are missing or the request fails.
        """
        self._app_request(
            "PUT", f"/api/app/users/{guid}/password", {"password": password}
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying HTTP session."""
        self._session.close()

    def __enter__(self) -> "SimpleAuth":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
