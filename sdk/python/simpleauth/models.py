"""Data models returned by the SimpleAuth SDK.

These are plain dataclasses with light validation. They map directly onto the
JSON shapes produced by the SimpleAuth server's token endpoints and the claims
embedded in its RS256 access tokens.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional


@dataclass
class TokenResponse:
    """Response from a token endpoint (login / refresh / client_credentials).

    Mirrors the JSON body returned by the SimpleAuth server. Fields that the
    server omits default to sensible empty values.

    Attributes:
        access_token: The signed RS256 access token (JWT).
        refresh_token: The refresh token, if one was issued. The
            client_credentials grant does not return a refresh token.
        token_type: The token type, normally ``"Bearer"``.
        expires_in: Access token lifetime in seconds.
        scope: Granted scope string, if any (client_credentials grant).
        id_token: OIDC ID token, if one was issued.
        force_password_change: ``True`` when the server signals that the user
            must change their password before continuing. Only set by login.
    """

    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "Bearer"
    expires_in: int = 0
    scope: Optional[str] = None
    id_token: Optional[str] = None
    force_password_change: bool = False

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TokenResponse":
        """Build a :class:`TokenResponse` from a decoded JSON mapping."""
        return cls(
            access_token=data.get("access_token", "") or "",
            refresh_token=data.get("refresh_token"),
            token_type=data.get("token_type", "Bearer") or "Bearer",
            expires_in=int(data.get("expires_in", 0) or 0),
            scope=data.get("scope"),
            id_token=data.get("id_token"),
            force_password_change=bool(data.get("force_password_change", False)),
        )


@dataclass
class User:
    """Claims extracted from a verified SimpleAuth access token.

    The ``sub`` claim is the user's GUID. Role and permission helpers operate
    on the ``roles`` and ``permissions`` lists carried in the token.
    """

    sub: str = ""
    name: Optional[str] = None
    email: Optional[str] = None
    preferred_username: Optional[str] = None
    roles: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    department: Optional[str] = None
    company: Optional[str] = None
    job_title: Optional[str] = None
    #: The full decoded JWT payload, for callers that need non-standard claims.
    claims: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_claims(cls, claims: Mapping[str, Any]) -> "User":
        """Build a :class:`User` from a decoded JWT payload.

        Roles fall back to the Keycloak-style ``realm_access.roles`` structure
        when a flat ``roles`` claim is absent, matching the other SDKs.
        """
        roles = claims.get("roles")
        if roles is None:
            realm_access = claims.get("realm_access") or {}
            roles = realm_access.get("roles", []) if isinstance(realm_access, Mapping) else []
        return cls(
            sub=claims.get("sub", "") or "",
            name=claims.get("name"),
            email=claims.get("email"),
            preferred_username=claims.get("preferred_username"),
            roles=list(roles or []),
            permissions=list(claims.get("permissions") or []),
            groups=list(claims.get("groups") or []),
            department=claims.get("department"),
            company=claims.get("company"),
            job_title=claims.get("job_title"),
            claims=dict(claims),
        )

    def has_role(self, role: str) -> bool:
        """Return ``True`` if the user has the given role."""
        return role in self.roles

    def has_permission(self, permission: str) -> bool:
        """Return ``True`` if the user has the given permission."""
        return permission in self.permissions

    def has_any_role(self, *roles: str) -> bool:
        """Return ``True`` if the user has at least one of the given roles."""
        return any(role in self.roles for role in roles)


@dataclass
class AppAuthz:
    """An app's per-app authorization, as returned by ``GET /api/app/authz``.

    Mirrors the JSON body of the v2 app self-management ``authz`` endpoint. The
    same shape (minus ``app_id``) is accepted by ``PUT /api/app/authz`` and is
    produced by :meth:`to_dict` for round-tripping.

    Attributes:
        app_id: The calling app's id (read-only; ignored on PUT).
        roles: Roles defined inside this app.
        permissions: Permissions defined inside this app.
        role_permissions: Map of role -> the permissions it grants.
        user_assignments: Map of a user reference (GUID, sAMAccountName, or
            username) -> the roles assigned to that user in this app.
        group_assignments: Map of a group identifier (sAMAccountName by default)
            -> the roles assigned to members of that group in this app.
    """

    app_id: str = ""
    roles: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    role_permissions: Dict[str, List[str]] = field(default_factory=dict)
    user_assignments: Dict[str, List[str]] = field(default_factory=dict)
    group_assignments: Dict[str, List[str]] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AppAuthz":
        """Build an :class:`AppAuthz` from a decoded JSON mapping."""

        def _str_map(value: Any) -> Dict[str, List[str]]:
            if not isinstance(value, Mapping):
                return {}
            return {str(k): list(v or []) for k, v in value.items()}

        return cls(
            app_id=data.get("app_id", "") or "",
            roles=list(data.get("roles") or []),
            permissions=list(data.get("permissions") or []),
            role_permissions=_str_map(data.get("role_permissions")),
            user_assignments=_str_map(data.get("user_assignments")),
            group_assignments=_str_map(data.get("group_assignments")),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to the JSON shape accepted by ``PUT /api/app/authz``.

        ``app_id`` is intentionally omitted: the server derives it from the
        credential and ignores any value in the body.
        """
        return {
            "roles": list(self.roles),
            "permissions": list(self.permissions),
            "role_permissions": {k: list(v) for k, v in self.role_permissions.items()},
            "user_assignments": {k: list(v) for k, v in self.user_assignments.items()},
            "group_assignments": {k: list(v) for k, v in self.group_assignments.items()},
        }


@dataclass
class UserInfo(dict):
    """Response from the ``/api/auth/userinfo`` endpoint.

    This is a ``dict`` subclass so callers can iterate it (``info.items()``)
    exactly like the raw JSON, while also exposing the common OIDC fields as
    attributes for convenience.
    """

    def __init__(self, data: Optional[Mapping[str, Any]] = None) -> None:
        super().__init__(data or {})

    @property
    def sub(self) -> Optional[str]:
        # The userinfo endpoint returns the GUID under "guid".
        return self.get("guid") or self.get("sub")

    @property
    def name(self) -> Optional[str]:
        return self.get("display_name") or self.get("name")

    @property
    def email(self) -> Optional[str]:
        return self.get("email")

    @property
    def preferred_username(self) -> Optional[str]:
        return self.get("preferred_username")


__all__ = ["TokenResponse", "User", "UserInfo", "AppAuthz"]
