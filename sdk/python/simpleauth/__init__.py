"""SimpleAuth Python SDK.

A small client for the SimpleAuth authentication server: password / refresh /
client-credentials token acquisition, the OIDC userinfo endpoint, admin
role/permission management, and offline RS256 JWT verification via JWKS.

Typical usage::

    from simpleauth import SimpleAuth

    auth = SimpleAuth(url="https://auth.example.com/sauth")
    tokens = auth.login("alice", "secret")
    user = auth.verify(tokens.access_token)
    if user.has_role("admin"):
        ...
"""

from __future__ import annotations

from .client import SimpleAuth
from .errors import (
    AdminError,
    AppError,
    AuthenticationError,
    SimpleAuthError,
    TokenVerificationError,
)
from .models import AppAuthz, TokenResponse, User, UserInfo

__version__ = "1.0.0"

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
    "__version__",
]
