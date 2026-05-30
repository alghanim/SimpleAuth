"""Exception types raised by the SimpleAuth SDK."""

from __future__ import annotations

from typing import Optional


class SimpleAuthError(Exception):
    """Base class for all SimpleAuth SDK errors.

    Attributes:
        message: Human-readable error message.
        status_code: HTTP status code associated with the error, if any.
        detail: Server-provided error detail / description, if any.
        code: Machine-readable error code (e.g. OAuth2 ``error`` field), if any.
    """

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        detail: Optional[str] = None,
        code: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.detail = detail
        self.code = code

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.message


class AuthenticationError(SimpleAuthError):
    """Raised when login, refresh, or another credential exchange fails.

    Typically carries the HTTP ``status_code`` (e.g. 401) and a ``detail``
    string extracted from the server's JSON error body.
    """


class TokenVerificationError(SimpleAuthError):
    """Raised when a JWT cannot be verified.

    Causes include a malformed token, an unsupported/forbidden algorithm, an
    unknown signing key, an invalid signature, a missing/expired ``exp``
    claim, or an issuer/audience mismatch when those checks are enabled.

    Token contents are never included in the message.
    """


class AdminError(SimpleAuthError):
    """Raised when an admin API call fails or no admin key was configured."""


__all__ = [
    "SimpleAuthError",
    "AuthenticationError",
    "TokenVerificationError",
    "AdminError",
]
