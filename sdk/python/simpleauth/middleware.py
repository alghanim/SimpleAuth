"""Framework integrations for Flask, FastAPI, and Django.

Every framework dependency is imported lazily inside the function or method that
needs it, so ``import simpleauth.middleware`` succeeds even when Flask, FastAPI,
or Django is not installed. You only pay for what you use.

Provided helpers:

* :func:`flask_middleware` — a Flask route decorator that verifies the Bearer
  token, stores the :class:`~simpleauth.models.User` on ``flask.g.user``, and
  optionally enforces a role or permission.
* :class:`SimpleAuthDep` — a FastAPI dependency that verifies the Bearer token
  and returns the :class:`~simpleauth.models.User`, optionally enforcing a role
  or permission.
* :class:`SimpleAuthMiddleware` — Django middleware that sets
  ``request.simpleauth_user`` (or ``None``) on every request.
* :func:`django_login_required` — a Django view decorator that requires an
  authenticated user and optionally a role or permission.
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Optional

from .client import SimpleAuth
from .errors import TokenVerificationError
from .models import User

__all__ = [
    "flask_middleware",
    "SimpleAuthDep",
    "SimpleAuthMiddleware",
    "django_login_required",
    "extract_bearer_token",
]


def extract_bearer_token(header_value: Optional[str]) -> Optional[str]:
    """Return the token from an ``Authorization: Bearer <token>`` header value.

    Returns ``None`` when the header is missing or not a Bearer credential.
    """
    if not header_value:
        return None
    prefix = "bearer "
    if header_value[: len(prefix)].lower() != prefix:
        return None
    token = header_value[len(prefix):].strip()
    return token or None


def _authorize(user: User, required_role: Optional[str], required_permission: Optional[str]) -> bool:
    """Return ``True`` if ``user`` satisfies the role/permission requirements."""
    if required_role is not None and not user.has_role(required_role):
        return False
    if required_permission is not None and not user.has_permission(required_permission):
        return False
    return True


# ---------------------------------------------------------------------------
# Flask
# ---------------------------------------------------------------------------


def flask_middleware(
    auth: SimpleAuth,
    required_role: Optional[str] = None,
    required_permission: Optional[str] = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Build a Flask route decorator that enforces SimpleAuth authentication.

    The decorator verifies the request's Bearer token, stores the resulting
    :class:`~simpleauth.models.User` on ``flask.g.user``, and then calls the
    wrapped view. It returns ``401`` when the token is missing or invalid and
    ``403`` when ``required_role`` / ``required_permission`` is not satisfied.

    Args:
        auth: The :class:`SimpleAuth` client used for verification.
        required_role: If set, the user must have this role.
        required_permission: If set, the user must have this permission.
    """

    def decorator(view: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(view)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            from flask import g, jsonify, request  # lazy import

            token = extract_bearer_token(request.headers.get("Authorization"))
            if token is None:
                return jsonify({"error": "missing or invalid Authorization header"}), 401

            try:
                user = auth.verify(token)
            except TokenVerificationError as exc:
                return jsonify({"error": str(exc)}), 401

            if not _authorize(user, required_role, required_permission):
                return jsonify({"error": "forbidden: insufficient permissions"}), 403

            g.user = user
            return view(*args, **kwargs)

        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# FastAPI
# ---------------------------------------------------------------------------


class SimpleAuthDep:
    """A FastAPI dependency that authenticates requests with SimpleAuth.

    Instances are callables suitable for ``Depends(...)``. On each request the
    dependency verifies the Bearer token and returns the
    :class:`~simpleauth.models.User`. It raises ``HTTPException(401)`` when the
    token is missing or invalid, and ``HTTPException(403)`` when the configured
    role/permission requirement is not met.

    Example:
        >>> get_user = SimpleAuthDep(auth)
        >>> require_admin = SimpleAuthDep(auth, required_role="admin")

    Args:
        auth: The :class:`SimpleAuth` client used for verification.
        required_role: If set, the user must have this role.
        required_permission: If set, the user must have this permission.
    """

    def __init__(
        self,
        auth: SimpleAuth,
        required_role: Optional[str] = None,
        required_permission: Optional[str] = None,
    ) -> None:
        import inspect

        from fastapi import Depends  # lazy import
        from fastapi.security import HTTPBearer

        self._auth = auth
        self._required_role = required_role
        self._required_permission = required_permission

        # Tell FastAPI (via __signature__) that __call__ takes one parameter,
        # ``credentials``, supplied by an HTTPBearer security dependency. Using
        # __signature__ avoids the stringized-annotation problem caused by
        # ``from __future__ import annotations`` and makes the Bearer scheme
        # show up in Swagger's Authorize dialog. auto_error=False lets us raise
        # our own clear 401 instead of FastAPI's default 403.
        bearer = Depends(HTTPBearer(auto_error=False))
        self.__signature__ = inspect.Signature(
            parameters=[
                inspect.Parameter(
                    "credentials",
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    default=bearer,
                )
            ]
        )

    async def __call__(self, credentials: Any = None) -> User:
        from fastapi import HTTPException  # lazy import

        token = credentials.credentials if credentials is not None else None
        if not token:
            raise HTTPException(
                status_code=401,
                detail="Missing or invalid Authorization header",
                headers={"WWW-Authenticate": "Bearer"},
            )

        try:
            user = self._auth.verify(token)
        except TokenVerificationError as exc:
            raise HTTPException(
                status_code=401,
                detail=str(exc),
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not _authorize(user, self._required_role, self._required_permission):
            raise HTTPException(status_code=403, detail="Insufficient permissions")

        return user


# ---------------------------------------------------------------------------
# Django
# ---------------------------------------------------------------------------


class SimpleAuthMiddleware:
    """Django middleware that attaches ``request.simpleauth_user`` to requests.

    Reads configuration from Django settings:

    * ``SIMPLEAUTH_URL`` (required) — server base URL including the base path.
    * ``SIMPLEAUTH_ADMIN_KEY`` (optional) — admin key for admin operations.
    * ``SIMPLEAUTH_VERIFY_SSL`` (optional, default ``True``).
    * ``SIMPLEAUTH_REALM`` (optional, default ``"simpleauth"``).
    * ``SIMPLEAUTH_EXPECTED_ISSUER`` (optional) — pin the token issuer.
    * ``SIMPLEAUTH_AUDIENCE`` (optional) — pin the token audience.

    For every request it verifies the Bearer token if present and sets
    ``request.simpleauth_user`` to the resulting
    :class:`~simpleauth.models.User`, or to ``None`` when no valid token is
    supplied. It does not reject unauthenticated requests itself — use
    :func:`django_login_required` on the views that need protection.
    """

    def __init__(self, get_response: Callable[[Any], Any]) -> None:
        from django.conf import settings  # lazy import
        from django.core.exceptions import ImproperlyConfigured  # lazy import

        self.get_response = get_response

        url = getattr(settings, "SIMPLEAUTH_URL", None)
        if not url:
            raise ImproperlyConfigured("SIMPLEAUTH_URL must be set in settings")

        self.auth = SimpleAuth(
            url=url,
            admin_key=getattr(settings, "SIMPLEAUTH_ADMIN_KEY", None) or None,
            verify_ssl=getattr(settings, "SIMPLEAUTH_VERIFY_SSL", True),
            realm=getattr(settings, "SIMPLEAUTH_REALM", "simpleauth") or "simpleauth",
            expected_issuer=getattr(settings, "SIMPLEAUTH_EXPECTED_ISSUER", None),
            audience=getattr(settings, "SIMPLEAUTH_AUDIENCE", None),
        )

    def __call__(self, request: Any) -> Any:
        request.simpleauth_user = self._resolve_user(request)
        return self.get_response(request)

    def _resolve_user(self, request: Any) -> Optional[User]:
        token = extract_bearer_token(request.META.get("HTTP_AUTHORIZATION"))
        if token is None:
            return None
        try:
            return self.auth.verify(token)
        except TokenVerificationError:
            return None


def django_login_required(
    required_role: Optional[str] = None,
    required_permission: Optional[str] = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorate a Django view to require an authenticated SimpleAuth user.

    Relies on :class:`SimpleAuthMiddleware` having populated
    ``request.simpleauth_user``. Returns a ``401`` JSON response when no user is
    present and a ``403`` JSON response when the configured role/permission is
    missing.

    Args:
        required_role: If set, the user must have this role.
        required_permission: If set, the user must have this permission.
    """

    def decorator(view: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(view)
        def wrapper(request: Any, *args: Any, **kwargs: Any) -> Any:
            from django.http import JsonResponse  # lazy import

            user: Optional[User] = getattr(request, "simpleauth_user", None)
            if user is None:
                return JsonResponse({"error": "Authentication required"}, status=401)

            if not _authorize(user, required_role, required_permission):
                return JsonResponse(
                    {"error": "Insufficient permissions"}, status=403
                )

            return view(request, *args, **kwargs)

        return wrapper

    return decorator
