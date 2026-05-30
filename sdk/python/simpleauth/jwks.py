"""JWKS fetching, caching, and RSA public-key construction.

The cache holds parsed :class:`RSAPublicKey` objects keyed by ``kid``. Keys are
cached for a configurable TTL (default one hour) and re-fetched on a ``kid``
miss, so key rotation on the server is picked up automatically.
"""

from __future__ import annotations

import base64
import threading
import time
from typing import Dict, Optional

import requests
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers

from .errors import TokenVerificationError


def _b64url_to_int(value: str) -> int:
    """Decode a base64url (unpadded) string into a big-endian integer."""
    padding = "=" * (-len(value) % 4)
    raw = base64.urlsafe_b64decode(value + padding)
    return int.from_bytes(raw, "big")


class JWKSCache:
    """Thread-safe cache of RSA signing keys fetched from a JWKS endpoint.

    Args:
        jwks_url: Absolute URL of the server's ``jwks.json`` document.
        session: A :class:`requests.Session` used for HTTP requests (so TLS
            verification and timeouts are shared with the owning client).
        ttl: Cache lifetime in seconds. Defaults to 3600 (one hour).
        verify_ssl: Whether to verify TLS certificates when fetching.
        timeout: Per-request timeout in seconds.
    """

    def __init__(
        self,
        jwks_url: str,
        session: requests.Session,
        ttl: float = 3600.0,
        verify_ssl: bool = True,
        timeout: float = 30.0,
    ) -> None:
        self._jwks_url = jwks_url
        self._session = session
        self._ttl = ttl
        self._verify_ssl = verify_ssl
        self._timeout = timeout

        self._keys: Dict[str, RSAPublicKey] = {}
        self._fetched_at: float = 0.0
        self._lock = threading.Lock()

    def get_key(self, kid: str) -> RSAPublicKey:
        """Return the RSA public key for ``kid``.

        Uses the cache when fresh; otherwise (or on a ``kid`` miss) re-fetches
        the JWKS document. Raises :class:`TokenVerificationError` if the key
        cannot be found after a refresh.
        """
        with self._lock:
            cached = self._keys.get(kid)
            fresh = (time.monotonic() - self._fetched_at) < self._ttl
            if cached is not None and fresh:
                return cached

            # Cache miss, stale cache, or unknown kid -> refetch.
            self._refresh_locked()

            key = self._keys.get(kid)
            if key is None:
                raise TokenVerificationError(
                    f"no signing key found for kid {kid!r}", status_code=401
                )
            return key

    def _refresh_locked(self) -> None:
        """Fetch and parse the JWKS document. Caller must hold ``self._lock``."""
        try:
            resp = self._session.get(
                self._jwks_url, verify=self._verify_ssl, timeout=self._timeout
            )
        except requests.RequestException as exc:
            raise TokenVerificationError(f"failed to fetch JWKS: {exc}") from exc

        if resp.status_code != 200:
            raise TokenVerificationError(
                f"JWKS endpoint returned HTTP {resp.status_code}",
                status_code=resp.status_code,
            )

        try:
            doc = resp.json()
        except ValueError as exc:
            raise TokenVerificationError("JWKS response was not valid JSON") from exc

        keys: Dict[str, RSAPublicKey] = {}
        for jwk in doc.get("keys", []):
            if jwk.get("kty") != "RSA":
                continue
            kid: Optional[str] = jwk.get("kid")
            try:
                n = _b64url_to_int(jwk["n"])
                e = _b64url_to_int(jwk["e"])
            except (KeyError, ValueError, TypeError):
                continue
            public_key = RSAPublicNumbers(e=e, n=n).public_key()
            if kid:
                keys[kid] = public_key

        self._keys = keys
        self._fetched_at = time.monotonic()


__all__ = ["JWKSCache"]
