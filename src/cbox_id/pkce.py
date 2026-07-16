"""PKCE (RFC 7636) helpers and the random values the login flow needs."""

from __future__ import annotations

import base64
import hashlib
import secrets


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def random_token(num_bytes: int = 32) -> str:
    """A URL-safe random token, for state and nonce."""
    return _b64url(secrets.token_bytes(num_bytes))


def create_verifier() -> str:
    """A high-entropy PKCE code verifier."""
    return random_token(32)


def challenge(verifier: str) -> str:
    """The S256 code challenge for a verifier."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return _b64url(digest)
