"""Value objects and configuration for the Cbox ID client."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CboxIdConfig:
    """Configuration for a :class:`CboxIdClient`."""

    issuer: str
    client_id: str
    redirect_uri: str
    client_secret: str | None = None
    scopes: list[str] = field(default_factory=lambda: ["openid", "profile", "email"])
    # The self-service page, not the org-admin one. `/settings` is the admin surface:
    # it redirects a non-admin to `/account` and drops `return_to` on the way, so a
    # member sent there lost the page they came from. Every SDK docstring already
    # described `/account` behaviour while defaulting to the other path.
    account_path: str = "/account"
    timeout_seconds: float = 10.0
    cache_ttl_seconds: float = 3600.0


@dataclass(frozen=True)
class AuthorizationRequest:
    """What :meth:`CboxIdClient.create_authorization_request` returns.

    Persist ``state``, ``code_verifier`` and ``nonce`` (e.g. in the session) and hand
    them back to :meth:`CboxIdClient.authenticate` on the callback.
    """

    url: str
    state: str
    code_verifier: str
    nonce: str


@dataclass(frozen=True)
class CboxUser:
    """The authenticated Cbox ID user.

    ``id`` is the stable opaque subject (``sub``) you key your local account on.
    ``claims`` is the full verified id_token + userinfo claim set.
    """

    id: str
    email: str | None
    name: str | None
    organization_id: str | None
    claims: dict[str, Any]
    access_token: str
    refresh_token: str | None
    id_token: str | None
    expires_in: int

    def claim(self, key: str) -> Any:
        """Return an arbitrary claim, or ``None``."""
        return self.claims.get(key)


@dataclass(frozen=True)
class RefreshedTokens:
    """Tokens returned by :meth:`CboxIdClient.refresh`.

    Cbox ID rotates refresh tokens and detects reuse, so ``refresh_token`` is a NEW
    value — store it and discard the one you presented; replaying a rotated token
    revokes the whole family.
    """

    access_token: str
    refresh_token: str
    id_token: str | None
    expires_in: int
    scope: str | None
