"""Value objects and configuration for the Cbox ID client."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
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


class AuthorizationPrompt(str, Enum):
    """An OIDC ``prompt`` value Cbox ID understands.

    The first four are OIDC Core §3.1.2.1; the last two are Cbox ID's organization steps:

    - ``SELECT_ORGANIZATION`` — always show the hosted organization picker, even to
      someone in a single organization.
    - ``CREATE_ORGANIZATION`` — the hosted "create a team" step: the person creates an
      organization, becomes its owner, and the sign-in continues bound to it.
    """

    NONE = "none"
    LOGIN = "login"
    CONSENT = "consent"
    SELECT_ACCOUNT = "select_account"
    SELECT_ORGANIZATION = "select_organization"
    CREATE_ORGANIZATION = "create_organization"


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
    #: The organization this sign-in is bound to, echoed when you passed one. Persist it
    #: with the rest and hand it back to :meth:`CboxIdClient.authenticate`, which then
    #: refuses tokens for any other organization — a binding nobody checks is a binding in
    #: name only.
    organization: str | None = None


class OrganizationRole(str, Enum):
    """The membership tier a person holds in the organization a token is bound to.

    The ``org_role`` claim. Coarse on purpose: it says who may administer the organization
    itself (invite, bill, delete). What they may do inside YOUR app is ``roles`` /
    ``permissions``, which your app declares and Cbox ID assigns.
    """

    OWNER = "owner"
    ADMIN = "admin"
    DEVELOPER = "developer"
    MEMBER = "member"
    VIEWER = "viewer"


@dataclass(frozen=True)
class ActiveOrganization:
    """The organization a token is bound to: the ``org``, ``org_name`` and ``org_role`` claims."""

    #: The stable organization id (``org``).
    id: str
    #: Its display name (``org_name``), when the instance sent one.
    name: str | None
    #: The person's membership tier in it (``org_role``). ``None`` when the claim is absent
    #: or carries a tier this SDK version does not know — an unrecognised tier is never
    #: guessed upward into one that grants something.
    role: OrganizationRole | None


@dataclass(frozen=True)
class Actor:
    """Who is actually driving a delegated session — the RFC 8693 §4.1 ``act`` claim.

    Cbox ID sets it on the tokens of a SUPPORT SESSION: a staff member acting as one of
    your users, with a stated reason, for at most an hour, with no refresh token.

    ``sub`` is the actor's subject id. It is ``None`` when an ``act`` claim is present but
    not in the shape RFC 8693 describes — the token is still acted, and saying so matters
    more than knowing by whom (see :func:`cbox_id.is_support_session`).
    """

    sub: str | None
    #: The prior actor, when delegation was chained (RFC 8693 §4.1 nested ``act``).
    actor: Actor | None = None


@dataclass(frozen=True)
class CboxUser:
    """The authenticated Cbox ID user.

    ``id`` is the stable opaque subject (``sub``) you key your local account on.
    ``claims`` is the full verified id_token + userinfo claim set; the named fields are
    conveniences over it.
    """

    id: str
    email: str | None
    name: str | None
    #: The active organization's id (``org`` claim). Same as ``organization.id``.
    organization_id: str | None
    claims: dict[str, Any]
    access_token: str
    refresh_token: str | None
    id_token: str | None
    expires_in: int
    # Defaulted, and after the fields above, so code that builds a CboxUser by hand (a
    # test fixture, a fake) keeps working unchanged.
    #: The organization this session is bound to — id, name and the person's membership
    #: tier in it — or ``None`` when it is bound to none.
    organization: ActiveOrganization | None = None
    #: App roles held in this session (``roles`` claim); empty when there are none.
    roles: list[str] = field(default_factory=list)
    #: Permissions held in this session (``permissions`` claim), already expanded from
    #: ``roles`` by Cbox ID; empty when there are none.
    permissions: list[str] = field(default_factory=list)
    #: Set when this is a SUPPORT SESSION — a staff member acting as this person (the RFC
    #: 8693 ``act`` claim). ``None`` for an ordinary sign-in. See :attr:`is_support_session`.
    actor: Actor | None = None
    #: The id_token's ``sid``: the identity-provider session this sign-in belongs to. Key
    #: your local session on it to honour an OIDC back-channel logout, whose logout token
    #: names the ``sid`` to end. Read from the signed id_token only, never from UserInfo.
    session_id: str | None = None

    def claim(self, key: str) -> Any:
        """Return an arbitrary claim, or ``None``."""
        return self.claims.get(key)

    @property
    def is_support_session(self) -> bool:
        """Whether somebody other than this person is driving the session.

        A staff member in a support session (the token carries ``act``). Fail-closed: an
        ``act`` claim this SDK cannot read still counts.
        """
        return self.actor is not None

    def has_role(self, role: str) -> bool:
        """Whether the session holds ``role``. Exact match; no wildcards."""
        return role in self.roles

    def has_permission(self, permission: str) -> bool:
        """Whether the session holds ``permission`` (``feature:action``). Exact match."""
        return permission in self.permissions


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
