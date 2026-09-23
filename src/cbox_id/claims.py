"""Read organization, support-session and authorization claims.

Every helper takes a :class:`~cbox_id.CboxUser` from sign-in OR a claim mapping you
verified yourself — an access token's payload on a resource server, say, which has claims
but no user. The same rules apply to both, so an API and the app in front of it cannot
disagree about what a token says.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeAlias

from .models import ActiveOrganization, Actor, CboxUser, OrganizationRole

#: A signed-in user, or a claim set you verified yourself.
ClaimSource: TypeAlias = CboxUser | Mapping[str, Any]

# Nesting is bounded: RFC 8693 chains are a handful deep in practice, and a claim nested
# thousands deep is either a bug or an attempt to exhaust the stack. Past the bound the
# chain is cut, not dropped — the session is still acted.
_MAX_ACTOR_DEPTH = 8

_ORGANIZATION_ROLES: dict[str, OrganizationRole] = {role.value: role for role in OrganizationRole}


def organization(source: ClaimSource) -> ActiveOrganization | None:
    """The organization this session is bound to, or ``None`` when it is bound to none.

    ::

        org = organization(user)
        if org and org.role is OrganizationRole.OWNER:
            show_billing()
    """
    claims = _claims_of(source)
    org_id = claims.get("org")

    if not isinstance(org_id, str) or org_id == "":
        return None

    name = claims.get("org_name")
    role = claims.get("org_role")

    return ActiveOrganization(
        id=org_id,
        name=name if isinstance(name, str) and name != "" else None,
        # A tier this version does not know reads as "none", never as a guess: mapping an
        # unknown value onto the nearest known one could hand somebody owner-only screens.
        role=_ORGANIZATION_ROLES.get(role) if isinstance(role, str) else None,
    )


def actor(source: ClaimSource) -> Actor | None:
    """The actor behind a support session (``act``), or ``None`` for an ordinary session."""
    return _parse_actor(_claims_of(source).get("act"), 0)


def is_support_session(source: ClaimSource) -> bool:
    """Whether somebody other than the signed-in person is driving this session.

    A staff member in a support session: the token carries ``act``.

    FAIL-CLOSED. Any present, non-null ``act`` claim counts, including one whose shape
    this SDK cannot read: the check exists so an app can show a banner and refuse the
    things a helper should never do on somebody's behalf (change their password, move
    their money), and a malformed claim is not evidence that nobody else is at the keyboard.
    """
    return actor(source) is not None


def roles(source: ClaimSource) -> list[str]:
    """The app roles this session holds — the ``roles`` claim; empty when there are none."""
    return _string_list(_claims_of(source).get("roles"))


def permissions(source: ClaimSource) -> list[str]:
    """The permissions this session holds — the ``permissions`` claim.

    Already expanded from ``roles`` by Cbox ID; empty when there are none.
    """
    return _string_list(_claims_of(source).get("permissions"))


def has_role(source: ClaimSource, role: str) -> bool:
    """Whether the session holds ``role``. Exact match; no wildcards."""
    return role in roles(source)


def has_permission(source: ClaimSource, permission: str) -> bool:
    """Whether the session holds ``permission`` (``feature:action``).

    Exact match; no wildcards — a claim of ``invoices:*`` does not grant
    ``invoices:delete``, because nothing on the issuing side ever mints one.
    """
    return permission in permissions(source)


def _parse_actor(claim: object, depth: int) -> Actor | None:
    # Only an absent or null claim means "nobody else". `False`, `""`, `[]` and `{}` are
    # all present, and all mean an issuer tried to say something about an actor.
    if claim is None:
        return None

    if not isinstance(claim, Mapping):
        return Actor(sub=None)

    sub = claim.get("sub")
    nested = _parse_actor(claim.get("act"), depth + 1) if depth + 1 < _MAX_ACTOR_DEPTH else None

    return Actor(sub=sub if isinstance(sub, str) and sub != "" else None, actor=nested)


def _string_list(claim: object) -> list[str]:
    if not isinstance(claim, list):
        return []
    return [value for value in claim if isinstance(value, str) and value != ""]


def _claims_of(source: ClaimSource) -> Mapping[str, Any]:
    return source.claims if isinstance(source, CboxUser) else source
