"""Declare this app's authorization roles & permissions, and publish them to Cbox ID.

This is the app-owned half of Cbox ID's federated RBAC model: the app declares, in
code, what its roles *mean* (which permissions each grants) and pushes that catalog to
Cbox ID with :meth:`CboxIdClient.publish_manifest`. Cbox ID owns identity and who holds
which role; the app owns what a role means. The manifest JSON contract is identical
across every Cbox ID SDK.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from .errors import ConfigurationError


@dataclass(frozen=True)
class Permission:
    """A single permission — a ``feature:action`` slug and a human description.

    ``tenant_assignable`` offers the permission to tenant administrators, who may then
    grant it on its own in their organization (self-serve). Off by default: a permission
    stays internal — reachable only through the roles you declare — unless you opt it in.
    """

    key: str
    description: str = ""
    tenant_assignable: bool = False

    def __post_init__(self) -> None:
        _require_bool(self.tenant_assignable, f'permission "{self.key}"')

    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {"key": self.key, "description": self.description}
        # Sent only when it differs from the server's default, so a manifest that never
        # mentions the flag is the same body it always was.
        if self.tenant_assignable:
            body["tenant_assignable"] = True
        return body


@dataclass(frozen=True)
class Role:
    """A role — a named bundle of permission keys the app grants together.

    Each entry in ``permissions`` should reference a declared :class:`Permission`
    ``key``; Cbox ID reports any that do not as ``orphaned_roles`` in the push summary.

    ``tenant_assignable=False`` makes it a STAFF role: only your own operators can grant
    it, never a customer's administrator — the role for a support desk that may act as
    any customer. On by default, because that is what every role was before the flag.
    """

    key: str
    name: str
    description: str = ""
    permissions: list[str] = field(default_factory=list)
    tenant_assignable: bool = True

    def __post_init__(self) -> None:
        _require_bool(self.tenant_assignable, f'role "{self.key}"')

    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "key": self.key,
            "name": self.name,
            "description": self.description,
            "permissions": list(self.permissions),
        }
        # THE ONE KEY THAT MUST NOT GO MISSING. The server reads an absent flag as
        # "assignable by every tenant", so a body that dropped it would publish a staff
        # role as one any customer administrator can hand out. Sent only when false, the
        # non-default, which keeps every other role's body exactly as it was.
        if not self.tenant_assignable:
            body["tenant_assignable"] = False
        return body


class AuthzManifest:
    """A fluent builder for this app's authorization manifest.

    Declare permissions and roles in code, then hand the manifest to
    :meth:`CboxIdClient.publish_manifest` (typically on deploy)::

        manifest = (
            AuthzManifest()
            .permission("invoices:create", "Create invoices")
            .role("billing-admin", "Billing Admin", permissions=["invoices:create"])
        )
        client.publish_manifest(manifest)
    """

    def __init__(self) -> None:
        self._permissions: list[Permission] = []
        self._roles: list[Role] = []

    def permission(
        self, key: str, description: str = "", *, tenant_assignable: bool = False
    ) -> AuthzManifest:
        """Declare a permission (a ``feature:action`` slug). Returns ``self``.

        ``tenant_assignable=True`` lets tenant administrators grant it on its own.
        """
        self._permissions.append(Permission(key, description, tenant_assignable))
        return self

    def role(
        self,
        key: str,
        name: str,
        description: str = "",
        *,
        permissions: list[str] | None = None,
        tenant_assignable: bool = True,
    ) -> AuthzManifest:
        """Declare a role and the permission keys it grants. Returns ``self``.

        ``tenant_assignable=False`` declares a staff role that only your own operators
        can grant.
        """
        self._roles.append(Role(key, name, description, list(permissions or []), tenant_assignable))
        return self

    def to_dict(self) -> dict[str, Any]:
        """The manifest as it will be sent — permissions, roles, and a content version.

        ``version`` is a content-derived hash, so republishing an unchanged catalog is
        a server-side no-op.
        """
        body: dict[str, Any] = {
            "permissions": [permission.to_dict() for permission in self._permissions],
            "roles": [role.to_dict() for role in self._roles],
        }
        body["version"] = _version(self._permissions, self._roles)
        return body

    def is_empty(self) -> bool:
        """Whether nothing has been declared yet."""
        return not self._permissions and not self._roles


def _require_bool(value: object, what: str) -> None:
    """Refuse a flag that is not a real ``bool``.

    Truthiness would read the string ``"false"`` — straight out of a YAML file or an
    environment variable — as true, and a staff role declared that way would be published
    as one every tenant can grant. The server refuses a non-boolean too; failing here does
    it before a deploy, in the process that made the mistake.
    """
    if not isinstance(value, bool):
        raise ConfigurationError(f"{what} tenant_assignable must be True or False, got {value!r}.")


def _empty_to_null(value: str | None) -> str | None:
    """PHP treats an absent or empty description as ``null`` in the hashed catalog."""
    return value if value else None


def _canonical_json(permissions: list[Permission], roles: list[Role]) -> str:
    """The exact canonical JSON the PHP reference hashes (``Manifest::checksum``).

    Object keys in insertion order, permissions and roles sorted by key, each role's
    permission refs de-duplicated and sorted (the server's parser drops repeats before it
    hashes), an absent-or-empty description emitted as ``null``, and PHP ``json_encode``
    defaults: compact separators, non-ASCII escaped as ``\\uXXXX`` (``ensure_ascii``),
    and forward slashes escaped as ``\\/``.

    ``tenant_assignable`` appears only in its non-default state — ``true`` on a
    permission, ``false`` on a role — so every manifest that never mentions it hashes to
    the bytes it always did. It has to appear at all because an unchanged hash skips the
    sync: marking a role staff-only would otherwise never reach the server.
    """
    canonical = {
        "permissions": [
            {
                "key": permission.key,
                "description": _empty_to_null(permission.description),
                **({"tenant_assignable": True} if permission.tenant_assignable else {}),
            }
            for permission in sorted(permissions, key=lambda permission: permission.key)
        ],
        "roles": [
            {
                "key": role.key,
                "name": role.name,
                "description": _empty_to_null(role.description),
                "permissions": sorted(set(role.permissions)),
                **({} if role.tenant_assignable else {"tenant_assignable": False}),
            }
            for role in sorted(roles, key=lambda role: role.key)
        ],
    }
    return json.dumps(canonical, separators=(",", ":"), ensure_ascii=True).replace("/", "\\/")


def _version(permissions: list[Permission], roles: list[Role]) -> str:
    """A stable 16-hex-char content hash of the manifest's permissions + roles.

    Mirrors the PHP reference SDK byte-for-byte (see :func:`_canonical_json`) so the
    same catalog yields the same version across every Cbox ID SDK.
    """
    encoded = _canonical_json(permissions, roles)
    return hashlib.sha256(encoded.encode()).hexdigest()[:16]
