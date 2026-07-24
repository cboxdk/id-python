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


@dataclass(frozen=True)
class Permission:
    """A single permission — a ``feature:action`` slug and a human description."""

    key: str
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"key": self.key, "description": self.description}


@dataclass(frozen=True)
class Role:
    """A role — a named bundle of permission keys the app grants together.

    Each entry in ``permissions`` should reference a declared :class:`Permission`
    ``key``; Cbox ID reports any that do not as ``orphaned_roles`` in the push summary.
    """

    key: str
    name: str
    description: str = ""
    permissions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "description": self.description,
            "permissions": list(self.permissions),
        }


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

    def permission(self, key: str, description: str = "") -> AuthzManifest:
        """Declare a permission (a ``feature:action`` slug). Returns ``self``."""
        self._permissions.append(Permission(key, description))
        return self

    def role(
        self,
        key: str,
        name: str,
        description: str = "",
        *,
        permissions: list[str] | None = None,
    ) -> AuthzManifest:
        """Declare a role and the permission keys it grants. Returns ``self``."""
        self._roles.append(Role(key, name, description, list(permissions or [])))
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


def _empty_to_null(value: str | None) -> str | None:
    """PHP treats an absent or empty description as ``null`` in the hashed catalog."""
    return value if value else None


def _canonical_json(permissions: list[Permission], roles: list[Role]) -> str:
    """The exact canonical JSON the PHP reference hashes (``Manifest::checksum``).

    Object keys in insertion order, permissions and roles sorted by key, each role's
    permission refs sorted, an absent-or-empty description emitted as ``null``, and
    PHP ``json_encode`` defaults: compact separators, non-ASCII escaped as ``\\uXXXX``
    (``ensure_ascii``), and forward slashes escaped as ``\\/``.
    """
    canonical = {
        "permissions": [
            {"key": permission.key, "description": _empty_to_null(permission.description)}
            for permission in sorted(permissions, key=lambda permission: permission.key)
        ],
        "roles": [
            {
                "key": role.key,
                "name": role.name,
                "description": _empty_to_null(role.description),
                "permissions": sorted(role.permissions),
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
