"""Cross-SDK manifest-hash fixture.

The manifests in ``fixtures/manifest_hash.json`` and their canonical JSON + hash were
generated from the PHP reference (``Cbox\\Id\\AccessControl\\Manifest\\Manifest::checksum``).
id-js, id-python, id-go and laravel-id all assert against this same file, so the four
canonicalizations stay byte-for-byte locked together.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from cbox_id.authz import AuthzManifest, Permission, Role, _canonical_json

FIXTURE: dict[str, Any] = json.loads(
    (Path(__file__).parent / "fixtures" / "manifest_hash.json").read_text(encoding="utf-8")
)


def _permission(entry: dict[str, Any]) -> Permission:
    # Absent means internal: a permission is offered to tenants only when opted in.
    return Permission(
        entry["key"], entry["description"] or "", entry.get("tenant_assignable", False)
    )


def _role(entry: dict[str, Any]) -> Role:
    # Absent means assignable: a role is staff-only only when declared so.
    return Role(
        entry["key"],
        entry["name"],
        entry["description"] or "",
        list(entry["permissions"]),
        entry.get("tenant_assignable", True),
    )


def test_fixture_covers_both_flags() -> None:
    # A copy that silently lost the staff-role or self-serve case would still pass below.
    names = {case["name"] for case in FIXTURE["cases"]}
    assert {"empty", "basic", "edge_cases", "staff_role", "self_serve_permission"} <= names


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=lambda case: case["name"])
def test_manifest_hash_matches_php_reference(case: dict[str, Any]) -> None:
    permissions = [_permission(entry) for entry in case["permissions"]]
    roles = [_role(entry) for entry in case["roles"]]

    # Byte-for-byte identical canonical serialization to PHP's json_encode, and the hash
    # of exactly those bytes.
    canonical = _canonical_json(permissions, roles)
    assert canonical == case["canonical_json"]
    assert hashlib.sha256(canonical.encode()).hexdigest() == case["sha256"]
    assert case["version"] == case["sha256"][:16]

    # And the same version flows through the public builder.
    manifest = AuthzManifest()
    for entry in case["permissions"]:
        manifest.permission(
            entry["key"],
            entry["description"] or "",
            tenant_assignable=entry.get("tenant_assignable", False),
        )
    for entry in case["roles"]:
        manifest.role(
            entry["key"],
            entry["name"],
            entry["description"] or "",
            permissions=list(entry["permissions"]),
            tenant_assignable=entry.get("tenant_assignable", True),
        )
    assert manifest.to_dict()["version"] == case["version"]


def test_repeated_permission_refs_hash_like_the_server_parsed_them() -> None:
    # The server drops a repeated ref before it hashes, so a role that lists one twice
    # must hash to the same version as one that lists it once — or every deploy of it
    # looks like a change and re-syncs for nothing.
    once = AuthzManifest().permission("a:read").role("r", "R", permissions=["a:read"])
    twice = AuthzManifest().permission("a:read").role("r", "R", permissions=["a:read", "a:read"])

    assert twice.to_dict()["version"] == once.to_dict()["version"]
