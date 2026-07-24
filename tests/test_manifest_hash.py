"""Cross-SDK manifest-hash fixture.

The manifests in ``fixtures/manifest_hash.json`` and their canonical JSON + hash were
generated from the PHP reference (``Cbox\\Id\\AccessControl\\Manifest\\Manifest::checksum``).
id-js, id-python, id-go and laravel-id all assert against this same file, so the four
canonicalizations stay byte-for-byte locked together.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cbox_id.authz import AuthzManifest, Permission, Role, _canonical_json

FIXTURE: dict[str, Any] = json.loads(
    (Path(__file__).parent / "fixtures" / "manifest_hash.json").read_text(encoding="utf-8")
)


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=lambda case: case["name"])
def test_manifest_hash_matches_php_reference(case: dict[str, Any]) -> None:
    permissions = [
        Permission(entry["key"], entry["description"] or "") for entry in case["permissions"]
    ]
    roles = [
        Role(entry["key"], entry["name"], entry["description"] or "", list(entry["permissions"]))
        for entry in case["roles"]
    ]

    # Byte-for-byte identical canonical serialization to PHP's json_encode.
    assert _canonical_json(permissions, roles) == case["canonical_json"]
    assert case["version"] == case["sha256"][:16]

    # And the same version flows through the public builder.
    manifest = AuthzManifest()
    for entry in case["permissions"]:
        manifest.permission(entry["key"], entry["description"] or "")
    for entry in case["roles"]:
        manifest.role(
            entry["key"],
            entry["name"],
            entry["description"] or "",
            permissions=list(entry["permissions"]),
        )
    assert manifest.to_dict()["version"] == case["version"]
