"""Fresh app permission decisions, bound to the authenticated person and organization."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

import httpx

from .errors import AuthenticationError, ConfigurationError
from .models import OrganizationRole


@dataclass(frozen=True)
class PermissionDecision:
    subject: str
    organization: str | None
    client_id: str
    organization_role: OrganizationRole | None
    organization_active: bool
    permissions: Mapping[str, bool]

    def allows(self, permission: str) -> bool:
        return self.organization_active and self.permissions.get(permission) is True

    def allowed(self) -> bool:
        return (
            self.organization_active and bool(self.permissions) and all(self.permissions.values())
        )


def request_decision(
    http: httpx.Client,
    issuer: str,
    client_id: str,
    access_token: str,
    subject: str,
    organization: str | None,
    permissions: Sequence[str],
    timeout: float,
) -> PermissionDecision:
    if (
        not subject
        or organization == ""
        or not access_token
        or len(access_token) > 32768
        or any(ord(char) <= 32 or ord(char) == 127 for char in access_token)
        or not permissions
        or len(permissions) > 50
        or any(
            not permission.strip() or len(permission.encode()) > 255 for permission in permissions
        )
    ):
        raise ConfigurationError("Permission decision request is not configured or valid.")
    requested = list(dict.fromkeys(permissions))
    try:
        with http.stream(
            "POST",
            issuer.rstrip("/") + "/oauth/decisions",
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            json={"subject": subject, "org": organization, "permission": requested},
            follow_redirects=False,
            timeout=max(0.001, timeout),
        ) as response:
            if response.status_code != 200:
                raise AuthenticationError("Permission decision could not be verified.")
            raw = bytearray()
            for chunk in response.iter_bytes(chunk_size=65537):
                raw.extend(chunk)
                if len(raw) > 65536:
                    raise AuthenticationError("Permission decision response exceeded its limit.")
            data = json.loads(raw)
        return _parse(data, subject, organization, client_id, requested)
    except AuthenticationError:
        raise
    except Exception:
        # Transport exceptions can expose credentials and response bodies.
        raise AuthenticationError("Permission decision could not be verified.") from None


def _parse(
    data: Any, subject: str, organization: str | None, client_id: str, requested: list[str]
) -> PermissionDecision:
    if not isinstance(data, dict):
        raise AuthenticationError("Permission decision response is invalid.")
    who = data.get("subject")
    role = data.get("org_role")
    results = data.get("results")
    if (
        data.get("mode") != "rbac"
        or not isinstance(who, dict)
        or who.get("type") != "user"
        or who.get("id") != subject
        or "organization" not in data
        or data["organization"] != organization
        or data.get("client_id") != client_id
        or type(data.get("organization_active")) is not bool
        or type(data.get("allowed")) is not bool
        or "org_role" not in data
        or (role is not None and role not in [item.value for item in OrganizationRole])
        or not isinstance(results, list)
        or len(results) != len(requested)
    ):
        raise AuthenticationError("Permission decision response binding is invalid.")
    checks: dict[str, bool] = {}
    for result in results:
        if (
            not isinstance(result, dict)
            or not isinstance(result.get("permission"), str)
            or type(result.get("allowed")) is not bool
            or result["permission"] not in requested
            or result["permission"] in checks
        ):
            raise AuthenticationError("Permission decision result is invalid.")
        checks[result["permission"]] = result["allowed"]
    decision = PermissionDecision(
        subject,
        organization,
        client_id,
        OrganizationRole(role) if role is not None else None,
        data["organization_active"],
        MappingProxyType(checks),
    )
    if data["allowed"] != decision.allowed():
        raise AuthenticationError("Permission decision result is inconsistent.")
    return decision
