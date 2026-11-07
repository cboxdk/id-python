from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from cbox_id import AuthenticationError, CboxIdClient, CboxIdConfig, OrganizationRole


def decision() -> dict[str, Any]:
    return {
        "mode": "rbac",
        "subject": {"type": "user", "id": "person-a"},
        "organization": "org-a",
        "client_id": "app-a",
        "org_role": "admin",
        "organization_active": True,
        "allowed": True,
        "results": [{"permission": "documents:read", "allowed": True}],
    }


def client(handler: Any) -> CboxIdClient:
    return CboxIdClient(
        CboxIdConfig(
            issuer="https://id.example.test",
            client_id="app-a",
            redirect_uri="https://app.example.test/callback",
        ),
        http_client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True),
    )


def test_decisions_recheck_revocation_and_do_not_promote_shared_admin() -> None:
    current = decision()
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert json.loads(request.content) == {
            "subject": "person-a",
            "org": "org-a",
            "permission": ["documents:read"],
        }
        return httpx.Response(200, json=current)

    sdk = client(handler)
    assert sdk.check_permissions("token", "person-a", "org-a", ["documents:read"]).allowed()
    current["allowed"] = False
    current["results"][0]["allowed"] = False
    revoked = sdk.check_permissions("token", "person-a", "org-a", ["documents:read"])
    assert revoked.organization_role == OrganizationRole.ADMIN
    assert not revoked.allowed()
    assert not revoked.allows("documents:write")
    assert len(calls) == 2


@pytest.mark.parametrize(
    "override",
    [
        {"subject": {"type": "user", "id": "person-b"}},
        {"subject": {"type": "client", "id": "person-a"}},
        {"organization": "org-b"},
        {"client_id": "app-b"},
        {"mode": "fga"},
        {"org_role": "superadmin"},
        {"organization_active": "true"},
        {"organization_active": False},
        {"allowed": False},
        {"results": []},
        {"results": [{"permission": "documents:write", "allowed": True}]},
        {"results": [{"permission": "documents:read", "allowed": 1}]},
    ],
)
def test_mismatched_decisions_fail_closed(override: dict[str, Any]) -> None:
    sdk = client(lambda _: httpx.Response(200, json={**decision(), **override}))
    with pytest.raises(AuthenticationError):
        sdk.check_permissions("token", "person-a", "org-a", ["documents:read"])


@pytest.mark.parametrize("status", [302, 401, 403, 429, 500, 503])
def test_http_failures_and_redirects_never_authorize(status: int) -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(
            status, text="secret-token", headers={"Location": "https://evil.test"}
        )

    with pytest.raises(AuthenticationError, match="could not be verified"):
        client(handler).check_permissions("token", "person-a", "org-a", ["documents:read"])
    assert len(calls) == 1


def test_response_size_and_transport_errors_are_bounded_and_sanitized() -> None:
    with pytest.raises(AuthenticationError, match="exceeded its limit"):
        client(lambda _: httpx.Response(200, content=b"x" * 65537)).check_permissions(
            "token", "person-a", "org-a", ["documents:read"]
        )

    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("secret-token")

    with pytest.raises(AuthenticationError, match="^Permission decision could not be verified.$"):
        client(handler).check_permissions("token", "person-a", "org-a", ["documents:read"])
