from __future__ import annotations

import json
from urllib.parse import parse_qsl

import httpx
import pytest

from cbox_id import (
    AuthzManifest,
    CboxIdClient,
    CboxIdConfig,
    ConfigurationError,
    ManifestPublishError,
)

ISSUER = "https://id.test"
CLIENT_ID = "client-abc"
CLIENT_SECRET = "secret-xyz"

DISCOVERY = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/oauth/authorize",
    "token_endpoint": f"{ISSUER}/oauth/token",
    "jwks_uri": f"{ISSUER}/oauth/jwks",
    "userinfo_endpoint": f"{ISSUER}/oauth/userinfo",
}


def build_manifest() -> AuthzManifest:
    return (
        AuthzManifest()
        .permission("invoices:create", "Create invoices")
        .permission("invoices:read", "View invoices")
        .role(
            "billing-admin",
            "Billing Admin",
            "Full billing access",
            permissions=["invoices:create", "invoices:read"],
        )
    )


class Recorder:
    """Records the token + manifest exchange served through an httpx MockTransport."""

    def __init__(self, *, manifest_status: int = 200) -> None:
        self.manifest_status = manifest_status
        self.token_form: dict[str, str] = {}
        self.manifest_request: httpx.Request | None = None
        self.manifest_body: dict[str, object] = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json=DISCOVERY)
        if url == DISCOVERY["token_endpoint"]:
            self.token_form = dict(parse_qsl(request.content.decode()))
            return httpx.Response(200, json={"access_token": "manifest-token"})
        if url == f"{ISSUER}/api/v1/apps/manifest":
            self.manifest_request = request
            self.manifest_body = json.loads(request.content)
            if self.manifest_status >= 400:
                return httpx.Response(self.manifest_status, json={"message": "rejected"})
            return httpx.Response(
                self.manifest_status,
                json={
                    "unchanged": False,
                    "roles_declared": 1,
                    "permissions_declared": 2,
                    "orphaned_roles": [],
                },
            )
        return httpx.Response(404)


def make_client(recorder: Recorder, *, client_secret: str | None = CLIENT_SECRET) -> CboxIdClient:
    http_client = httpx.Client(transport=httpx.MockTransport(recorder.handler))
    config = CboxIdConfig(
        issuer=ISSUER,
        client_id=CLIENT_ID,
        client_secret=client_secret,
        redirect_uri="https://app.test/auth/callback",
    )
    return CboxIdClient(config, http_client=http_client)


def test_manifest_declares_permissions_and_roles() -> None:
    body = build_manifest().to_dict()

    assert body["permissions"] == [
        {"key": "invoices:create", "description": "Create invoices"},
        {"key": "invoices:read", "description": "View invoices"},
    ]
    assert body["roles"] == [
        {
            "key": "billing-admin",
            "name": "Billing Admin",
            "description": "Full billing access",
            "permissions": ["invoices:create", "invoices:read"],
        }
    ]
    assert len(body["version"]) == 16
    assert int(body["version"], 16) >= 0  # 16 hex chars


def test_version_is_stable_and_content_sensitive() -> None:
    assert build_manifest().to_dict()["version"] == build_manifest().to_dict()["version"]

    changed = (
        AuthzManifest()
        .permission("invoices:create", "Create invoices")
        .permission("invoices:read", "View invoices")
        .role(
            "billing-admin",
            "Billing Admin",
            "Now with less access",  # description changed
            permissions=["invoices:create", "invoices:read"],
        )
    )
    assert changed.to_dict()["version"] != build_manifest().to_dict()["version"]


def test_publish_mints_apps_manifest_token_and_posts_manifest() -> None:
    recorder = Recorder()
    client = make_client(recorder)

    summary = client.publish_manifest(build_manifest())

    # 1. The token is minted with client-credentials + the apps.manifest scope.
    assert recorder.token_form["grant_type"] == "client_credentials"
    assert recorder.token_form["scope"] == "apps.manifest"
    assert recorder.token_form["client_id"] == CLIENT_ID
    assert recorder.token_form["client_secret"] == CLIENT_SECRET

    # 2. The manifest is POSTed with the bearer token, Accept, and the exact body.
    assert recorder.manifest_request is not None
    assert recorder.manifest_request.headers["authorization"] == "Bearer manifest-token"
    assert recorder.manifest_request.headers["accept"] == "application/json"
    assert recorder.manifest_body == build_manifest().to_dict()

    # 3. The server's sync summary is returned as-is.
    assert summary == {
        "unchanged": False,
        "roles_declared": 1,
        "permissions_declared": 2,
        "orphaned_roles": [],
    }


def test_publish_raises_on_rejected_push() -> None:
    recorder = Recorder(manifest_status=422)
    client = make_client(recorder)

    with pytest.raises(ManifestPublishError, match="422"):
        client.publish_manifest(build_manifest())


def test_publish_requires_client_secret() -> None:
    recorder = Recorder()
    client = make_client(recorder, client_secret=None)

    with pytest.raises(ConfigurationError):
        client.publish_manifest(build_manifest())
