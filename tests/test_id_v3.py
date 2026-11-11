"""Cbox ID v3, additively: the /v1 API on `api_url`, organization naming, prefixed ids and the
`id.*` event names. Without `api_url` every call is the one 0.12.0 made (test_management)."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import httpx
import pytest

from cbox_id import (
    AuthzManifest,
    CboxIdClient,
    CboxIdConfig,
    ConfigurationError,
    PipeNotConnectedError,
    PipesClient,
    current_event_name,
    event_name_aliases,
    is_prefixed_id,
    legacy_event_name,
    raw_id,
    same_event,
    same_id,
)
from cbox_id.management import (
    ENVIRONMENT_OPERATIONS,
    PLATFORM_OPERATIONS,
    WORKSPACE_OPERATIONS,
    CboxIdApiError,
    EnvironmentClient,
    OrganizationClient,
    PlatformClient,
    RetryOptions,
    WorkspaceClient,
)

from .management_helpers import FakeApi, json_response

API_URL = "https://api.cboxid.com"
V1 = f"{API_URL}/v1"
KEY = "cbid_env_test_key"
ULID = "01J9ZK3M4N5P6Q7R8S9T0VWXYZ"


def v1_env(fake: FakeApi, **options: Any) -> EnvironmentClient:
    settings: dict[str, Any] = {
        "api_url": API_URL,
        "api_key": KEY,
        "transport": fake.transport,
        "retry": RetryOptions(base_delay=0),
        "approval_poll_interval": 0,
        **options,
    }
    return EnvironmentClient(**settings)


def query(url: str) -> dict[str, str]:
    return dict(parse_qsl(urlsplit(url).query))


# ── Where the calls go ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("given", [API_URL, f"{API_URL}/", f"{API_URL}/v1", f"{API_URL}/v1/"])
def test_api_url_is_the_v1_api_with_or_without_its_version(given: str) -> None:
    client = EnvironmentClient(api_url=given, api_key=KEY)

    assert client.base_url == V1
    assert client.core.v1 is True


def test_without_api_url_nothing_changes() -> None:
    assert EnvironmentClient(base_url="https://acme.test", api_key=KEY).base_url == (
        "https://acme.test/api/v1"
    )
    assert WorkspaceClient(api_key="cbid_ws_k").base_url == "https://api.cboxid.com/api/v1"
    assert EnvironmentClient(base_url="https://acme.test", api_key=KEY).core.v1 is False


def test_api_url_replaces_the_default_base_url_of_the_root_planes() -> None:
    assert WorkspaceClient(api_url=API_URL, api_key="cbid_ws_k").base_url == V1
    assert PlatformClient(api_url=API_URL, access_token="t").base_url == V1


def test_api_url_and_base_url_together_are_refused() -> None:
    with pytest.raises(ConfigurationError, match="not both"):
        EnvironmentClient(base_url="https://acme.test", api_url=API_URL, api_key=KEY)


def test_api_url_must_be_https() -> None:
    with pytest.raises(ConfigurationError, match="`api_url` must be https"):
        EnvironmentClient(api_url="http://api.cboxid.com", api_key=KEY)

    assert EnvironmentClient(api_url="http://localhost:8000", api_key=KEY).base_url == (
        "http://localhost:8000/v1"
    )


def test_a_root_token_names_its_environment_on_v1_too() -> None:
    fake = FakeApi(json_response({"object": "app", "id": "app_1"}))
    client = v1_env(fake, api_key=None, access_token="root-token", environment="acme")

    client.apps.get("app_1")

    assert fake.calls[0].url == f"{V1}/apps/app_1"
    assert fake.calls[0].headers["cbox-environment"] == "acme"


def test_a_key_still_names_no_environment_on_v1() -> None:
    with pytest.raises(ConfigurationError, match="bound to its own environment"):
        EnvironmentClient(api_url=API_URL, api_key=KEY, environment="acme")


# ── Paths ───────────────────────────────────────────────────────────────────────────────────


def test_an_operation_keeps_its_method_and_takes_its_v1_path() -> None:
    fake = FakeApi(json_response({"object": "app", "id": "app_1", "name": "Acme"}))

    v1_env(fake).apps.get("app_1")

    assert fake.calls[0].method == "GET"
    assert fake.calls[0].url == f"{V1}/apps/app_1"
    assert fake.calls[0].headers["authorization"] == f"Bearer {KEY}"


def test_a_child_is_addressed_directly_and_its_parent_named_in_the_query() -> None:
    fake = FakeApi(httpx.Response(204))

    v1_env(fake).members.remove("org_1", "usr_1")

    call = fake.calls[0]
    assert call.method == "DELETE"
    assert urlsplit(call.url).path == "/v1/organization-memberships/usr_1"
    assert query(call.url) == {"organization_id": "org_1"}


def test_a_parent_named_id_is_renamed_in_the_query_and_the_body_still_travels() -> None:
    fake = FakeApi(json_response({"object": "access_review_item", "id": "item_1"}))

    v1_env(fake).access_reviews.items.decide("rev_1", "item_1", {"decision": "certify"})

    call = fake.calls[0]
    assert call.method == "POST"
    assert urlsplit(call.url).path == "/v1/access-review-items/item_1/decide"
    assert query(call.url) == {"access_review_id": "rev_1"}
    assert call.body == {"decision": "certify"}


def test_a_parent_the_v1_route_takes_in_the_body_is_sent_there() -> None:
    fake = FakeApi(httpx.Response(204))

    v1_env(fake).organizations.domains.remove("org_1", "dom_1")

    call = fake.calls[0]
    assert call.method == "DELETE"
    assert call.url == f"{V1}/organization-domains/dom_1"
    assert call.body == {"organization_id": "org_1"}


def test_a_changed_method_follows_the_v1_route() -> None:
    fake = FakeApi(json_response({"object": "organization_domain", "id": "dom_1"}))

    v1_env(fake).organizations.domains.capture("org_1", "dom_1", {"capture": True})

    call = fake.calls[0]
    assert ENVIRONMENT_OPERATIONS["organizations.domains.capture"].method == "PUT"
    assert call.method == "PATCH"
    assert call.url == f"{V1}/organization-domains/dom_1"
    assert call.body == {"capture": True, "organization_id": "org_1"}


def test_the_organization_plane_moves_to_its_own_v1_resources() -> None:
    fake = FakeApi(
        json_response({"object": "organization", "id": "org_1", "name": "Acme"}),
        httpx.Response(204),
    )
    client = OrganizationClient(
        api_url=API_URL, api_key="cbid_org_k", transport=fake.transport, retry=RetryOptions(0)
    )

    org = client.organization.get()
    client.keys.environment.revoke("env_1", "ekey_1")

    assert fake.calls[0].url == f"{V1}/organization"
    assert org.data == {"object": "organization", "id": "org_1", "name": "Acme"}
    assert fake.calls[0].headers["authorization"] == "Bearer cbid_org_k"
    assert urlsplit(fake.calls[1].url).path == "/v1/environment-keys/ekey_1"
    assert query(fake.calls[1].url) == {"environment_id": "env_1"}


def test_an_operation_without_a_v1_route_is_refused_before_any_request() -> None:
    fake = FakeApi()
    client = PlatformClient(api_url=API_URL, access_token="t", transport=fake.transport)

    assert PLATFORM_OPERATIONS["platform.workspaces.create"].legacy_only

    with pytest.raises(ConfigurationError, match="no /v1 route"):
        client.workspaces.create({"name": "Acme", "owner_email": "a@acme.test"})  # type: ignore[typeddict-item]

    assert fake.calls == []


def test_every_generated_operation_knows_its_v1_route() -> None:
    for table in (ENVIRONMENT_OPERATIONS, WORKSPACE_OPERATIONS, PLATFORM_OPERATIONS):
        for key, op in table.items():
            assert op.v1 is not None or op.legacy_only, key


def test_request_takes_a_path_relative_to_v1() -> None:
    fake = FakeApi(json_response({"object": "list", "data": [], "has_more": False}))

    v1_env(fake).request("GET", "/sod-policies", query={"limit": 5})

    assert fake.calls[0].url == f"{V1}/sod-policies?limit=5"


# ── Shapes ──────────────────────────────────────────────────────────────────────────────────


def test_an_object_is_not_wrapped_so_data_is_the_object() -> None:
    # An object may well have a field called `data`: it stays the object's field.
    body = {"object": "event", "id": "idevt_1", "data": {"user_id": "usr_1"}}
    fake = FakeApi(json_response(body))

    result = v1_env(fake).request("GET", "/events/idevt_1")

    assert result.data == body
    assert result.meta is None


def test_a_list_envelope_gives_its_items_and_the_paging_fields() -> None:
    fake = FakeApi(
        json_response(
            {"object": "list", "data": [{"id": "usr_1"}], "has_more": True, "next_cursor": "c2"}
        )
    )

    result = v1_env(fake).users.list()

    assert result.data == [{"id": "usr_1"}]
    assert result.meta == {"object": "list", "has_more": True, "next_cursor": "c2"}


def test_paging_follows_next_cursor_as_after() -> None:
    fake = FakeApi(
        json_response(
            {"object": "list", "data": [{"id": "usr_1"}], "has_more": True, "next_cursor": "c2"}
        ),
        json_response({"object": "list", "data": [{"id": "usr_2"}], "has_more": False}),
    )

    ids = [user["id"] for user in v1_env(fake).users.list_all({"limit": 1})]

    assert ids == ["usr_1", "usr_2"]
    assert query(fake.calls[1].url) == {"limit": "1", "after": "c2"}


def test_a_problem_document_becomes_the_same_typed_error() -> None:
    fake = FakeApi(
        httpx.Response(
            422,
            json={
                "type": "https://api.cboxid.com/problems/validation_failed",
                "title": "Unprocessable Content",
                "status": 422,
                "detail": "The name field is required.",
                "error": "validation_failed",
                "errors": {"name": ["The name field is required."]},
                "request_id": "req_1",
            },
            headers={"content-type": "application/problem+json"},
        )
    )

    with pytest.raises(CboxIdApiError) as caught:
        v1_env(fake).apps.create({})  # type: ignore[typeddict-item]

    assert caught.value.error == "validation_failed"
    assert str(caught.value.message) == "The name field is required."
    assert caught.value.errors == {"name": ["The name field is required."]}
    assert caught.value.request_id == "req_1"


def test_an_approval_held_on_v1_is_polled_and_the_request_repeated() -> None:
    approval = {
        "object": "approval",
        "id": "apr_1",
        "status": "pending",
        "binding_code": "42",
        "expires_at": "2099-01-01T00:00:00Z",
        "poll_url": f"{V1}/approvals/apr_1",
    }
    fake = FakeApi(
        json_response(approval, 202),
        json_response({**approval, "status": "approved"}),
        json_response({"object": "app_secret", "id": "sec_1"}),
    )
    seen: list[str] = []
    client = v1_env(fake, on_approval_required=lambda a, _ctx: seen.append(a.binding_code))

    result = client.apps.secrets.rotate("app_1", {"grace_seconds": 0})

    assert seen == ["42"]
    assert fake.calls[1].url == f"{V1}/approvals/apr_1"
    assert fake.calls[2].headers["cbox-approval"] == "apr_1"
    assert fake.calls[2].headers["idempotency-key"] == fake.calls[0].headers["idempotency-key"]
    assert result.data == {"object": "app_secret", "id": "sec_1"}


# ── Organization naming ─────────────────────────────────────────────────────────────────────


def test_organization_client_is_the_workspace_client_under_its_new_name() -> None:
    client = OrganizationClient(api_key="cbid_org_k")

    assert isinstance(client, WorkspaceClient)
    assert client.organization is client.workspace
    assert client.base_url == "https://api.cboxid.com/api/v1"


# ── Ids ─────────────────────────────────────────────────────────────────────────────────────


def test_a_prefixed_id_unwraps_to_the_raw_ulid() -> None:
    assert raw_id(f"org_{ULID}") == ULID.lower()
    assert raw_id(ULID.lower()) == ULID.lower()
    assert raw_id("org_1") == "org_1"
    assert raw_id("cbid_env_abc") == "cbid_env_abc"
    assert is_prefixed_id(f"usr_{ULID}")
    assert not is_prefixed_id(ULID)


def test_ids_match_with_and_without_their_prefix() -> None:
    assert same_id(f"org_{ULID}", ULID.lower())
    assert same_id(ULID, f"org_{ULID.lower()}")
    assert same_id("org_1", "org_1")
    assert not same_id("org_1", "1")
    assert not same_id(f"org_{ULID}", "01J9ZK3M4N5P6Q7R8S9T0VWXY0")
    assert not same_id(None, ULID)
    assert not same_id("", "")


def test_a_permission_decision_accepts_prefixed_ids_for_the_raw_ones_asked() -> None:
    subject, organization = ULID.lower(), "01j9zk3m4n5p6q7r8s9t0vwxy0"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "mode": "rbac",
                "subject": {"type": "user", "id": f"usr_{subject.upper()}"},
                "organization": f"org_{organization.upper()}",
                "client_id": "app-a",
                "org_role": "member",
                "organization_active": True,
                "allowed": True,
                "results": [{"permission": "documents:read", "allowed": True}],
            },
        )

    sdk = CboxIdClient(
        CboxIdConfig(
            issuer="https://id.example.test",
            client_id="app-a",
            redirect_uri="https://app.example.test/callback",
        ),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    decision = sdk.check_permissions("token", subject, organization, ["documents:read"])

    assert decision.allowed()
    assert decision.subject == subject


# ── Event names ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("legacy", "current"),
    [
        ("organization.member_added", "id.organization.member_added"),
        ("user.login", "id.user.signed_in"),
        ("directory.user.provisioned", "id.directory.user.provisioned"),
    ],
)
def test_an_event_has_its_old_name_and_its_id_name(legacy: str, current: str) -> None:
    assert current_event_name(legacy) == current
    assert current_event_name(current) == current
    assert legacy_event_name(current) == legacy
    assert legacy_event_name(legacy) == legacy
    assert same_event(legacy, current)
    assert same_event(current, legacy)
    assert event_name_aliases(legacy) == (legacy, current)
    assert event_name_aliases(current) == (current, legacy)


def test_different_events_stay_different() -> None:
    assert not same_event("user.login", "id.user.created")
    assert not same_event("user.created", "user.deleted")
    assert current_event_name("*") == "*"


# ── Manifest and Pipes on api_url ───────────────────────────────────────────────────────────

ISSUER = "https://id.example.test"


def sdk(handler: Any, **config: Any) -> CboxIdClient:
    return CboxIdClient(
        CboxIdConfig(
            issuer=ISSUER,
            client_id="cid_app",
            client_secret="secret",
            redirect_uri="https://app.example.test/callback",
            **config,
        ),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


@pytest.mark.parametrize(
    ("api_url", "expected"),
    [(None, f"{ISSUER}/api/v1/apps/manifest"), (API_URL, f"{V1}/app-manifests")],
)
def test_the_manifest_goes_to_v1_only_when_api_url_is_set(
    api_url: str | None, expected: str
) -> None:
    manifest = AuthzManifest()
    manifest.permission("documents.read", "Read documents")
    posted: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": ISSUER,
                    "token_endpoint": f"{ISSUER}/oauth/token",
                    "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
                    "authorization_endpoint": f"{ISSUER}/oauth/authorize",
                },
            )
        if url == f"{ISSUER}/oauth/token":
            return httpx.Response(200, json={"access_token": "m"})
        posted.append(url)
        sent = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "unchanged": False,
                "roles_declared": 0,
                "permissions_declared": 1,
                "client_id": "cid_app",
                "version": sent["version"],
                "checksum": manifest.checksum(),
            },
        )

    sdk(handler, api_url=api_url).publish_manifest(manifest)

    assert posted == [expected]


def test_a_pipe_lease_on_v1_is_a_resource_with_the_provider_in_the_body() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"access_token": "gho_abc", "provider": "github"})

    client = PipesClient(
        ISSUER,
        "app-token",
        api_url=f"{API_URL}/v1",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    token = client.lease_token("github", user_id="usr_1", purpose="list-repos")

    assert str(requests[0].url) == f"{V1}/pipe-leases"
    assert json.loads(requests[0].content) == {
        "provider": "github",
        "purpose": "list-repos",
        "user_id": "usr_1",
    }
    assert token.access_token == "gho_abc"


def test_a_pipe_problem_keeps_its_type_and_detail() -> None:
    connect = f"{ISSUER}/account/connected-services/github/connect"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            404,
            json={
                "type": "https://api.cboxid.com/problems/pipe_not_connected",
                "title": "Not Found",
                "status": 404,
                "detail": "Connect GitHub first.",
                "error": "pipe_not_connected",
                "connect_url": connect,
            },
        )

    client = PipesClient(
        ISSUER,
        "app-token",
        api_url=API_URL,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    with pytest.raises(PipeNotConnectedError) as caught:
        client.lease_token("github", purpose="x")

    assert str(caught.value) == "Connect GitHub first."
    assert caught.value.connect_url == connect


def test_the_client_pipes_follow_the_config_api_url() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no request expected")

    assert sdk(handler).pipes._v1 is None
    assert sdk(handler, api_url=API_URL).pipes._v1 == V1


def test_an_api_url_that_is_not_https_is_refused_up_front() -> None:
    with pytest.raises(ConfigurationError, match="`api_url` must be https"):
        sdk(lambda r: httpx.Response(500), api_url="http://api.cboxid.com")
