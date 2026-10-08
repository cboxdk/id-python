"""The management clients: requests, idempotency, approvals, errors, paging, credentials."""

from __future__ import annotations

import base64
import hashlib
import inspect
import os
import re
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from typing_extensions import assert_type

from cbox_id.management import (
    ACCOUNT_OPERATIONS,
    ENVIRONMENT_OPERATIONS,
    PLATFORM_OPERATIONS,
    WORKSPACE_OPERATIONS,
    AccountClient,
    ApiResponse,
    ApprovalContext,
    ApprovalDeniedError,
    ApprovalExpiredError,
    CboxIdApiError,
    CboxIdError,
    ConfigurationError,
    EnvironmentClient,
    ES256DPoPSigner,
    ManagementClient,
    ManagementNetworkError,
    PendingApproval,
    PendingApprovalResult,
    PlatformClient,
    RetryOptions,
    WorkspaceClient,
    generate_dpop_key,
)
from cbox_id.management.generated.environment import App, AppSecret, Organization
from scripts.generate_management import generate_all

from .management_helpers import (
    API,
    HOST,
    KEY,
    FakeApi,
    approval_status,
    env_client,
    held,
    json_response,
)

APP = {"id": "app_1", "client_id": "cid", "name": "Billing"}
UUID4 = r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"


# ── Requests ─────────────────────────────────────────────────────────────────────────────


def test_sends_the_key_as_a_bearer_token_and_unwraps_the_envelope() -> None:
    fake = FakeApi(json_response({"data": APP}, 201))
    result = env_client(fake).apps.create({"name": "Billing", "type": "web"})

    call = fake.calls[0]
    assert call.url == f"{API}/apps"
    assert call.method == "POST"
    assert call.headers["authorization"] == f"Bearer {KEY}"
    assert call.headers["content-type"] == "application/json"
    assert call.body == {"name": "Billing", "type": "web"}
    assert result.status == 201
    assert dict(result.data) == APP
    assert_type(result, ApiResponse[App])
    assert result.replayed is False
    assert result.pending is False


def test_path_parameters_are_encoded_in_order_and_get_input_goes_in_the_query() -> None:
    fake = FakeApi(
        json_response({"data": [], "meta": {"has_more": False}}),
        json_response({"data": []}),
    )
    client = env_client(fake)

    client.members.list("org/1", {"limit": 5})
    client.roles.list({"client_id": "cid", "organization_id": "org_1"})

    assert fake.calls[0].url == f"{API}/organizations/org%2F1/members?limit=5"
    assert "idempotency-key" not in fake.calls[0].headers
    assert fake.calls[1].url == f"{API}/roles?client_id=cid&organization_id=org_1"


def test_query_lists_and_booleans_take_the_shape_laravel_reads() -> None:
    fake = FakeApi(json_response({"data": []}))
    env_client(fake).request(
        "GET", "/things", query={"ids": ["a", "b"], "active": True, "gone": False, "skip": None}
    )

    assert fake.calls[0].url == f"{API}/things?ids%5B%5D=a&ids%5B%5D=b&active=1&gone=0"


def test_a_204_has_no_data() -> None:
    fake = FakeApi(httpx.Response(204))
    result = env_client(fake).apps.delete("app_1")

    assert result.status == 204
    assert result.data is None


# ── Idempotency and retries ──────────────────────────────────────────────────────────────


def test_a_write_reuses_one_generated_idempotency_key_on_every_retry() -> None:
    fake = FakeApi(
        json_response({"error": "server_error", "message": "Boom."}, 503),
        httpx.ConnectError("connection refused"),
        json_response(
            {"error": "rate_limited", "message": "Slow down."}, 429, {"Retry-After": "0"}
        ),
        json_response({"data": APP}, 201, {"Idempotent-Replayed": "true"}),
    )
    result = env_client(fake).apps.create({"name": "Billing"})

    assert len(fake.calls) == 4
    keys = {call.headers["idempotency-key"] for call in fake.calls}
    assert len(keys) == 1
    (key,) = keys
    assert re.match(UUID4, key)
    assert all(call.body == {"name": "Billing"} for call in fake.calls)
    assert result.replayed is True
    assert result.idempotency_key == key


def test_uses_the_callers_key_and_a_fresh_one_per_call_otherwise() -> None:
    fake = FakeApi(*(json_response({"data": APP}, 201) for _ in range(3)))
    client = env_client(fake)

    client.apps.create({"name": "A"}, idempotency_key="mine-1")
    client.apps.create({"name": "A"})
    client.apps.create({"name": "A"})

    assert fake.calls[0].headers["idempotency-key"] == "mine-1"
    assert fake.calls[1].headers["idempotency-key"] != fake.calls[2].headers["idempotency-key"]


def test_waits_out_409_idempotency_in_progress_with_the_same_key() -> None:
    fake = FakeApi(
        json_response(
            {"error": "idempotency_in_progress", "message": "Still running."},
            409,
            {"Retry-After": "0"},
        ),
        json_response({"data": APP}, 201, {"Idempotent-Replayed": "true"}),
    )
    result = env_client(fake).apps.create({"name": "A"})

    assert fake.calls[0].headers["idempotency-key"] == fake.calls[1].headers["idempotency-key"]
    assert result.replayed is True


def test_honours_retry_after_and_never_waits_longer_than_max_delay() -> None:
    fake = FakeApi(
        json_response({"error": "rate_limited", "message": "Slow."}, 429, {"Retry-After": "7"}),
        json_response({"data": []}),
    )
    client = env_client(fake, retry=RetryOptions(base_delay=0, max_delay=10))
    slept: list[float] = []
    client.core.sleep = slept.append

    client.apps.list()

    assert slept == [7.0]


def test_does_not_retry_a_4xx_and_gives_up_after_max_retries() -> None:
    conflict = FakeApi(json_response({"error": "slug_taken", "message": "Taken."}, 409))

    with pytest.raises(CboxIdApiError) as caught:
        env_client(conflict).organizations.create({"name": "Acme", "slug": "acme"})

    assert caught.value.status == 409
    assert caught.value.error == "slug_taken"
    assert len(conflict.calls) == 1

    down = FakeApi(httpx.ConnectError("a"), httpx.ConnectError("b"), httpx.ConnectError("c"))

    with pytest.raises(ManagementNetworkError) as network:
        env_client(down, retry=RetryOptions(max_retries=2, base_delay=0)).apps.create(
            {"name": "A"}, idempotency_key="k-1"
        )

    assert network.value.idempotency_key == "k-1"
    assert isinstance(network.value.__cause__, httpx.ConnectError)
    assert len(down.calls) == 3


def test_raises_a_429_at_once_when_retry_after_is_longer_than_it_may_wait() -> None:
    fake = FakeApi(
        json_response(
            {"error": "rate_limited", "message": "Slow down."}, 429, {"Retry-After": "120"}
        )
    )

    with pytest.raises(CboxIdApiError) as caught:
        env_client(fake).apps.list()

    assert caught.value.status == 429
    assert caught.value.retry_after == 120
    assert len(fake.calls) == 1


# ── Errors ───────────────────────────────────────────────────────────────────────────────


def test_types_a_validation_failure_and_never_echoes_the_request_body() -> None:
    fake = FakeApi(
        json_response(
            {
                "error": "validation_failed",
                "message": "The given data was invalid.",
                "errors": {"name": ["The name field is required."]},
                "request_id": "req_42",
            },
            422,
            {"X-Request-Id": "req_from_header"},
        )
    )

    with pytest.raises(CboxIdApiError) as caught:
        env_client(fake).users.create({"email": "a@b.test", "password": "hunter2-secret"})

    error = caught.value
    assert error.status == 422
    assert error.error == "validation_failed"
    assert error.is_validation_error is True
    assert error.message == "The given data was invalid."
    assert str(error) == "The given data was invalid."
    assert error.errors == {"name": ["The name field is required."]}
    assert error.request_id == "req_42"
    assert "hunter2" not in repr(error) and "hunter2" not in str(error)
    assert isinstance(error, CboxIdError)


def test_falls_back_to_the_x_request_id_header() -> None:
    fake = FakeApi(
        httpx.Response(404, text="<html>Not found</html>", headers={"X-Request-Id": "req_7"})
    )

    with pytest.raises(CboxIdApiError) as caught:
        env_client(fake).apps.get("app_1")

    assert caught.value.status == 404
    assert caught.value.request_id == "req_7"


def test_reads_a_bearer_challenge_and_a_non_json_body() -> None:
    challenge = FakeApi(
        json_response({"error": "invalid_token", "error_description": "Expired."}, 401)
    )

    with pytest.raises(CboxIdApiError) as caught:
        env_client(challenge).apps.list()

    assert (caught.value.error, caught.value.message, caught.value.status) == (
        "invalid_token",
        "Expired.",
        401,
    )

    html = FakeApi(httpx.Response(403, text="<html>Forbidden</html>"))

    with pytest.raises(CboxIdApiError) as forbidden:
        env_client(html).apps.list()

    assert (forbidden.value.error, forbidden.value.message) == ("http_403", "HTTP 403")


# ── Approvals ────────────────────────────────────────────────────────────────────────────


def test_shows_the_binding_code_polls_then_repeats_with_cbox_approval_and_the_same_key() -> None:
    secret = {"id": "sec_2", "secret": "cbid_secret_shown_once", "ends_with": "once"}
    fake = FakeApi(
        held(),
        approval_status("pending"),
        approval_status("approved"),
        json_response({"data": secret}, 201),
    )
    seen: list[tuple[PendingApproval, ApprovalContext]] = []
    client = env_client(fake, on_approval_required=lambda a, c: seen.append((a, c)))

    result = client.apps.secrets.rotate("app_1", {"grace_seconds": 3600})

    assert len(seen) == 1
    approval, context = seen[0]
    assert (approval.id, approval.binding_code) == ("apr_1", "K7-4Q")
    assert (context.action, context.danger) == ("apps.secrets.rotate", "critical")
    assert [f"{c.method} {c.url}" for c in fake.calls] == [
        f"POST {API}/apps/app_1/secrets",
        f"GET {API}/action-approvals/apr_1",
        f"GET {API}/action-approvals/apr_1",
        f"POST {API}/apps/app_1/secrets",
    ]
    assert "cbox-approval" not in fake.calls[0].headers
    assert fake.calls[1].headers["authorization"] == f"Bearer {KEY}"
    assert fake.calls[3].headers["cbox-approval"] == "apr_1"
    assert fake.calls[3].headers["idempotency-key"] == fake.calls[0].headers["idempotency-key"]
    assert fake.calls[3].body == {"grace_seconds": 3600}
    assert_type(result, ApiResponse[AppSecret])
    assert result.data == secret


def test_raises_a_typed_error_when_the_person_denies_it_or_nobody_answers() -> None:
    denied = FakeApi(held(), approval_status("denied"))

    with pytest.raises(ApprovalDeniedError):
        env_client(denied).apps.secrets.rotate("app_1", {"grace_seconds": 0})

    assert len(denied.calls) == 2

    expired = FakeApi(held(), approval_status("expired"))

    with pytest.raises(ApprovalExpiredError) as caught:
        env_client(expired).apps.secrets.rotate("app_1", {"grace_seconds": 0})

    assert caught.value.approval.id == "apr_1"
    assert caught.value.reason == "expired"


def test_return_mode_hands_back_the_pending_approval_and_resume_finishes() -> None:
    fake = FakeApi(
        held(), approval_status("approved"), json_response({"data": {"id": "sec_3"}}, 201)
    )
    seen: list[PendingApproval] = []
    client = env_client(fake, on_approval_required=lambda a, _: seen.append(a))

    outcome = client.apps.secrets.rotate("app_1", {"grace_seconds": 0}, approval="return")

    assert_type(outcome, ApiResponse[AppSecret] | PendingApprovalResult[AppSecret])
    assert isinstance(outcome, PendingApprovalResult)
    assert outcome.pending is True
    assert outcome.status == 202
    assert outcome.approval.binding_code == "K7-4Q"
    assert outcome.action == "apps.secrets.rotate"
    assert len(fake.calls) == 1
    assert seen == []

    done = outcome.resume()

    assert_type(done, ApiResponse[AppSecret])
    assert done.data == {"id": "sec_3"}
    assert fake.calls[2].headers["cbox-approval"] == "apr_1"
    assert fake.calls[2].headers["idempotency-key"] == outcome.idempotency_key


def test_never_sends_the_credential_to_a_poll_url_on_another_origin() -> None:
    fake = FakeApi(held("apr_1", "https://evil.test/api/v1/action-approvals/apr_1"))

    with pytest.raises(CboxIdError, match="another origin"):
        env_client(fake).apps.secrets.rotate("app_1", {"grace_seconds": 0})

    assert len(fake.calls) == 1


def test_polls_the_workspace_planes_own_approval_route() -> None:
    fake = FakeApi(
        held("apr_9", "https://api.cboxid.test/api/v1/workspace/action-approvals/apr_9"),
        approval_status("approved", "apr_9"),
        httpx.Response(204),
    )
    ws = WorkspaceClient(
        base_url="https://api.cboxid.test",
        api_key="cbid_ws_k",
        transport=fake.transport,
        retry=RetryOptions(base_delay=0),
        approval_poll_interval=0,
    )
    ws.keys.workspace.revoke("wk_1")

    assert fake.calls[1].url == "https://api.cboxid.test/api/v1/workspace/action-approvals/apr_9"
    assert fake.calls[2].headers["cbox-approval"] == "apr_9"


def test_a_relative_poll_url_and_a_missing_one_resolve_on_the_planes_own_host() -> None:
    fake = FakeApi(
        held("apr_2", "/api/v1/action-approvals/apr_2"),
        approval_status("approved", "apr_2"),
        json_response({"data": {"id": "sec"}}, 201),
    )
    env_client(fake).apps.secrets.rotate("app_1", {"grace_seconds": 0})

    assert fake.calls[1].url == f"{API}/action-approvals/apr_2"


# ── Pagination ───────────────────────────────────────────────────────────────────────────


def test_follows_next_cursor_on_a_cursor_paged_list() -> None:
    fake = FakeApi(
        json_response(
            {
                "data": [{"id": "o1"}, {"id": "o2"}],
                "meta": {"limit": 2, "has_more": True, "next_cursor": "c2"},
            }
        ),
        json_response(
            {"data": [{"id": "o3"}], "meta": {"limit": 2, "has_more": False, "next_cursor": None}}
        ),
    )
    ids = [org["id"] for org in env_client(fake).organizations.list_all({"limit": 2})]

    assert ids == ["o1", "o2", "o3"]
    assert fake.calls[0].url == f"{API}/organizations?limit=2"
    assert fake.calls[1].url == f"{API}/organizations?limit=2&after=c2"


def test_list_all_yields_typed_items() -> None:
    fake = FakeApi(json_response({"data": [{"id": "o1"}], "meta": {"has_more": False}}))

    for org in env_client(fake).organizations.list_all():
        assert_type(org, Organization)


def test_follows_next_page_on_a_numbered_list_and_stops_when_has_more_is_false() -> None:
    fake = FakeApi(
        json_response(
            {"data": [{"id": "m1"}], "meta": {"page": 1, "has_more": True, "next_page": 2}}
        ),
        json_response(
            {"data": [{"id": "m2"}], "meta": {"page": 2, "has_more": False, "next_page": None}}
        ),
    )
    ws = WorkspaceClient(api_key="cbid_ws_k", transport=fake.transport)
    ids = [member["id"] for member in ws.team.list_all()]

    assert ids == ["m1", "m2"]
    assert fake.calls[0].url == "https://api.cboxid.com/api/v1/workspace/members"
    assert fake.calls[1].url == "https://api.cboxid.com/api/v1/workspace/members?page=2"


def test_stops_reading_pages_when_the_caller_breaks_out() -> None:
    fake = FakeApi(
        json_response(
            {"data": [{"id": "u1"}, {"id": "u2"}], "meta": {"has_more": True, "next_cursor": "x"}}
        )
    )

    for user in env_client(fake).users.list_all():
        assert user["id"] == "u1"
        break

    assert len(fake.calls) == 1


# ── Credentials ──────────────────────────────────────────────────────────────────────────


def test_refuses_a_key_from_the_wrong_plane_a_key_where_none_is_accepted_and_plain_http() -> None:
    with pytest.raises(ConfigurationError):
        EnvironmentClient(base_url=HOST, api_key="cbid_ws_x")
    with pytest.raises(ConfigurationError):
        WorkspaceClient(api_key="cbid_env_x")
    with pytest.raises(ConfigurationError, match="accepts no management key"):
        PlatformClient(api_key="cbid_ws_x")
    with pytest.raises(ConfigurationError):
        AccountClient(base_url=HOST, api_key="cbid_env_x")
    with pytest.raises(ConfigurationError, match="https"):
        EnvironmentClient(base_url="http://acme.test", api_key=KEY)
    with pytest.raises(ConfigurationError, match="exactly one"):
        EnvironmentClient(base_url=HOST)
    with pytest.raises(ConfigurationError, match="base_url"):
        EnvironmentClient(api_key=KEY)

    EnvironmentClient(base_url="http://localhost:8000", api_key=KEY).close()


def test_drives_any_environment_from_the_platform_root_with_one_token() -> None:
    fake = FakeApi(
        json_response({"data": []}),
        held("apr_1", "https://api.cboxid.test/api/v1/action-approvals/apr_1"),
        approval_status("approved"),
        json_response({"data": APP}, 201),
    )
    root = EnvironmentClient(
        base_url="https://api.cboxid.test",
        access_token="root_token",
        environment="acme-staging",
        transport=fake.transport,
        approval_poll_interval=0,
    )

    root.apps.list()
    root.apps.create({"name": "A"})

    assert fake.calls[0].url == "https://api.cboxid.test/api/v1/apps"
    assert len(fake.calls) == 4
    assert fake.calls[3].headers["cbox-approval"] == "apr_1"
    assert all(c.headers["cbox-environment"] == "acme-staging" for c in fake.calls)
    assert all(c.headers["authorization"] == "Bearer root_token" for c in fake.calls)


def test_a_key_never_sends_cbox_environment() -> None:
    fake = FakeApi(json_response({"data": []}))
    env_client(fake).apps.list()

    assert "cbox-environment" not in fake.calls[0].headers


def test_refuses_environment_with_a_key_or_on_another_plane() -> None:
    with pytest.raises(ConfigurationError):
        EnvironmentClient(base_url=HOST, api_key=KEY, environment="acme")
    with pytest.raises(ConfigurationError, match="environment plane"):
        WorkspaceClient(access_token="t", environment="acme")


def test_calls_a_token_provider_before_every_request() -> None:
    fake = FakeApi(json_response({"data": {}}), json_response({"data": {}}))
    tokens = iter(["tok_1", "tok_2"])
    client = AccountClient(
        base_url=f"{HOST}/api/v1/", access_token=lambda: next(tokens), transport=fake.transport
    )

    client.request("GET", "/me/profile")
    client.request("GET", "/me/profile")

    assert fake.calls[0].url == f"{API}/me/profile"
    assert [c.headers["authorization"] for c in fake.calls] == ["Bearer tok_1", "Bearer tok_2"]


def test_extra_headers_cannot_override_authorization() -> None:
    fake = FakeApi(json_response({"data": []}))
    client = env_client(fake, headers={"User-Agent": "acme/1", "Authorization": "Bearer stolen"})

    client.apps.list(headers={"X-Trace": "t1"})

    assert fake.calls[0].headers["user-agent"] == "acme/1"
    assert fake.calls[0].headers["x-trace"] == "t1"
    assert fake.calls[0].headers["authorization"] == f"Bearer {KEY}"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def test_presents_a_dpop_bound_token_with_a_proof_that_pins_method_url_and_token() -> None:
    signer = ES256DPoPSigner(generate_dpop_key())
    fake = FakeApi(json_response({"data": APP}, 201))
    client = EnvironmentClient(
        base_url=HOST, access_token="at_123", dpop=signer, transport=fake.transport
    )

    client.apps.create({"name": "A"})

    call = fake.calls[0]
    assert call.headers["authorization"] == "DPoP at_123"
    proof = call.headers["dpop"]
    header = jwt.get_unverified_header(proof)
    assert header["typ"] == "dpop+jwt"
    key = jwt.PyJWK(header["jwk"], "ES256")
    payload = jwt.decode(proof, key.key, algorithms=["ES256"])
    assert payload["htm"] == "POST"
    assert payload["htu"] == f"{API}/apps"
    assert payload["ath"] == _b64url(hashlib.sha256(b"at_123").digest())
    assert isinstance(payload["jti"], str)


def test_answers_a_dpop_nonce_challenge_once_with_the_nonce_in_the_next_proof() -> None:
    signer = ES256DPoPSigner(generate_dpop_key())
    fake = FakeApi(
        json_response(
            {"error": "use_dpop_nonce", "error_description": "Nonce required."},
            401,
            {"DPoP-Nonce": "n-1"},
        ),
        json_response({"data": []}),
    )
    EnvironmentClient(
        base_url=HOST, access_token="at", dpop=signer, transport=fake.transport
    ).apps.list()

    first = jwt.decode(fake.calls[0].headers["dpop"], options={"verify_signature": False})
    second = jwt.decode(fake.calls[1].headers["dpop"], options={"verify_signature": False})
    assert "nonce" not in first
    assert second["nonce"] == "n-1"


def test_closes_only_a_client_it_created() -> None:
    mine = httpx.Client()
    with EnvironmentClient(base_url=HOST, api_key=KEY, http_client=mine) as client:
        assert isinstance(client, EnvironmentClient)

    assert not mine.is_closed
    mine.close()


# ── Generated surface ────────────────────────────────────────────────────────────────────


def test_names_methods_after_x_action_with_the_specs_method_path_scope_and_danger() -> None:
    client = env_client(FakeApi())

    assert callable(client.apps.create)
    assert callable(client.apps.secrets.rotate)
    assert callable(client.sso.connections.require_sso)
    assert callable(client.sso.saml_metadata.import_)
    assert callable(client.organizations.list_all)
    assert callable(WorkspaceClient(api_key="cbid_ws_k").environments.create)
    # The account and platform planes prefix every action with the plane; the client drops it.
    assert callable(AccountClient(base_url=HOST, access_token="t").sessions.revoke_others)
    assert callable(PlatformClient(access_token="t").workspaces.create)

    apps_create = ENVIRONMENT_OPERATIONS["apps.create"]
    assert (apps_create.method, apps_create.path, apps_create.scope, apps_create.danger) == (
        "POST",
        "/apps",
        "apps:write",
        "critical",
    )
    rotate = ENVIRONMENT_OPERATIONS["apps.secrets.rotate"]
    assert rotate.action == "apps.secrets.rotate"
    assert rotate.operation_id == "apps_secrets_rotate"
    assert (rotate.method, rotate.path, rotate.path_params) == (
        "POST",
        "/apps/{id}/secrets",
        ("id",),
    )
    assert rotate.approval is True
    assert ENVIRONMENT_OPERATIONS["organizations.list"].pagination == "cursor"
    grant = ENVIRONMENT_OPERATIONS["members.roles.grant"]
    assert grant.method == "PUT"
    assert grant.path_params == ("organization_id", "user_id", "role_id")
    environments = WORKSPACE_OPERATIONS["environments.create"]
    assert (environments.path, environments.scope, environments.danger) == (
        "/workspace/environments",
        "environments:write",
        "critical",
    )
    assert WORKSPACE_OPERATIONS["team.list"].pagination == "page"
    events = ENVIRONMENT_OPERATIONS["audit_logs.events.create"]
    assert (events.path, events.scope, events.danger) == (
        "/audit-logs/events",
        "audit_logs:write",
        "write",
    )
    assert ENVIRONMENT_OPERATIONS["audit_logs.verify"].scope == "audit_logs:read"


def test_every_action_carries_its_scope() -> None:
    """From ``x-scope``, or the description's "Requires scope" for a hand-written route."""
    tables = [ENVIRONMENT_OPERATIONS, WORKSPACE_OPERATIONS, PLATFORM_OPERATIONS, ACCOUNT_OPERATIONS]
    actions = [op for table in tables for op in table.values() if op.action is not None]

    assert actions
    assert [op.action for op in actions if op.scope is None] == []

    scheme = ENVIRONMENT_OPERATIONS["webhooks.signature_scheme.change"]
    assert (scheme.method, scheme.path, scheme.scope, scheme.danger) == (
        "POST",
        "/webhooks/{id}/signature-scheme",
        "webhooks:write",
        "destructive",
    )
    links = ENVIRONMENT_OPERATIONS["organizations.portal_links.revoke"]
    assert links.method == "DELETE"
    assert links.path_params == ("organization_id", "id")


def test_generated_code_is_exactly_what_the_generator_makes_of_the_vendored_specs() -> None:
    """Regenerate with ``python -m scripts.generate_management``."""
    for path, result in generate_all().items():
        assert path.read_text("utf-8") == result.code, f"{path.name} is stale"


SNAPSHOT = Path(__file__).parent / "fixtures" / "management_surface.txt"


def _surface(prefix: str, namespace: object) -> list[str]:
    lines: list[str] = []

    for name, member in sorted(vars(type(namespace)).items()):
        if name.startswith("_") or not inspect.isfunction(member):
            continue

        signature = inspect.signature(member)
        params: list[str] = []
        star = False

        for param in list(signature.parameters.values())[1:]:
            if param.kind is param.KEYWORD_ONLY and not star:
                params.append("*")
                star = True

            params.append(param.name if param.default is param.empty else f"{param.name}=")

        returns = signature.return_annotation
        lines.append(f"{prefix}.{name}({', '.join(params)}) -> {returns}")

    for name, child in sorted(vars(namespace).items()):
        if not name.startswith("_"):
            lines.extend(_surface(f"{prefix}.{name}", child))

    return lines


def test_generated_surface_matches_the_snapshot() -> None:
    """Every public method of every plane. Refresh with ``UPDATE_SNAPSHOTS=1 pytest``."""
    clients: list[tuple[str, ManagementClient]] = [
        ("environment", EnvironmentClient(base_url=HOST, api_key=KEY)),
        ("workspace", WorkspaceClient(api_key="cbid_ws_k")),
        ("platform", PlatformClient(access_token="t")),
        ("account", AccountClient(base_url=HOST, access_token="t")),
    ]
    lines: list[str] = []

    for plane, client in clients:
        for name, namespace in sorted(vars(client).items()):
            if name != "core":
                lines.extend(_surface(f"{plane}.{name}", namespace))

    surface = "\n".join(lines) + "\n"

    if os.environ.get("UPDATE_SNAPSHOTS"):
        SNAPSHOT.write_text(surface, "utf-8")

    assert surface == SNAPSHOT.read_text("utf-8")


def test_a_call_with_a_plain_operation_spec_runs_through_the_same_core() -> None:
    fake = FakeApi(json_response({"data": {"ok": True}}))
    client = env_client(fake)
    result: Any = client.core.call(ENVIRONMENT_OPERATIONS["apps.get"], ["app_1"])

    assert isinstance(result, ApiResponse)
    assert fake.calls[0].url == f"{API}/apps/app_1"
