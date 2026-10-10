"""Pipes: leasing a person's connected-account token, and the typed refusals."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from cbox_id import (
    PipeLeaseDeniedError,
    PipeLeaseError,
    PipeNotConnectedError,
    PipeReauthorizationRequiredError,
    PipesClient,
    PipeTemporarilyUnavailableError,
    pipe_connect_url,
)

from .conftest import CLIENT_ID, ISSUER, FakeInstance

CONNECT = f"{ISSUER}/account/connected-services/github/connect"
LEASE = {
    "access_token": "gho_abc",
    "token_type": "Bearer",
    "provider": "github",
    "user_id": "usr_1",
    "connection_id": "con_1",
    "scopes": ["read:user", "repo"],
    "expires_at": None,
    "lease_expires_at": "2026-10-09T14:05:00+00:00",
    "metadata": {},
}


class Recorder:
    def __init__(self, status: int, body: Any, headers: dict[str, str] | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self.status = status
        self.body = body
        self.headers = headers or {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if isinstance(self.body, str):
            return httpx.Response(self.status, text=self.body, headers=self.headers)
        return httpx.Response(self.status, json=self.body, headers=self.headers)


def pipes(recorder: Recorder, token: str = "app-token") -> PipesClient:
    http = httpx.Client(transport=httpx.MockTransport(recorder))
    return PipesClient(ISSUER, token, client_id="cid_1", http_client=http)


def test_leases_a_token_for_a_named_person() -> None:
    recorder = Recorder(200, LEASE)

    token = pipes(recorder).lease_token("github", user_id="usr_1", purpose="list-repos")

    request = recorder.requests[0]
    assert str(request.url) == f"{ISSUER}/api/v1/vault/pipes/github/token"
    assert request.method == "POST"
    assert request.headers["authorization"] == "Bearer app-token"
    assert json.loads(request.content) == {"purpose": "list-repos", "user_id": "usr_1"}
    assert token.access_token == "gho_abc"
    assert token.scopes == ["read:user", "repo"]
    assert token.expires_at is None
    assert token.lease_expires_at == "2026-10-09T14:05:00+00:00"


def test_leaves_user_id_out_for_a_token_issued_for_the_person() -> None:
    recorder = Recorder(200, {**LEASE, "metadata": {"instance_url": "https://acme.sf.com"}})

    token = pipes(recorder, "user-token").lease_token("salesforce", purpose="sync")

    assert json.loads(recorder.requests[0].content) == {"purpose": "sync"}
    assert token.metadata == {"instance_url": "https://acme.sf.com"}


def test_not_connected_carries_the_connect_url() -> None:
    body = {"error": "not_connected", "message": "Not connected.", "connect_url": CONNECT}

    with pytest.raises(PipeNotConnectedError) as raised:
        pipes(Recorder(404, body)).lease_token("github", user_id="u", purpose="p")

    error = raised.value
    assert isinstance(error, PipeLeaseError)
    assert error.status == 404
    assert error.error == "not_connected"
    assert error.connect_url == CONNECT
    assert error.connect_url_with(client_id="cid_1", return_to="https://app.test/s") == (
        f"{CONNECT}?client_id=cid_1&return_to=https%3A%2F%2Fapp.test%2Fs"
    )


def test_a_provider_that_needs_reconnecting_is_typed() -> None:
    body = {"error": "reauthorization_required", "message": "Again.", "connect_url": CONNECT}

    with pytest.raises(PipeReauthorizationRequiredError) as raised:
        pipes(Recorder(409, body)).lease_token("github", purpose="p")

    assert raised.value.connect_url == CONNECT


def test_unavailable_carries_retry_after() -> None:
    recorder = Recorder(503, {"error": "temporarily_unavailable"}, {"Retry-After": "30"})

    with pytest.raises(PipeTemporarilyUnavailableError) as raised:
        pipes(recorder).lease_token("google", purpose="p")

    assert raised.value.retry_after == 30


def test_a_denied_lease_is_typed_and_a_missing_scope_is_not() -> None:
    with pytest.raises(PipeLeaseDeniedError) as denied:
        pipes(Recorder(403, {"error": "lease_denied"})).lease_token("github", purpose="p")
    assert denied.value.connect_url_with(client_id="c") is None

    with pytest.raises(PipeLeaseError) as scope:
        pipes(Recorder(403, {"error": "insufficient_scope"})).lease_token("github", purpose="p")
    assert not isinstance(scope.value, PipeLeaseDeniedError)
    assert scope.value.error == "insufficient_scope"


def test_survives_a_body_that_is_not_json() -> None:
    with pytest.raises(PipeLeaseError) as raised:
        pipes(Recorder(502, "<html>bad gateway</html>")).lease_token("github", purpose="p")

    assert raised.value.status == 502
    assert "html" not in str(raised.value)


def test_the_client_leases_with_its_own_cached_vault_lease_token(fake: FakeInstance) -> None:
    seen: list[str] = []
    grants: list[str] = []
    original = fake.http._transport

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/api/v1/vault/pipes/"):
            seen.append(request.headers["authorization"])
            return httpx.Response(200, json=LEASE)
        if request.url.path == "/oauth/token":
            grants.append(request.content.decode())
            return httpx.Response(200, json={"access_token": "lease-token", "expires_in": 3600})
        return original.handle_request(request)

    fake.http._transport = httpx.MockTransport(handler)

    fake.client.pipes.lease_token("github", user_id="u", purpose="p")
    fake.client.pipes.lease_token("github", user_id="u", purpose="p")

    assert seen == ["Bearer lease-token", "Bearer lease-token"]
    assert len(grants) == 1
    assert "scope=vault.lease" in grants[0]


def test_connect_urls(fake: FakeInstance) -> None:
    assert pipe_connect_url(
        f"{ISSUER}/", "github", client_id="cid_1", return_to="https://a.test/x"
    ) == (f"{CONNECT}?client_id=cid_1&return_to=https%3A%2F%2Fa.test%2Fx")
    assert pipe_connect_url(ISSUER, "notion") == (
        f"{ISSUER}/account/connected-services/notion/connect"
    )
    assert fake.client.pipe_connect_url("slack", "https://app.test/i") == (
        f"{ISSUER}/account/connected-services/slack/connect"
        f"?client_id={CLIENT_ID}&return_to=https%3A%2F%2Fapp.test%2Fi"
    )
    assert fake.client.pipes.connect_url("slack") == (
        f"{ISSUER}/account/connected-services/slack/connect?client_id={CLIENT_ID}"
    )
