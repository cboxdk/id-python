"""Reading the public configuration with a publishable key."""

from __future__ import annotations

import httpx
import pytest

from cbox_id import CboxIdError, ConfigurationError, FrontendApiError, FrontendClient

CONFIG = {
    "mode": "live",
    "issuer": "https://id.acme.test",
    "endpoints": {"authorization": "https://id.acme.test/oauth/authorize"},
    "social": [{"provider": "google", "name": "Google"}],
    "appearance": {"light": {"primary": "#5b5bd6"}},
}


def transport_for(
    status: int = 200,
    body: dict | None = None,
    seen: list | None = None,
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)

        return httpx.Response(status, json=body if body is not None else CONFIG)

    return httpx.MockTransport(handler)


def test_refuses_anything_that_is_not_a_publishable_key() -> None:
    """A secret where a public key belongs is the mistake this channel removes."""
    with pytest.raises(ConfigurationError):
        FrontendClient("https://id.acme.test", "sk_live_secret")


def test_sends_the_key_in_a_header_never_a_query_string() -> None:
    seen: list[httpx.Request] = []
    client = FrontendClient(
        "https://id.acme.test", "pk_live_abc", transport=transport_for(seen=seen)
    )

    client.config()

    assert seen[0].headers["X-Cbox-Publishable-Key"] == "pk_live_abc"
    assert seen[0].url.query == b""


def test_reads_the_configuration_including_the_customers_theme() -> None:
    client = FrontendClient("https://id.acme.test", "pk_live_abc", transport=transport_for())
    config = client.config()

    assert config.mode == "live"
    assert config.appearance["light"]["primary"] == "#5b5bd6"


def test_fetches_the_document_once_per_client() -> None:
    seen: list[httpx.Request] = []
    client = FrontendClient(
        "https://id.acme.test", "pk_live_abc", transport=transport_for(seen=seen)
    )

    client.config()
    client.config()

    assert len(seen) == 1


def test_signed_out_is_a_state_not_an_error() -> None:
    """Code that renders an avatar everywhere should not treat a rejection as a state."""
    seen: list[httpx.Request] = []
    client = FrontendClient(
        "https://id.acme.test", "pk_live_abc", transport=transport_for(seen=seen)
    )

    assert client.session(None).user is None
    assert seen == []


def test_names_the_allow_list_when_refused() -> None:
    client = FrontendClient("https://id.acme.test", "pk_live_abc", transport=transport_for(401, {}))

    with pytest.raises(FrontendApiError, match="allow-list") as refusal:
        client.config()

    # Machine-readable, so a caller branches on the code rather than matching on prose.
    assert refusal.value.code == "origin_not_allowed"
    assert refusal.value.status == 401


def test_prefers_the_reason_the_server_gave() -> None:
    """
    The server answers precisely — "No publishable key was presented" is a different
    problem from "That publishable key cannot be used from this origin" — and this client
    used to discard that and substitute a guess, making it less precise than the API it
    wraps.
    """
    client = FrontendClient(
        "https://id.acme.test",
        "pk_live_abc",
        transport=transport_for(
            401, {"error": "missing_key", "error_description": "No publishable key was presented."}
        ),
    )

    with pytest.raises(FrontendApiError, match="No publishable key was presented"):
        client.config()


def test_a_server_error_stays_inside_the_packages_own_hierarchy() -> None:
    """`raise_for_status()` let `httpx.HTTPStatusError` escape, so a caller writing
    `except CboxIdError` — the one thing everybody writes — missed every outage."""
    client = FrontendClient("https://id.acme.test", "pk_live_abc", transport=transport_for(503, {}))

    with pytest.raises(CboxIdError) as failure:
        client.config()

    assert isinstance(failure.value, FrontendApiError)
    assert failure.value.code == "server_error"


def test_a_non_json_body_is_reported_as_one() -> None:
    client = FrontendClient(
        "https://id.acme.test",
        "pk_live_abc",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, text="<html>a captive portal</html>")
        ),
    )

    with pytest.raises(FrontendApiError) as failure:
        client.config()

    assert failure.value.code == "bad_response"


def test_reuses_a_client_it_was_given() -> None:
    """A new `httpx.Client` per request set up and tore down a connection pool for every
    call, and left a caller with a configured client no way to pass it."""
    calls: list[str] = []

    def record(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))

        return httpx.Response(200, json={"issuer": "https://id.acme.test", "endpoints": {}})

    with httpx.Client(transport=httpx.MockTransport(record)) as shared:
        client = FrontendClient("https://id.acme.test", "pk_live_abc", http_client=shared)
        client.config()
        client.session("token")

    assert len(calls) == 2


def test_knows_whether_it_drives_real_sign_ins() -> None:
    live = FrontendClient("https://id.acme.test", "pk_live_a")
    test = FrontendClient("https://id.acme.test", "pk_test_a")

    assert (live.is_live, test.is_live) == (True, False)
