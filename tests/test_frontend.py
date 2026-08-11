"""Reading the public configuration with a publishable key."""

from __future__ import annotations

import httpx
import pytest

from cbox_id import FrontendClient
from cbox_id.errors import ConfigurationError

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

    with pytest.raises(ConfigurationError, match="allow-list"):
        client.config()


def test_knows_whether_it_drives_real_sign_ins() -> None:
    live = FrontendClient("https://id.acme.test", "pk_live_a")
    test = FrontendClient("https://id.acme.test", "pk_test_a")

    assert (live.is_live, test.is_live) == (True, False)
