"""The browser-facing half of Cbox ID, read from Python.

Everything else in this package assumes a confidential client: it holds a secret, it
exchanges codes, it verifies webhooks. A **publishable key** is the opposite — public on
purpose, safe in a bundle, and useful only from the origins its owner registered.

Why a Python client for a browser-facing API at all: a server-rendered page still has to
know what to draw. Reading the environment's sign-in configuration here — the endpoints,
the social buttons, the customer's theme — lets a Django or Flask template render a themed
sign-in box without shipping a JavaScript SDK to do it.

The publishable key grants nothing on its own. :meth:`FrontendClient.session` is authorised
by the access token you already hold; the key only names an environment and says a browser
is asking.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from .errors import ConfigurationError

__all__ = ["FrontendClient", "FrontendConfig", "FrontendSession"]


@dataclass(frozen=True, slots=True)
class FrontendConfig:
    """Everything needed to draw a sign-in box, and nothing that identifies anybody."""

    mode: str | None
    issuer: str
    endpoints: dict[str, str]
    social: list[dict[str, str]] = field(default_factory=list)
    appearance: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class FrontendSession:
    """Who is signed in, or nobody."""

    user: dict[str, Any] | None


class FrontendClient:
    """Reads the public configuration and the current session.

    ``publishable_key`` must be a ``pk_test_`` or ``pk_live_`` value. A client secret
    passed here raises immediately rather than failing later as an opaque 401 — putting a
    secret where a public key belongs is the exact mistake this channel exists to make
    unnecessary, and as a 401 in a log the cause is invisible.
    """

    def __init__(
        self,
        issuer: str,
        publishable_key: str,
        *,
        timeout: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not issuer:
            raise ConfigurationError("issuer is required.")

        if not publishable_key.startswith("pk_"):
            raise ConfigurationError(
                "publishable_key must be a pk_test_… or pk_live_… key. "
                "Client secrets and API keys must never be used here."
            )

        self._issuer = issuer.rstrip("/")
        self._key = publishable_key
        self._timeout = timeout
        self._transport = transport
        self._config: FrontendConfig | None = None

    @property
    def is_live(self) -> bool:
        """Whether this key drives real sign-ins — handy for a "test mode" badge."""
        return self._key.startswith("pk_live_")

    def config(self) -> FrontendConfig:
        """The public sign-in configuration.

        Cached on the instance. The document is small and changes when somebody edits it in
        the console, so a long-lived process picks changes up when it next builds a client
        rather than mid-request — the right trade for something that decides layout.
        """
        if self._config is None:
            body = self._get("/frontend/v1/config")

            self._config = FrontendConfig(
                mode=body.get("mode"),
                issuer=body.get("issuer", self._issuer),
                endpoints=body.get("endpoints", {}),
                social=body.get("social", []),
                appearance=body.get("appearance"),
            )

        return self._config

    def session(self, access_token: str | None = None) -> FrontendSession:
        """Who is signed in, given a token you already hold.

        Returns ``FrontendSession(user=None)`` rather than raising when nobody is — that is
        a state, not an error, and code that renders an avatar on every page should not
        have to treat a rejection as one.
        """
        if not access_token:
            return FrontendSession(user=None)

        body = self._get("/frontend/v1/session", {"Authorization": f"Bearer {access_token}"})

        return FrontendSession(user=body.get("user"))

    def _get(self, path: str, extra_headers: dict[str, str] | None = None) -> dict[str, Any]:
        headers = {
            # A header, never a query string: a query string puts the key in server logs,
            # in Referer on every outbound link, and in browser history.
            "X-Cbox-Publishable-Key": self._key,
            "Accept": "application/json",
            **(extra_headers or {}),
        }

        with httpx.Client(timeout=self._timeout, transport=self._transport) as client:
            response = client.get(f"{self._issuer}{path}", headers=headers)

        if response.status_code in (401, 403):
            raise ConfigurationError(
                f"Cbox ID refused the request ({response.status_code}). Check that this "
                "caller's origin is on the key's allow-list, and that the key is not revoked."
            )

        response.raise_for_status()

        body = response.json()

        if not isinstance(body, dict):
            raise ConfigurationError("Cbox ID returned a body that is not the expected document.")

        return body
