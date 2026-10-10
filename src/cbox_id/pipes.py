"""Pipes: lease a fresh access token for a person's connected account at a provider.

A person connects their own GitHub, Google, Slack… account on Cbox ID's hosted connect
page; your backend then leases a working access token whenever it calls that provider as
them. Cbox ID refreshes the token first when it is about to expire, so you never handle a
refresh token.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import httpx

from .errors import (
    PipeLeaseDeniedError,
    PipeLeaseError,
    PipeNotConnectedError,
    PipeReauthorizationRequiredError,
    PipeTemporarilyUnavailableError,
)

#: A provider a pipe can connect to.
PipeProvider = Literal[
    "github", "google", "microsoft", "slack", "salesforce", "hubspot", "linear", "notion"
]


@dataclass(frozen=True)
class PipeToken:
    """A fresh access token for one person's connected account. Use it, drop it, lease again."""

    #: The provider's access token. Send it as a bearer token to the provider's API.
    access_token: str
    provider: str
    user_id: str
    connection_id: str
    #: When to drop it and lease again (ISO 8601).
    lease_expires_at: str
    #: What the person consented to.
    scopes: list[str] = field(default_factory=list)
    #: When the PROVIDER stops accepting it; ``None`` for tokens that do not expire.
    expires_at: str | None = None
    #: What some providers need to be called at all — Salesforce's ``instance_url``,
    #: Slack's ``team.id``. Never a credential.
    metadata: dict[str, str] = field(default_factory=dict)
    token_type: str = "Bearer"


def with_connect_return(
    connect_url: str, *, client_id: str | None = None, return_to: str | None = None
) -> str:
    """Add ``client_id`` and ``return_to`` to a connect URL.

    The one a lease error carries, or one built with :func:`pipe_connect_url`.
    """
    parts = urlsplit(connect_url)
    query = dict(parse_qsl(parts.query))
    if client_id:
        query["client_id"] = client_id
    if return_to:
        query["return_to"] = return_to
    return urlunsplit(parts._replace(query=urlencode(query)))


def pipe_connect_url(
    issuer: str,
    provider: str,
    *,
    client_id: str | None = None,
    return_to: str | None = None,
) -> str:
    """The hosted page where the signed-in person connects their account at ``provider``.

    ``{issuer}/account/connected-services/{provider}/connect?client_id=…&return_to=…``. They
    come back to ``return_to`` with ``?provider=…&status=connected|cancelled|failed``,
    honoured only on an origin the app registered.
    """
    base = f"{issuer.rstrip('/')}/account/connected-services/{quote(provider, safe='')}/connect"
    return with_connect_return(base, client_id=client_id, return_to=return_to)


class PipesClient:
    """Leases Pipes tokens with an access token that carries the ``vault.lease`` scope.

    ``access_token`` is a string, or a callable returning one (called before every lease,
    so it can refresh). A client-credentials token names the person in ``user_id``; a token
    issued to your app FOR a person leases that person's connection, and ``user_id`` is
    left out. :attr:`CboxIdClient.pipes <cbox_id.CboxIdClient.pipes>` builds one that
    obtains its own client-credentials token.
    """

    def __init__(
        self,
        issuer: str,
        access_token: str | Callable[[], str],
        *,
        client_id: str | None = None,
        http_client: httpx.Client | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._issuer = issuer.rstrip("/")
        self._access_token = access_token
        self._client_id = client_id
        self._http = http_client or httpx.Client(timeout=timeout)

    def lease_token(
        self, provider: PipeProvider | str, *, purpose: str, user_id: str | None = None
    ) -> PipeToken:
        """Lease a fresh access token for a person's connected account at ``provider``.

        ``purpose`` is recorded on the audit trail.

        ::

            try:
                token = client.pipes.lease_token("github", user_id=uid, purpose="list-repos")
            except (PipeNotConnectedError, PipeReauthorizationRequiredError) as e:
                return redirect(e.connect_url_with(client_id=CLIENT_ID, return_to=here))

        :raises PipeNotConnectedError: 404 — send the person to ``connect_url``.
        :raises PipeReauthorizationRequiredError: 409 — send them to ``connect_url`` again.
        :raises PipeTemporarilyUnavailableError: 503 — retry after ``retry_after`` seconds.
        :raises PipeLeaseDeniedError: 403 — the app is not granted this pipe.
        :raises PipeLeaseError: anything else.
        """
        token = self._access_token() if callable(self._access_token) else self._access_token
        payload: dict[str, str] = {"purpose": purpose}
        if user_id is not None:
            payload["user_id"] = user_id

        response = self._http.post(
            f"{self._issuer}/api/v1/vault/pipes/{quote(provider, safe='')}/token",
            json=payload,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )

        try:
            parsed = response.json()
        except ValueError:
            parsed = None
        body: dict[str, Any] = parsed if isinstance(parsed, dict) else {}

        if response.status_code >= 400:
            raise _lease_error(response, body)

        access_token = body.get("access_token")
        if not isinstance(access_token, str):
            raise PipeLeaseError(
                "The pipe lease answered without an access token.",
                error=None,
                status=response.status_code,
            )

        scopes = body.get("scopes")
        metadata = body.get("metadata")
        expires_at = body.get("expires_at")
        return PipeToken(
            access_token=access_token,
            provider=str(body.get("provider", provider)),
            user_id=str(body.get("user_id", "")),
            connection_id=str(body.get("connection_id", "")),
            lease_expires_at=str(body.get("lease_expires_at", "")),
            scopes=[s for s in scopes if isinstance(s, str)] if isinstance(scopes, list) else [],
            expires_at=expires_at if isinstance(expires_at, str) else None,
            metadata={k: v for k, v in metadata.items() if isinstance(v, str)}
            if isinstance(metadata, dict)
            else {},
        )

    def connect_url(self, provider: PipeProvider | str, *, return_to: str | None = None) -> str:
        """The hosted connect page for ``provider``, preselected to this client's app."""
        return pipe_connect_url(
            self._issuer, provider, client_id=self._client_id, return_to=return_to
        )


def _lease_error(response: httpx.Response, body: dict[str, Any]) -> PipeLeaseError:
    status = response.status_code
    error = body.get("error") if isinstance(body.get("error"), str) else None
    raw_message = body.get("message")
    message = (
        raw_message
        if isinstance(raw_message, str) and raw_message
        else f"The pipe lease failed with status {status}."
    )
    raw_url = body.get("connect_url")
    connect_url = raw_url if isinstance(raw_url, str) and raw_url else None
    header = response.headers.get("retry-after", "").strip()
    retry_after = int(header) if header.isdigit() else None

    kind: type[PipeLeaseError] = PipeLeaseError
    if status == 404 and connect_url is not None:
        kind = PipeNotConnectedError
    elif status == 409 and connect_url is not None:
        kind = PipeReauthorizationRequiredError
    elif status == 503:
        kind = PipeTemporarilyUnavailableError
    elif status == 403 and error != "insufficient_scope":
        kind = PipeLeaseDeniedError

    return kind(
        message, error=error, status=status, connect_url=connect_url, retry_after=retry_after
    )
