"""Exceptions raised by the Cbox ID client."""

from __future__ import annotations

from typing import Any


class CboxIdError(Exception):
    """Base class for every error this SDK raises."""


class ConfigurationError(CboxIdError):
    """The client is misconfigured (a required option is missing)."""


class InvalidStateError(CboxIdError):
    """The login state did not match — the callback is forged or stale."""


class AuthenticationError(CboxIdError):
    """Login could not be completed, or a token failed verification.

    ``error`` is the RFC 6749 §5.2 code the server sent, when it sent one. It used to
    be discarded at every back-channel boundary, leaving a single message string for
    outcomes that demand opposite responses: ``invalid_grant`` on a refresh means the
    session is over and the person must sign in again, while a 503 means the same
    token is still good in a moment. Code reduced to matching on prose either retries
    what can never succeed, or signs out somebody who did not need to be.
    """

    def __init__(
        self,
        message: str,
        error: str | None = None,
        error_description: str | None = None,
        status: int | None = None,
        retry_after: int | None = None,
    ) -> None:
        super().__init__(message)
        self.error = error
        self.error_description = error_description
        self.status = status
        #: Seconds to wait, off the ``Retry-After`` header — set only on a 429.
        #:
        #: A 429 is the ONLY back-channel failure where the same request succeeds
        #: unchanged if you wait; every other one needs a different request or a new
        #: sign-in. The limiter says how long and this SDK dropped the header, so a
        #: caller with a retry loop hammered a server already telling it to stop.
        self.retry_after = retry_after

    @property
    def is_rate_limited(self) -> bool:
        """Whether waiting and repeating the same request unchanged is worth it."""
        return self.status == 429

    @classmethod
    def from_response(cls, reason: str, response: Any) -> AuthenticationError:
        """Build from a failed back-channel response, keeping what the server said.

        Best-effort by design: a 502 from a proxy is HTML and a captive portal is
        worse, and the caller still needs an exception rather than a decode error.
        What it must never do is invent a code — an absent or unparseable ``error``
        stays ``None``, so ``exc.error == "invalid_grant"`` is true only because the
        server said so.
        """
        error: str | None = None
        description: str | None = None

        try:
            body = response.json()
        except Exception:  # noqa: BLE001 - any decode failure means "not an OAuth error"
            body = None

        if isinstance(body, dict):
            raw_error = body.get("error")
            raw_description = body.get("error_description")
            error = raw_error if isinstance(raw_error, str) else None
            description = raw_description if isinstance(raw_description, str) else None

        status = getattr(response, "status_code", None)
        detail = error if error is not None else f"HTTP {status}"

        # Seconds only. The HTTP-date form is legal per RFC 9110 and deliberately not
        # parsed: guessing at clock skew is worse than saying nothing, and a 429 status
        # still tells the caller to back off.
        header = str(getattr(response, "headers", {}).get("Retry-After", "")).strip()
        retry_after = int(header) if header.isdigit() else None

        return cls(f"{reason}: {detail}", error, description, status, retry_after)


class ManifestPublishError(CboxIdError):
    """Publishing the authorization manifest to Cbox ID was rejected."""


class FrontendApiError(CboxIdError):
    """
    The browser-facing channel refused, or answered something unusable.

    ``code`` is machine-readable and stable — ``origin_not_allowed``,
    ``rate_limited``, ``server_error``, ``bad_response``, ``transport`` — so a caller can
    branch without matching on prose. ``status`` is the HTTP status when there was one.

    A class of its own because these are not configuration problems, and they were raised
    as ``ConfigurationError`` alongside genuine ones. Worse, a 5xx escaped the package's
    hierarchy entirely as ``httpx.HTTPStatusError``, so ``except CboxIdError`` — the one
    thing every caller writes — missed every outage.
    """

    def __init__(self, message: str, *, code: str, status: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


class PipeLeaseError(CboxIdError):
    """A Pipes token lease was refused.

    Catch the subclasses for the cases you can act on:

    - :class:`PipeNotConnectedError` (404) and :class:`PipeReauthorizationRequiredError`
      (409) — send the person to :attr:`connect_url`.
    - :class:`PipeTemporarilyUnavailableError` (503) — retry after :attr:`retry_after`.
    - :class:`PipeLeaseDeniedError` (403) — a configuration problem: the app is not granted
      the pipe, the pipe is disabled, or the person is outside the app's organization.

    Anything else (401, 422, 429) is raised as this base class with ``status`` and ``error``.
    """

    def __init__(
        self,
        message: str,
        *,
        error: str | None,
        status: int,
        connect_url: str | None = None,
        retry_after: int | None = None,
    ) -> None:
        super().__init__(message)
        #: The server's error code, e.g. ``not_connected``.
        self.error = error
        self.status = status
        #: Where to send the person to (re)connect — set on 404 and 409.
        self.connect_url = connect_url
        #: Seconds to wait, off ``Retry-After``, when the server sent one.
        self.retry_after = retry_after

    def connect_url_with(
        self, *, client_id: str | None = None, return_to: str | None = None
    ) -> str | None:
        """:attr:`connect_url` with your ``client_id`` and ``return_to`` on it, or ``None``."""
        from .pipes import with_connect_return

        if self.connect_url is None:
            return None
        return with_connect_return(self.connect_url, client_id=client_id, return_to=return_to)


class PipeNotConnectedError(PipeLeaseError):
    """The person has not connected this provider (404 ``not_connected``).

    Send them to :attr:`connect_url`.
    """

    connect_url: str


class PipeReauthorizationRequiredError(PipeLeaseError):
    """The provider stopped accepting the connection (409 ``reauthorization_required``).

    Revoked at the provider, or the refresh token expired. Send the person to
    :attr:`connect_url` to connect again.
    """

    connect_url: str


class PipeTemporarilyUnavailableError(PipeLeaseError):
    """The provider could not refresh the token just now (503). Retry after ``retry_after``."""


class PipeLeaseDeniedError(PipeLeaseError):
    """The lease was denied (403 ``lease_denied``).

    The app is not granted the pipe, the pipe is disabled or missing, the person is not in
    the app's organization, or ``user_id`` names someone other than the token's person. One
    answer for every reason, by design.
    """
