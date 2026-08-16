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
