"""Exceptions raised by the Cbox ID client."""

from __future__ import annotations


class CboxIdError(Exception):
    """Base class for every error this SDK raises."""


class ConfigurationError(CboxIdError):
    """The client is misconfigured (a required option is missing)."""


class InvalidStateError(CboxIdError):
    """The login state did not match — the callback is forged or stale."""


class AuthenticationError(CboxIdError):
    """Login could not be completed, or a token failed verification."""


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
