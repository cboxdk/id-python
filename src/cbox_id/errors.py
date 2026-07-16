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
