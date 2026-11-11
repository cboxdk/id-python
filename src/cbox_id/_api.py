"""Where the SDK's own API calls go when ``api_url`` is set."""

from __future__ import annotations

from urllib.parse import urlsplit

from .errors import ConfigurationError

_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})


def v1_base_url(api_url: str) -> str:
    """``{api_url}/v1``: Cbox ID's ``/v1`` API, given with or without its version.

    ``https://api.cboxid.com`` and ``https://api.cboxid.com/v1`` are the same setting.
    """
    parts = urlsplit(api_url.strip())

    if parts.scheme == "" or parts.hostname is None or parts.query or parts.fragment:
        raise ConfigurationError("Cbox ID config `api_url` is not a valid URL.")

    if parts.username is not None or parts.password is not None:
        raise ConfigurationError("Cbox ID config `api_url` must not carry credentials.")

    loopback = parts.hostname in _LOOPBACK

    if parts.scheme != "https" and not (parts.scheme == "http" and loopback):
        raise ConfigurationError(
            f"Cbox ID config `api_url` must be https (got {parts.scheme}://{parts.hostname})."
        )

    path = parts.path.rstrip("/").removesuffix("/v1")

    return f"{parts.scheme}://{parts.netloc}{path}/v1"
