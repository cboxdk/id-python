"""Cbox ID's object ids, in either spelling.

Cbox ID is moving its API, webhooks and console to prefixed public ids (``org_01J9Z…``,
``usr_01J9Z…``: a type prefix and the object's ULID), while token claims (``sub``,
``org``) keep the raw ULID. For a while both spellings arrive, often for the same object
in the same request, so compare ids with :func:`same_id`, never with ``==``.

Only ``<prefix>_<ULID>`` is unwrapped. Anything else — test ids such as ``org_1``, keys,
slugs — is compared exactly as given.
"""

from __future__ import annotations

import re

#: A type prefix and a ULID (26 Crockford base32 characters).
_PUBLIC_ID = re.compile(r"\A[a-z][a-z0-9]{0,15}_([0-9A-HJKMNP-TV-Z]{26})\Z", re.IGNORECASE)


def raw_id(value: str) -> str:
    """The id without its type prefix: the raw ULID for ``org_01J9Z…``, ``value`` otherwise.

    The ULID comes back lowercase, the way Cbox ID stores it and token claims carry it.
    """
    match = _PUBLIC_ID.match(value)
    return match.group(1).lower() if match else value


def is_prefixed_id(value: str) -> bool:
    """Whether ``value`` is a prefixed public id (``org_01J9Z…``)."""
    return _PUBLIC_ID.match(value) is not None


def same_id(a: str | None, b: str | None) -> bool:
    """Whether two ids name the same object: ``org_01J9Z…`` and ``01j9z…`` do.

    ``None`` and the empty string never match anything.
    """
    if not a or not b:
        return False

    if a == b:
        return True

    raw_a, raw_b = raw_id(a), raw_id(b)

    # Unwrapped on either side: compare the ULIDs regardless of case. Neither side a public
    # id: they were already compared exactly.
    return (raw_a != a or raw_b != b) and raw_a.lower() == raw_b.lower()
