"""Fine-grained authorization helpers for ``env.fga``.

The batch check (``env.fga.check_batch({"checks": [...]})``) takes each check in the tuple
notation — ``document:readme#viewer@user:alice``, or ``folder:policies#viewer@group:eng#member``
for a userset. :func:`fga_tuple` writes that notation from the same mapping
``env.fga.tuples.write`` takes, so code that writes tuples and checks them speaks one shape.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_NAME_FORBIDDEN = re.compile(r"[\s#@:]")
_ID_FORBIDDEN = re.compile(r"[\s#@]")


def _name(value: object, what: str) -> str:
    if not isinstance(value, str) or value == "" or _NAME_FORBIDDEN.search(value):
        raise ValueError(
            f"An FGA {what} cannot be empty or contain whitespace, '#', '@' or ':': {value!r}"
        )
    return value


def _id(value: object, what: str) -> str:
    if not isinstance(value, str) or value == "" or _ID_FORBIDDEN.search(value):
        raise ValueError(
            f"An FGA {what} cannot be empty or contain whitespace, '#' or '@': {value!r}"
        )
    return value


def fga_tuple(tuple_: Mapping[str, Any]) -> str:
    """Write a tuple in the notation the batch check and the console use.

    ``{"resource_type": "document", "resource_id": "readme", "relation": "viewer",
    "subject": {"type": "user", "id": "alice"}}`` → ``document:readme#viewer@user:alice``.

    Raises :class:`ValueError` for a part that is empty or contains ``#``, ``@``, ``:`` (in
    a type or relation) or whitespace — the notation has no escaping, so such a part would
    be read back as a different tuple. Ids may contain ``:``.
    """
    subject = tuple_.get("subject")
    if not isinstance(subject, Mapping):
        raise ValueError("An FGA tuple needs a subject mapping with a type and an id.")

    relation = subject.get("relation")
    userset = f"#{_name(relation, 'subject relation')}" if relation else ""

    return (
        f"{_name(tuple_.get('resource_type'), 'resource type')}:"
        f"{_id(tuple_.get('resource_id'), 'resource id')}#"
        f"{_name(tuple_.get('relation'), 'relation')}@"
        f"{_name(subject.get('type'), 'subject type')}:{_id(subject.get('id'), 'subject id')}"
        f"{userset}"
    )
