"""Cbox ID's webhook event names, old and new.

Cbox ID is adding its product key to every event type: ``organization.member_added``
becomes ``id.organization.member_added``, and ``user.login`` becomes
``id.user.signed_in`` (a past verb). For a while a delivery may carry either name, so treat
the two as one event::

    event = json.loads(body)

    if same_event(event["type"], "organization.member_added"):
        ...

    handler = HANDLERS.get(legacy_event_name(event["type"]))  # keyed by today's names
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

#: The product key Cbox ID puts in front of its event types.
EVENT_PREFIX = "id."

#: Old names whose new name is not just :data:`EVENT_PREFIX` added.
RENAMED_EVENTS: Mapping[str, str] = MappingProxyType({"user.login": "id.user.signed_in"})

_WILDCARD = "*"


def current_event_name(event_type: str) -> str:
    """The ``id.*`` name of an event type, whichever name it was given in."""
    if event_type == _WILDCARD or event_type.startswith(EVENT_PREFIX):
        return event_type

    return RENAMED_EVENTS.get(event_type, EVENT_PREFIX + event_type)


def legacy_event_name(event_type: str) -> str:
    """The name an event type had before the ``id.*`` names, whichever name it was given in."""
    if not event_type.startswith(EVENT_PREFIX):
        return event_type

    for old, new in RENAMED_EVENTS.items():
        if new == event_type:
            return old

    return event_type[len(EVENT_PREFIX) :]


def event_name_aliases(event_type: str) -> tuple[str, ...]:
    """Both names of an event type, the one given first: for subscribing to either."""
    return tuple(
        dict.fromkeys((event_type, legacy_event_name(event_type), current_event_name(event_type)))
    )


def same_event(a: str, b: str) -> bool:
    """Whether two event type names are the same event (``user.login`` is
    ``id.user.signed_in``)."""
    return a == b or legacy_event_name(a) == legacy_event_name(b)
