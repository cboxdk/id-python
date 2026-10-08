"""Ergonomics for the environment plane's Audit Logs product.

On top of the generated ``env.audit_logs.*`` methods: a buffered sender, an export that
waits until it is ready, and a client-side check of an organization's hash chain that is
byte-compatible with the server's.
"""

from __future__ import annotations

import hashlib
import math
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Literal

from typing_extensions import NotRequired, TypedDict

from ..errors import CboxIdError, ConfigurationError
from .generated.environment import (
    AuditLogExport,
    AuditLogsEventsCreateBodyEventsItem,
    AuditLogsEventsCreateBodyEventsItemActor,
    AuditLogsEventsCreateBodyEventsItemContext,
    AuditLogsEventsCreateBodyEventsItemTargetsItem,
    AuditLogsEventsListQuery,
    AuditLogsExportsCreateBody,
)

if TYPE_CHECKING:
    from .generated.environment import EnvironmentClient

#: One event as ``audit_logs.events.create`` takes it.
AuditLogEventInput = AuditLogsEventsCreateBodyEventsItem

#: The most events one ``POST /audit-logs/events`` takes.
MAX_AUDIT_BATCH = 100

#: The ``prev_hash`` of an organization's first event: 64 zeros.
AUDIT_CHAIN_GENESIS = "0" * 64


class AuditLogRecord(TypedDict):
    """An event for :meth:`AuditLogger.record`: ``occurred_at`` defaults to now."""

    #: The organization (your customer) the event happened in.
    organization_id: str
    #: What happened, as dotted words: ``invoice.voided``, ``user.signed_in``.
    action: str
    actor: AuditLogsEventsCreateBodyEventsItemActor
    #: ISO 8601 with a time zone, to the millisecond. Defaults to now.
    occurred_at: NotRequired[str]
    targets: NotRequired[list[AuditLogsEventsCreateBodyEventsItemTargetsItem]]
    context: NotRequired[AuditLogsEventsCreateBodyEventsItemContext]
    metadata: NotRequired[dict[str, Any]]


def _now() -> str:
    """Now, the way JavaScript's ``toISOString`` writes it: ``2026-10-08T09:15:30.123Z``."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# ── Buffered sender ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class _Batch:
    events: list[AuditLogEventInput]
    #: Fixed when the batch is cut, so every resend of it is the same request to the server.
    idempotency_key: str


class AuditLogger:
    """Buffers audit events and sends them in batches of up to 100.

    Each batch goes under its own ``Idempotency-Key``: on a full batch, every
    ``flush_interval`` seconds, and on :meth:`flush` / :meth:`close`.

    Batches go out one at a time and in order, because the server appends each to its
    organization's hash chain in the order received. A batch that fails stays queued with
    the SAME key, so sending it again can never record an event twice.

    With ``flush_interval > 0`` a daemon thread sends in the background, and errors go to
    ``on_error`` (the batch stays queued). With ``flush_interval=0`` there is no thread: a
    full batch is sent from :meth:`record` itself, and everything else on :meth:`flush`.
    Use it as a context manager, or call :meth:`close` on shutdown — a daemon thread does
    not flush on its own when the process exits.
    """

    def __init__(
        self,
        client: EnvironmentClient,
        *,
        batch_size: int = MAX_AUDIT_BATCH,
        flush_interval: float = 5.0,
        on_error: Callable[[Exception, Sequence[AuditLogEventInput]], None] | None = None,
    ) -> None:
        if (
            not isinstance(batch_size, int)
            or isinstance(batch_size, bool)
            or not 1 <= batch_size <= MAX_AUDIT_BATCH
        ):
            raise ConfigurationError(f"batch_size must be 1–{MAX_AUDIT_BATCH}.")

        self._client = client
        self._batch_size = batch_size
        self._on_error = on_error
        self._buffer: list[AuditLogEventInput] = []
        self._queue: deque[_Batch] = deque()
        #: Guards the buffer, the queue and ``_closed``.
        self._lock = threading.Lock()
        #: One drain at a time, so batches reach the server in order.
        self._sending = threading.Lock()
        self._closed = False
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._interval = max(0.0, flush_interval)
        self._thread: threading.Thread | None = None

        if self._interval > 0:
            self._thread = threading.Thread(
                target=self._run, name="cbox-id-audit-logger", daemon=True
            )
            self._thread.start()

    @property
    def pending(self) -> int:
        """Events buffered or queued, not yet acknowledged by the server."""
        with self._lock:
            return len(self._buffer) + sum(len(batch.events) for batch in self._queue)

    def record(self, event: AuditLogRecord) -> None:
        """Buffer one event. A full batch is sent (in the background, when there is a thread)."""
        with self._lock:
            if self._closed:
                raise CboxIdError("This AuditLogger is closed.")

            stamped: AuditLogEventInput = {
                **event,
                "occurred_at": event.get("occurred_at") or _now(),
            }
            self._buffer.append(stamped)
            full = len(self._buffer) >= self._batch_size

        if full:
            if self._thread is not None:
                self._wake.set()
            else:
                self._background()

    def flush(self) -> None:
        """Send everything buffered, and return once the server has it. Raises if a batch fails."""
        with self._sending:
            self._cut()
            self._drain()

    def close(self) -> None:
        """Stop the background thread and flush."""
        with self._lock:
            self._closed = True

        if self._thread is not None:
            self._stop.set()
            self._wake.set()
            self._thread.join()
            self._thread = None

        self.flush()

    def __enter__(self) -> AuditLogger:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(self._interval)
            self._wake.clear()

            if self._stop.is_set():
                return

            self._background()

    def _background(self) -> None:
        try:
            self.flush()
        except Exception as exc:  # noqa: BLE001 - reported, and the batch stays queued
            if self._on_error is not None:
                with self._lock:
                    head = list(self._queue[0].events) if self._queue else []
                self._on_error(exc, head)

    def _cut(self) -> None:
        """Move the buffer into batches, each with the key every resend of it will carry."""
        with self._lock:
            while self._buffer:
                events = self._buffer[: self._batch_size]
                del self._buffer[: self._batch_size]
                self._queue.append(_Batch(events=events, idempotency_key=str(uuid.uuid4())))

    def _drain(self) -> None:
        while True:
            with self._lock:
                if not self._queue:
                    return
                batch = self._queue[0]

            self._client.audit_logs.events.create(
                {"events": batch.events}, idempotency_key=batch.idempotency_key
            )

            with self._lock:
                self._queue.popleft()


# ── Exports ─────────────────────────────────────────────────────────────────────────────


class AuditLogExportError(CboxIdError):
    """An export ended ``failed`` or ``expired``, or was not ready in time."""

    def __init__(self, message: str, export: AuditLogExport | None) -> None:
        super().__init__(message)
        self.export = export


def export_audit_logs(
    client: EnvironmentClient,
    filters: AuditLogsExportsCreateBody | None = None,
    *,
    poll_interval: float = 2.0,
    timeout: float = 600.0,
    idempotency_key: str | None = None,
) -> AuditLogExport:
    """Start a CSV export (``audit_logs.exports.create``) and read it until it is ``ready``.

    The result's ``url`` is signed and short-lived: download it straight away, or call
    ``env.audit_logs.exports.get(id)`` again for a fresh one. Pass the create call's
    ``idempotency_key`` to resume an export you started before.
    """
    created = client.audit_logs.exports.create(filters or {}, idempotency_key=idempotency_key)
    deadline = time.monotonic() + timeout
    interval = max(0.0, poll_interval)
    current = created.data

    while True:
        state = current["state"]

        if state == "ready":
            return current

        if state in ("failed", "expired"):
            raise AuditLogExportError(f"Audit log export {current['id']} is {state}.", current)

        if time.monotonic() >= deadline:
            raise AuditLogExportError(
                f"Audit log export {current['id']} was not ready in time.", current
            )

        time.sleep(interval)
        current = client.audit_logs.exports.get(current["id"]).data


# ── Chain verification ──────────────────────────────────────────────────────────────────


def _php_float(value: float) -> str:
    """A float the way PHP's ``json_encode`` writes it (``serialize_precision = -1``)."""
    if not math.isfinite(value):
        raise ValueError("Canonical JSON cannot encode NaN or Infinity.")

    if value == 0:
        return "-0" if math.copysign(1.0, value) < 0 else "0"

    sign = "-" if value < 0 else ""
    # The shortest round-trip digits — the same digits PHP's mode-0 conversion picks.
    shortest = Decimal(repr(abs(value))).normalize().as_tuple()
    digits = "".join(str(d) for d in shortest.digits)
    exponent = int(shortest.exponent)
    decpt = len(digits) + exponent

    if decpt < -3 or decpt > 17:
        scientific = decpt - 1
        mark = "-" if scientific < 0 else "+"
        return f"{sign}{digits[0]}.{digits[1:] or '0'}e{mark}{abs(scientific)}"

    if decpt <= 0:
        return f"{sign}0.{'0' * -decpt}{digits}"

    if decpt >= len(digits):
        return f"{sign}{digits}{'0' * (decpt - len(digits))}"

    return f"{sign}{digits[:decpt]}.{digits[decpt:]}"


_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _php_string(value: str) -> str:
    out = ['"']

    for char in value:
        code = ord(char)

        if char in _ESCAPES:
            out.append(_ESCAPES[char])
        elif code < 0x20 or code in (0x2028, 0x2029):
            # Control characters, and — like PHP even with JSON_UNESCAPED_UNICODE — the two
            # line terminators JavaScript cannot take raw in a string.
            out.append(f"\\u{code:04x}")
        else:
            out.append(char)

    out.append('"')
    return "".join(out)


def canonical_json(value: object) -> str:
    """Canonical JSON exactly as Cbox ID hashes it (``Cbox\\AuditChain\\Codec\\CanonicalJson``).

    Object keys sorted by their UTF-8 bytes at every depth, lists in order, slashes and
    Unicode written as-is — plus the two places PHP's arrays show through, so the bytes
    match:

    - an object whose sorted keys are ``"0"…"n-1"`` is a PHP list, and is written as an array;
    - an empty object is an empty PHP array, written ``[]``.

    And, like PHP, U+2028 and U+2029 are escaped. Floats are written in PHP's form (``1.0``
    as ``1``, ``1e25`` as ``1.0e+25``).
    """
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _php_float(value)
    if isinstance(value, str):
        return _php_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, Mapping):
        entries = sorted(
            ((str(key), item) for key, item in value.items()),
            key=lambda entry: entry[0].encode("utf-8"),
        )

        if not entries:
            return "[]"

        if all(key == str(index) for index, (key, _) in enumerate(entries)):
            return "[" + ",".join(canonical_json(item) for _, item in entries) + "]"

        body = ",".join(f"{_php_string(key)}:{canonical_json(item)}" for key, item in entries)
        return "{" + body + "}"

    raise TypeError(f"Canonical JSON cannot encode a {type(value).__name__}.")


def _metadata_of(value: object) -> object:
    """Metadata as it is hashed: the value, or ``None`` for none — never an empty ``[]``/``{}``."""
    if isinstance(value, (list, tuple, Mapping)):
        return value if len(value) > 0 else None

    return None


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def audit_event_document(event: Mapping[str, Any]) -> dict[str, Any]:
    """The document an event's hash covers, in the server's shape.

    The server's ``AuditLogEventResource::document``.
    """
    actor = _mapping(event.get("actor"))
    context = _mapping(event.get("context"))
    targets = event.get("targets") or []

    return {
        "id": event.get("id"),
        "organization_id": event.get("organization_id"),
        "sequence": event.get("sequence"),
        "action": event.get("action"),
        "occurred_at": event.get("occurred_at"),
        "actor": {
            "id": actor.get("id"),
            "type": actor.get("type"),
            "name": actor.get("name"),
            "metadata": _metadata_of(actor.get("metadata")),
        },
        "targets": [
            {
                "id": target.get("id"),
                "type": target.get("type"),
                "name": target.get("name"),
                "metadata": _metadata_of(target.get("metadata")),
            }
            for target in (_mapping(t) for t in targets)
        ],
        "context": {
            "location": context.get("location"),
            "user_agent": context.get("user_agent"),
        },
        "metadata": _metadata_of(event.get("metadata")),
    }


def audit_event_hash(previous_hash: str, event: Mapping[str, Any]) -> str:
    """``sha256(previous_hash ‖ canonical_json(document))``, lowercase hex."""
    document = canonical_json(audit_event_document(event))
    return hashlib.sha256((previous_hash + document).encode("utf-8")).hexdigest()


ChainBreak = Literal["missing", "link", "hash"]


@dataclass(frozen=True, slots=True)
class AuditChainVerification:
    """What :func:`verify_audit_chain` found — the server's ``AuditLogVerification``, minus
    its view of the chain's head."""

    valid: bool
    verified_count: int
    first_sequence: int | None
    last_sequence: int | None
    broken_at_sequence: int | None
    #: ``missing`` (a sequence gap), ``link`` (``prev_hash`` does not name the event
    #: before), ``hash`` (the event changed).
    reason: ChainBreak | None


def verify_audit_chain(
    events: Iterable[Mapping[str, Any]], *, previous_hash: str | None = None
) -> AuditChainVerification:
    """Check one organization's events the way ``GET /audit-logs/verify`` does.

    In sequence order, every sequence present, every ``prev_hash`` naming the event before,
    every ``hash`` matching the event. Takes events as the API returns them, in any order
    (they are sorted by ``sequence``). Unlike the server's check it cannot see the chain's
    head, so it cannot tell whether events were removed from the end.

    :param previous_hash: The hash the first event must chain from. Default: 64 zeros when
        the first event is sequence 1; otherwise the first event's own ``prev_hash``, taken
        on trust — pass the hash you kept for the event before it to check that link too.
    """
    ordered = sorted(events, key=lambda event: int(event["sequence"]))
    first = ordered[0] if ordered else None

    if previous_hash is not None:
        previous = previous_hash
    elif first is None or first["sequence"] == 1:
        previous = AUDIT_CHAIN_GENESIS
    else:
        previous = str(first["prev_hash"])

    expected = int(first["sequence"]) if first is not None else 1
    verified = 0

    def result(reason: ChainBreak | None) -> AuditChainVerification:
        return AuditChainVerification(
            valid=reason is None,
            verified_count=verified,
            first_sequence=None if verified == 0 or first is None else int(first["sequence"]),
            last_sequence=None if verified == 0 else expected - 1,
            broken_at_sequence=None if reason is None else expected,
            reason=reason,
        )

    for event in ordered:
        if event["sequence"] != expected:
            return result("missing")
        if event["prev_hash"] != previous:
            return result("link")
        if audit_event_hash(previous, event) != event["hash"]:
            return result("hash")

        previous = str(event["hash"])
        expected += 1
        verified += 1

    return result(None)


def verify_audit_log_chain(
    client: EnvironmentClient,
    organization_id: str,
    *,
    limit: int | None = None,
    previous_hash: str | None = None,
) -> AuditChainVerification:
    """Read every event of one organization and verify its chain on this side.

    Independent of the server's own check (``env.audit_logs.verify()``). The events are held
    in memory to be put in sequence order — the list is ordered by ``occurred_at``, which
    the sender chose, not by ``sequence`` — so this suits a chain of thousands, not
    millions. For a long chain, use the server's check, which pages by sequence.
    """
    query: AuditLogsEventsListQuery = {"organization_id": organization_id, "order": "asc"}

    if limit is not None:
        query["limit"] = limit

    return verify_audit_chain(client.audit_logs.events.list_all(query), previous_hash=previous_hash)
