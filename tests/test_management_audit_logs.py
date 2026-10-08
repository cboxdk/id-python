"""Audit Logs helpers: the chain verifier against the server's vector, the logger, exports."""

from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from cbox_id.management import (
    AUDIT_CHAIN_GENESIS,
    AuditChainVerification,
    AuditLogExportError,
    AuditLogger,
    CboxIdApiError,
    CboxIdError,
    ConfigurationError,
    RetryOptions,
    audit_event_document,
    audit_event_hash,
    canonical_json,
    export_audit_logs,
    verify_audit_chain,
    verify_audit_log_chain,
)

from .management_helpers import API, Call, FakeApi, env_client, json_response

FIXTURE = Path(__file__).parent / "fixtures" / "audit_chain.json"


def fixture() -> list[dict[str, Any]]:
    data: list[dict[str, Any]] = json.loads(FIXTURE.read_text("utf-8"))["data"]
    return data


def client(fake: FakeApi) -> Any:
    return env_client(fake, retry=RetryOptions(max_retries=0))


# ── Chain: byte for byte with the server ─────────────────────────────────────────────────


def test_canonicalises_and_hashes_each_event_exactly_as_cbox_id_did() -> None:
    """The vector was computed by the server's own code (see the fixture's ``_source``)."""
    previous = AUDIT_CHAIN_GENESIS

    for event in fixture():
        assert canonical_json(audit_event_document(event)) == event["canonical"]
        assert event["prev_hash"] == previous
        assert audit_event_hash(previous, event) == event["hash"]
        previous = event["hash"]


def test_verifies_the_chain_in_any_order_and_finds_a_changed_missing_or_relinked_event() -> None:
    events = fixture()

    assert verify_audit_chain(list(reversed(events))) == AuditChainVerification(
        valid=True,
        verified_count=3,
        first_sequence=1,
        last_sequence=3,
        broken_at_sequence=None,
        reason=None,
    )

    changed = [{**e, "action": "user.signed_out"} if e["sequence"] == 2 else e for e in events]
    result = verify_audit_chain(changed)
    assert (result.valid, result.reason, result.broken_at_sequence, result.verified_count) == (
        False,
        "hash",
        2,
        1,
    )

    gap = verify_audit_chain([e for e in events if e["sequence"] != 2])
    assert (gap.valid, gap.reason, gap.broken_at_sequence) == (False, "missing", 2)

    relinked = [
        {**e, "prev_hash": AUDIT_CHAIN_GENESIS} if e["sequence"] == 3 else e for e in events
    ]
    link = verify_audit_chain(relinked)
    assert (link.valid, link.reason, link.broken_at_sequence) == (False, "link", 3)

    # A window that starts later trusts its first prev_hash, unless told what it must be.
    tail = [e for e in events if e["sequence"] > 1]
    assert verify_audit_chain(tail).valid is True
    assert verify_audit_chain(tail).first_sequence == 2
    assert verify_audit_chain(tail, previous_hash="f" * 64).reason == "link"

    assert verify_audit_chain([]) == AuditChainVerification(True, 0, None, None, None, None)


def test_writes_numbers_and_strings_the_way_php_json_encode_does() -> None:
    # Expected strings are PHP 8's json_encode output for the same values (id-js's vector).
    values = [1.0, 1e25, 1e-7, 0.1, 1.5, 1e15, 1e16, 1e17, 0.0001, 0.00012, 1.2345e20]
    values += [-2.5e-5, 0.1 + 0.2, 1e100, -0.0]
    assert [canonical_json(v) for v in values] == [
        "1",
        "1.0e+25",
        "1.0e-7",
        "0.1",
        "1.5",
        "1000000000000000",
        "10000000000000000",
        "1.0e+17",
        "0.0001",
        "0.00012",
        "1.2345e+20",
        "-2.5e-5",
        "0.30000000000000004",
        "1.0e+100",
        "-0",
    ]
    assert canonical_json({"b": "x/y", "a": 'Æ\u2028"\n'}) == '{"a":"Æ\\u2028\\"\\n","b":"x/y"}'
    assert canonical_json({"1": "b", "0": "a"}) == '["a","b"]'
    assert canonical_json({"10": "k", "2": "j"}) == '{"10":"k","2":"j"}'
    assert canonical_json({}) == "[]"
    assert canonical_json([]) == "[]"
    assert canonical_json({"a": True, "b": None, "c": 7}) == '{"a":true,"b":null,"c":7}'

    with pytest.raises(ValueError):
        canonical_json(float("nan"))


# ── AuditLogger ──────────────────────────────────────────────────────────────────────────


def accept(call: Call) -> httpx.Response:
    return json_response({"data": {"events": (call.body or {}).get("events", [])}}, 201)


def test_sends_batches_of_at_most_100_each_under_its_own_idempotency_key() -> None:
    fake = FakeApi(accept, accept, accept)
    logger = AuditLogger(client(fake), flush_interval=0)

    for i in range(250):
        logger.record(
            {
                "organization_id": "org_1",
                "action": "invoice.viewed",
                "actor": {"id": f"u{i}", "type": "user"},
            }
        )
    logger.flush()

    assert [len(c.body["events"]) for c in fake.calls] == [100, 100, 50]
    assert all(c.method == "POST" and c.url == f"{API}/audit-logs/events" for c in fake.calls)
    assert len({c.headers["idempotency-key"] for c in fake.calls}) == 3
    first = fake.calls[0].body["events"][0]
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$", first["occurred_at"])
    assert logger.pending == 0


def test_keeps_a_failed_batch_and_resends_it_with_the_same_key() -> None:
    fake = FakeApi(json_response({"error": "server_error", "message": "Down."}, 503), accept)
    logger = AuditLogger(client(fake), flush_interval=0)
    logger.record(
        {
            "organization_id": "org_1",
            "action": "a.b",
            "actor": {"id": "u", "type": "user"},
            "occurred_at": "2026-10-08T00:00:00.000Z",
        }
    )

    with pytest.raises(CboxIdApiError) as caught:
        logger.flush()

    assert caught.value.status == 503
    assert logger.pending == 1

    logger.flush()

    assert len(fake.calls) == 2
    assert fake.calls[1].headers["idempotency-key"] == fake.calls[0].headers["idempotency-key"]
    assert fake.calls[1].body["events"][0]["occurred_at"] == "2026-10-08T00:00:00.000Z"
    assert logger.pending == 0


def test_a_full_batch_without_a_thread_is_sent_from_record_and_failures_go_to_on_error() -> None:
    fake = FakeApi(json_response({"error": "server_error", "message": "Down."}, 503), accept)
    errors: list[tuple[Exception, int]] = []
    logger = AuditLogger(
        client(fake),
        batch_size=2,
        flush_interval=0,
        on_error=lambda exc, batch: errors.append((exc, len(batch))),
    )
    event: Any = {"organization_id": "o", "action": "a.b", "actor": {"id": "u", "type": "user"}}

    logger.record(event)
    assert fake.calls == []
    logger.record(event)

    assert len(fake.calls) == 1
    assert len(errors) == 1 and errors[0][1] == 2
    assert logger.pending == 2

    logger.close()
    assert logger.pending == 0


def test_flushes_on_its_interval_and_refuses_events_once_closed() -> None:
    sent = threading.Event()

    def answer(call: Call) -> httpx.Response:
        sent.set()
        return accept(call)

    fake = FakeApi(answer)
    logger = AuditLogger(client(fake), flush_interval=0.05)
    logger.record(
        {"organization_id": "org_1", "action": "a.b", "actor": {"id": "u", "type": "user"}}
    )

    assert sent.wait(5), "the background thread never flushed"
    logger.close()

    assert len(fake.calls) == 1
    with pytest.raises(CboxIdError, match="closed"):
        logger.record(
            {"organization_id": "org_1", "action": "a.b", "actor": {"id": "u", "type": "user"}}
        )


def test_refuses_a_batch_size_outside_1_to_100() -> None:
    for size in (0, 101, True):
        with pytest.raises(ConfigurationError):
            AuditLogger(client(FakeApi()), batch_size=size, flush_interval=0)


# ── Exports and lists ────────────────────────────────────────────────────────────────────


def exported(state: str) -> dict[str, Any]:
    return {
        "data": {
            "id": "exp_1",
            "organization_id": "org_1",
            "state": state,
            "filters": {},
            "row_count": None,
            "url": "https://files.test/x.csv" if state == "ready" else None,
            "created_at": None,
            "completed_at": None,
            "expires_at": None,
        }
    }


def test_creates_an_export_and_reads_it_until_it_is_ready() -> None:
    fake = FakeApi(
        json_response(exported("pending"), 201),
        json_response(exported("pending")),
        json_response(exported("pending")),
        json_response(exported("ready")),
    )
    result = export_audit_logs(client(fake), {"organization_id": "org_1"}, poll_interval=0)

    assert result["url"] == "https://files.test/x.csv"
    assert [f"{c.method} {c.url}" for c in fake.calls] == [
        f"POST {API}/audit-logs/exports",
        f"GET {API}/audit-logs/exports/exp_1",
        f"GET {API}/audit-logs/exports/exp_1",
        f"GET {API}/audit-logs/exports/exp_1",
    ]
    assert fake.calls[0].body == {"organization_id": "org_1"}


def test_raises_when_the_export_fails_or_is_not_ready_in_time() -> None:
    failed = FakeApi(json_response(exported("pending"), 201), json_response(exported("failed")))

    with pytest.raises(AuditLogExportError) as caught:
        export_audit_logs(client(failed), poll_interval=0)

    assert caught.value.export is not None and caught.value.export["state"] == "failed"

    slow = FakeApi(json_response(exported("pending"), 201))

    with pytest.raises(AuditLogExportError, match="in time"):
        export_audit_logs(client(slow), poll_interval=0, timeout=0)


def test_pages_events_and_verifies_an_organizations_chain_from_the_list() -> None:
    events = fixture()

    def page(call: Call) -> httpx.Response:
        if "after" in parse_qs(urlsplit(call.url).query):
            return json_response({"data": events[2:], "meta": {"has_more": False}})
        return json_response({"data": events[:2], "meta": {"has_more": True, "next_cursor": "c1"}})

    fake = FakeApi(page, page, page, page)
    env = client(fake)
    ids = [
        event["id"]
        for event in env.audit_logs.events.list_all(
            {"organization_id": "org_1", "actions": ["invoice.voided", "user.signed_in"]}
        )
    ]

    assert ids == [e["id"] for e in events]
    assert fake.calls[0].url == (
        f"{API}/audit-logs/events?organization_id=org_1"
        "&actions%5B%5D=invoice.voided&actions%5B%5D=user.signed_in"
    )

    result = verify_audit_log_chain(env, "org_1")

    assert (result.valid, result.verified_count) == (True, 3)
    assert parse_qs(urlsplit(fake.calls[2].url).query)["order"] == ["asc"]
