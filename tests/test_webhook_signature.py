"""Golden webhook-signature vectors, shared cross-SDK.

``fixtures/webhook_signature.json`` is byte-for-byte identical to the copies in
laravel-id (the sender), id-js, id-go and laravel-id-client.

``test_webhook.py`` signs with its own copy of the formula and then verifies it, so
it stays green even when this SDK and the server disagree: flip the signed string
from ``"{timestamp}.{payload}"`` to ``"{payload}.{timestamp}"`` on either side and
that suite still passes while every delivery fails in the field. The signatures
below are fixed bytes produced by the server implementation and independently
reproduced with OpenSSL and Python.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cbox_id import verify_webhook

FIXTURE: dict[str, Any] = json.loads(
    (Path(__file__).parent / "fixtures" / "webhook_signature.json").read_text(encoding="utf-8")
)
CASES: list[dict[str, Any]] = FIXTURE["cases"]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_accepts_the_golden_signature(case: dict[str, Any]) -> None:
    assert (
        verify_webhook(case["body"], case["header"], case["secret"], now=case["timestamp"]) is True
    )


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_rejects_the_reversed_concatenation(case: dict[str, Any]) -> None:
    # The same secret, timestamp and body signed as "{body}.{timestamp}". A verifier
    # that concatenates the other way round accepts this — and rejects every real
    # delivery.
    assert (
        verify_webhook(
            case["body"], case["reversed_order_header"], case["secret"], now=case["timestamp"]
        )
        is False
    )


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_rejects_a_golden_signature_against_a_tampered_body(case: dict[str, Any]) -> None:
    assert (
        verify_webhook(case["body"] + " ", case["header"], case["secret"], now=case["timestamp"])
        is False
    )


def test_verifies_raw_bytes_not_a_reserialized_body() -> None:
    # The unicode case ships escaped slashes and \\uXXXX escapes. Re-encoding the
    # parsed object yields equivalent JSON with different bytes, which must NOT
    # verify — the most common webhook integration bug.
    case = next(c for c in CASES if c["name"] == "unicode_and_escaped_slashes")
    re_serialized = json.dumps(json.loads(case["body"]))

    assert re_serialized != case["body"]
    assert (
        verify_webhook(re_serialized, case["header"], case["secret"], now=case["timestamp"])
        is False
    )


def test_pins_the_signed_payload_order_the_server_uses() -> None:
    """The wire format, stated once as a constant.

    This package verifies against its OWN copy of the fixture, as every SDK does, so a
    copy that drifts is silent: this suite stays green against the drifted bytes while
    every delivery from the server fails in the field. The docblock above calls the
    copies byte-for-byte identical and nothing enforced it — the templates were the one
    field no test read.

    Deliberately NOT derived from the file it guards: ``{timestamp}.{body}`` is the
    contract with the sender, and a copy that says otherwise is wrong rather than
    authoritative.
    """
    assert FIXTURE["signed_payload_template"] == "{timestamp}.{body}"
    assert FIXTURE["header_template"] == "t={timestamp},v1={signature}"


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_builds_each_case_literal_from_the_published_templates(case: dict[str, Any]) -> None:
    """The template and the literal are the same fact stated twice.

    Either one edited alone is now a failure, which is what makes carrying both worth it:
    the vector tests hash the literal, so a flipped template alone changed nothing.
    """
    signed_payload = FIXTURE["signed_payload_template"].format(
        timestamp=case["timestamp"], body=case["body"]
    )

    assert signed_payload == case["signed_payload"]


def _case(name: str) -> dict[str, Any]:
    return next(c for c in CASES if c["name"] == name)


def test_rejects_a_signature_truncated_to_a_valid_prefix() -> None:
    """A signature is accepted only in full, and only at its exact length.

    ``hmac.compare_digest`` gives both properties for free — which is precisely why
    nothing asserted them, and why a rewrite could quietly lose them. Verified across the
    SDKs: replacing the comparison with an 8-character prefix match left every suite
    green.

    Every character present here is correct; there are just fewer of them, which is
    exactly what a prefix comparison accepts and a full one refuses.
    """
    case = _case("envelope")
    truncated = f"t={case['timestamp']},v1={case['signature'][:32]}"

    assert verify_webhook(case["body"], truncated, case["secret"], now=case["timestamp"]) is False


def test_rejects_a_valid_signature_with_anything_appended() -> None:
    """The digest is intact and complete; there is simply more after it."""
    case = _case("envelope")

    assert (
        verify_webhook(case["body"], case["header"] + "00", case["secret"], now=case["timestamp"])
        is False
    )


def test_rejects_a_signature_differing_only_in_its_last_character() -> None:
    """The far end of the digest, where a comparison that stops early never looks."""
    case = _case("envelope")
    signature = str(case["signature"])
    flipped = signature[:-1] + ("1" if signature.endswith("0") else "0")

    assert (
        verify_webhook(
            case["body"],
            f"t={case['timestamp']},v1={flipped}",
            case["secret"],
            now=case["timestamp"],
        )
        is False
    )
