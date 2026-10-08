"""Standard Webhooks verification, against the specification's own test vector."""

from __future__ import annotations

import base64
import hashlib
import hmac

from cbox_id import verify_standard_webhook

# https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md
SECRET = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
MSG_ID = "msg_p5jXN8AQM9LWM0D4loKWxJek"
TIMESTAMP = "1614265330"
BODY = '{"test": 2432232314}'
SIGNATURE = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
NOW = 1614265330


def verify(signature: str = SIGNATURE, **overrides: object) -> bool:
    options: dict[str, object] = {
        "webhook_id": MSG_ID,
        "webhook_timestamp": TIMESTAMP,
        "webhook_signature": signature,
        "secret": SECRET,
        "now": NOW,
        **overrides,
    }
    payload = options.pop("payload", BODY)
    return verify_standard_webhook(payload, **options)  # type: ignore[arg-type]


def test_accepts_the_spec_vector() -> None:
    assert verify() is True
    assert verify(payload=BODY.encode()) is True


def test_accepts_any_matching_entry_of_several() -> None:
    assert verify(f"v1,bm90IGl0 {SIGNATURE} v2,ignored") is True


def test_refuses_a_changed_body_id_timestamp_or_secret() -> None:
    assert verify(payload='{"test": 2432232315}') is False
    assert verify(webhook_id="msg_other") is False
    assert verify(webhook_timestamp="1614265331", now=1614265331) is False
    assert verify(secret="whsec_" + base64.b64encode(b"another key").decode()) is False


def test_refuses_a_stale_or_future_timestamp() -> None:
    assert verify(now=NOW + 301) is False
    assert verify(now=NOW - 301) is False
    assert verify(now=NOW + 300) is True


def test_refuses_missing_or_malformed_input_without_raising() -> None:
    assert verify("") is False
    assert verify("v1") is False
    assert verify("v2," + SIGNATURE[3:]) is False
    assert verify(webhook_id=None) is False
    assert verify(webhook_timestamp="soon") is False
    assert verify(secret="whsec_not*base64") is False


def test_a_cbox_hex_secret_verifies_like_its_whsec_form() -> None:
    """The server signs a hex Cbox secret under standard_webhooks as whsec_ + base64(hex)."""
    hex_secret = "ab" * 32
    whsec = "whsec_" + base64.b64encode(hex_secret.encode()).decode()
    digest = hmac.new(
        hex_secret.encode(), f"{MSG_ID}.{TIMESTAMP}.{BODY}".encode(), hashlib.sha256
    ).digest()
    signature = "v1," + base64.b64encode(digest).decode()

    assert verify(signature, secret=hex_secret) is True
    assert verify(signature, secret=whsec) is True
