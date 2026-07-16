from __future__ import annotations

import hashlib
import hmac

from cbox_id import verify_webhook

SECRET = "whsec_test"
PAYLOAD = '{"event":"user.updated","id":"user-1"}'
NOW = 1_700_000_000


def sign(timestamp: int, body: str) -> str:
    mac = hmac.new(SECRET.encode(), f"{timestamp}.{body}".encode(), hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={mac}"


def test_accepts_fresh_valid_signature() -> None:
    assert verify_webhook(PAYLOAD, sign(NOW, PAYLOAD), SECRET, now=NOW) is True


def test_rejects_tampered_payload() -> None:
    assert verify_webhook(PAYLOAD + "x", sign(NOW, PAYLOAD), SECRET, now=NOW) is False


def test_rejects_wrong_secret() -> None:
    assert verify_webhook(PAYLOAD, sign(NOW, PAYLOAD), "whsec_other", now=NOW) is False


def test_rejects_stale_timestamp() -> None:
    assert verify_webhook(PAYLOAD, sign(NOW - 10_000, PAYLOAD), SECRET, now=NOW) is False


def test_rejects_missing_or_malformed_header() -> None:
    assert verify_webhook(PAYLOAD, None, SECRET, now=NOW) is False
    assert verify_webhook(PAYLOAD, "garbage", SECRET, now=NOW) is False
    assert verify_webhook(PAYLOAD, "t=abc,v1=xx", SECRET, now=NOW) is False
