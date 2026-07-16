"""Verify Cbox ID webhook / inline-action signatures."""

from __future__ import annotations

import hashlib
import hmac
import time


def verify_webhook(
    payload: str,
    signature_header: str | None,
    secret: str,
    tolerance_seconds: int = 300,
    now: float | None = None,
) -> bool:
    """Verify an ``X-Cbox-Signature`` header.

    The header is ``t={unix},v1={hex hmac}`` — an HMAC-SHA256 over
    ``"{timestamp}.{raw body}"``, valid within a freshness window. Pass the RAW
    request body, not a re-serialized copy. Returns ``False`` (never raises) on any
    problem.
    """
    if not signature_header:
        return False

    parts: dict[str, str] = {}
    for segment in signature_header.split(","):
        key, _, value = segment.strip().partition("=")
        if key:
            parts[key] = value

    timestamp = parts.get("t", "")
    signature = parts.get("v1", "")

    if not timestamp.isdigit() or signature == "":
        return False

    current = time.time() if now is None else now
    if abs(current - int(timestamp)) > tolerance_seconds:
        return False

    expected = hmac.new(
        secret.encode("utf-8"),
        f"{timestamp}.{payload}".encode(),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, signature)
