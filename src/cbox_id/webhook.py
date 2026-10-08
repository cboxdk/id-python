"""Verify Cbox ID webhook / inline-action signatures."""

from __future__ import annotations

import base64
import binascii
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


def _standard_webhooks_key(secret: str) -> bytes:
    """The HMAC key a Standard Webhooks secret names.

    A ``whsec_`` secret is base64 of the key. Anything else is taken as a Cbox secret,
    whose key is its own characters — the server signs a 64-hex Cbox secret under
    ``standard_webhooks`` as ``whsec_`` + base64 of that hex string, so both forms of the
    same secret verify the same deliveries.
    """
    if secret.startswith("whsec_"):
        return base64.b64decode(secret[len("whsec_") :], validate=True)

    return secret.encode("utf-8")


def verify_standard_webhook(
    payload: str | bytes,
    *,
    webhook_id: str | None,
    webhook_timestamp: str | None,
    webhook_signature: str | None,
    secret: str,
    tolerance_seconds: int = 300,
    now: float | None = None,
) -> bool:
    """Verify a delivery signed with the ``standard_webhooks`` scheme.

    Pass the ``webhook-id``, ``webhook-timestamp`` and ``webhook-signature`` headers and the
    RAW request body. The signature is base64 HMAC-SHA256 over ``"{id}.{timestamp}.{body}"``;
    the header may list several space-separated ``v1,<signature>`` entries (during a secret
    rotation) and any one matching is enough. ``secret`` is the endpoint's ``whsec_…``
    secret, or its Cbox hex secret. Returns ``False`` (never raises) on any problem.

    Endpoints on the default ``cbox`` scheme send ``X-Cbox-Signature`` instead: use
    :func:`verify_webhook` for those.
    """
    if not webhook_id or not webhook_timestamp or not webhook_signature:
        return False

    if not webhook_timestamp.isdigit():
        return False

    current = time.time() if now is None else now
    if abs(current - int(webhook_timestamp)) > tolerance_seconds:
        return False

    try:
        key = _standard_webhooks_key(secret)
    except (ValueError, binascii.Error):
        return False

    body = payload.encode("utf-8") if isinstance(payload, str) else payload
    signed = f"{webhook_id}.{webhook_timestamp}.".encode() + body
    expected = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode("ascii")
    matched = False

    for entry in webhook_signature.split():
        version, _, signature = entry.partition(",")

        # Compare every candidate, so the time taken does not say which entry matched.
        if version == "v1" and hmac.compare_digest(expected, signature):
            matched = True

    return matched
