"""The handler on your side of a migration off an old login.

Cbox ID offers an email and a password it has never seen; your callable answers with the
person or with nothing. On a yes they are created in Cbox ID as a result of the login that
just succeeded, and from their next sign-in the old system is never asked again.

WHY THIS EXISTS RATHER THAN A DOCUMENTED WIRE FORMAT. The contract is a signed POST with
JSON in and JSON out — small enough to describe in a paragraph, and describing it would
mean every adopter writes the signature check themselves. That check is the part people
get wrong: ``==`` instead of a constant-time compare, no freshness window, no thought
about a captured request replayed an hour later. This owns all of it, and reuses
:func:`cbox_id.webhook.verify_webhook` so there is one implementation of the construction
in this package rather than two that can drift.

FRAMEWORK-AGNOSTIC ON PURPOSE. Python has no single request object — Flask, Django,
FastAPI and Starlette all differ — so this takes the raw body and the signature header and
returns ``(status, body)``. Adapting that to any of them is three lines, and inventing a
request abstraction to avoid those three lines would be the larger imposition.

    from cbox_id import LegacyUser, handle_legacy_login

    @app.post("/cbox-legacy")
    def cbox_legacy():
        status, body = handle_legacy_login(
            request.get_data(as_text=True),
            request.headers.get("X-Cbox-Signature"),
            secret=os.environ["CBOX_LEGACY_SECRET"],
            verify=lookup,
        )
        return jsonify(body), status
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass

from .errors import ConfigurationError
from .webhook import verify_webhook

__all__ = ["LegacyUser", "handle_legacy_login"]


@dataclass(frozen=True, slots=True)
class LegacyUser:
    """A person as your old system knows them.

    Everything but the email is optional, because a store that can only answer "yes, and
    here is the address" is still enough to migrate somebody.
    """

    email: str
    name: str | None = None
    email_verified: bool = False
    password_hash: str | None = None
    """Your stored hash, when you can expose it.

    Passing it lets the person keep their password in Cbox ID verbatim — stored as is, and
    upgraded to the platform hasher on their next login, exactly like a bulk-imported user.
    Omit it and Cbox ID hashes the password they just proved they know, which is the honest
    option when your store cannot hand one over.
    """


def handle_legacy_login(
    raw_body: str,
    signature_header: str | None,
    *,
    secret: str,
    verify: Callable[[str, str], LegacyUser | None],
    tolerance_seconds: int = 300,
) -> tuple[int, dict[str, object]]:
    """Verify the request and ask ``verify`` about the credentials.

    ``raw_body`` must be the EXACT bytes received, decoded as text. The signature covers
    them, so re-serialising a parsed payload produces different bytes and would refuse
    every valid request — a failure that looks like a wrong secret and costs an afternoon.

    ``verify`` returns ``None`` for "wrong password". RAISING IS DIFFERENT: it means your
    store could not decide, and is answered with 503 so Cbox ID refuses the sign-in rather
    than reading an outage as a bad credential — and can tell the two apart in its logs.
    """
    if len(secret) < 32:
        # `ConfigurationError`, not a bare `ValueError`: this is the same class of mistake
        # as passing a client secret where a publishable key belongs, and a caller writing
        # `except CboxIdError` around their handler's construction should catch both.
        raise ConfigurationError(
            "A legacy-login secret of at least 32 characters is required; "
            "it is the only thing proving a request came from Cbox ID."
        )

    if not verify_webhook(raw_body, signature_header, secret, tolerance_seconds):
        # No detail. A caller who cannot sign is not owed help telling a bad signature from
        # a stale timestamp — both mean the same thing to anyone legitimate, and the
        # difference is a hint to anyone else.
        return 401, {"error": "unauthorized"}

    try:
        payload = json.loads(raw_body)
    except ValueError:
        return 400, {"error": "invalid_request"}

    if not isinstance(payload, dict):
        return 400, {"error": "invalid_request"}

    email = payload.get("email")
    password = payload.get("password")

    if not isinstance(email, str) or not email:
        return 400, {"error": "invalid_request"}

    # No password means Cbox ID is asking "do you know this address" — the tooling path,
    # for a dry run before cutover. It never arrives from a sign-in.
    if not isinstance(password, str):
        return 200, {"user": None}

    try:
        user = verify(email, password)
    except Exception:  # noqa: BLE001 — any failure means "could not decide", see above
        return 503, {"error": "unavailable"}

    if user is None:
        return 200, {"user": None}

    body: dict[str, object] = {
        "email": user.email,
        "name": user.name,
        "email_verified": user.email_verified,
    }

    if user.password_hash:
        body["password_hash"] = user.password_hash

    return 200, body
