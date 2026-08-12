"""The handler on the customer's side of a migration."""

from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest

from cbox_id import ConfigurationError, LegacyUser, handle_legacy_login

SECRET = "a-secret-long-enough-to-mean-something-here"


def sign(body: str, secret: str = SECRET, timestamp: int | None = None) -> str:
    timestamp = timestamp or int(time.time())
    mac = hmac.new(secret.encode(), f"{timestamp}.{body}".encode(), hashlib.sha256).hexdigest()

    return f"t={timestamp},v1={mac}"


def ada(_email: str, _password: str) -> LegacyUser:
    return LegacyUser("ada@acme.test", "Ada", email_verified=True)


def test_refuses_a_secret_too_short_to_mean_anything() -> None:
    # Inside the package's own hierarchy, so a caller wrapping their handler's
    # construction in `except CboxIdError` catches this the way they catch every other
    # configuration mistake this SDK reports.
    with pytest.raises(ConfigurationError):
        handle_legacy_login("{}", None, secret="short", verify=ada)


def test_answers_with_the_person_when_the_credentials_are_good() -> None:
    body = json.dumps({"email": "ada@acme.test", "password": "pw"})
    status, payload = handle_legacy_login(body, sign(body), secret=SECRET, verify=ada)

    assert status == 200
    assert payload["email"] == "ada@acme.test"
    assert payload["email_verified"] is True


def test_refuses_unsigned_wrong_and_stale_without_consulting_the_store() -> None:
    """The check this function exists to own — the part adopters would otherwise write."""
    called = False

    def spy(_e: str, _p: str) -> LegacyUser | None:
        nonlocal called
        called = True

        return None

    body = json.dumps({"email": "ada@acme.test", "password": "pw"})

    assert handle_legacy_login(body, None, secret=SECRET, verify=spy)[0] == 401
    wrong = sign(body, "another-secret-of-adequate-length!!!")
    assert handle_legacy_login(body, wrong, secret=SECRET, verify=spy)[0] == 401
    # Outside the freshness window: a captured request must stop working.
    stale = sign(body, SECRET, int(time.time()) - 400)
    assert handle_legacy_login(body, stale, secret=SECRET, verify=spy)[0] == 401
    assert called is False


def test_verifies_the_exact_bytes_it_was_sent() -> None:
    """Re-serialising a parsed payload produces different bytes and would refuse everything."""
    body = '{"email":"ada@acme.test",  "password":"pw"}'

    assert handle_legacy_login(body, sign(body), secret=SECRET, verify=ada)[0] == 200


def test_says_no_plainly_for_a_wrong_password() -> None:
    body = json.dumps({"email": "ada@acme.test", "password": "wrong"})
    status, payload = handle_legacy_login(body, sign(body), secret=SECRET, verify=lambda *_: None)

    assert status == 200
    assert payload == {"user": None}


def test_answers_503_when_the_store_cannot_decide() -> None:
    """A raise is not a wrong password — Cbox ID must tell the two apart in its logs."""

    def broken(_e: str, _p: str) -> LegacyUser | None:
        raise RuntimeError("database is down")

    body = json.dumps({"email": "ada@acme.test", "password": "pw"})

    assert handle_legacy_login(body, sign(body), secret=SECRET, verify=broken)[0] == 503


def test_answers_a_passwordless_probe_without_consulting_the_store() -> None:
    called = False

    def spy(_e: str, _p: str) -> LegacyUser | None:
        nonlocal called
        called = True

        return None

    body = json.dumps({"email": "ada@acme.test"})
    status, payload = handle_legacy_login(body, sign(body), secret=SECRET, verify=spy)

    assert (status, payload, called) == (200, {"user": None}, False)


def test_passes_a_stored_hash_through() -> None:
    body = json.dumps({"email": "ada@acme.test", "password": "pw"})
    status, payload = handle_legacy_login(
        body,
        sign(body),
        secret=SECRET,
        verify=lambda *_: LegacyUser("ada@acme.test", password_hash="$2y$10$abc"),
    )

    assert payload["password_hash"] == "$2y$10$abc"
