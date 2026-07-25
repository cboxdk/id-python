from __future__ import annotations

import base64
import json
import time
from urllib.parse import parse_qs, urlparse

import jwt
import pytest

from cbox_id import (
    AuthenticationError,
    CboxIdClient,
    CboxIdConfig,
    ConfigurationError,
    InvalidStateError,
)
from cbox_id.pkce import challenge

from .conftest import CLIENT_ID, ISSUER, NONCE, FakeInstance

STORED = {"expected_state": "state-1", "code_verifier": "verifier-1", "nonce": NONCE}


def _tamper_claim(token: str, claim: str, value: str) -> str:
    """Alter a claim but re-attach the ORIGINAL signature (a forgery attempt)."""
    header, payload, signature = token.split(".")
    data = json.loads(base64.urlsafe_b64decode(payload + "=="))
    data[claim] = value
    new_payload = base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()
    return f"{header}.{new_payload}.{signature}"


def test_authorization_request_uses_pkce_s256(fake: FakeInstance) -> None:
    req = fake.client.create_authorization_request()
    parsed = urlparse(req.url)
    query = parse_qs(parsed.query)

    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == f"{ISSUER}/oauth/authorize"
    assert query["response_type"] == ["code"]
    assert query["client_id"] == [CLIENT_ID]
    assert query["scope"] == ["openid profile email"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["state"] == [req.state]
    assert query["nonce"] == [req.nonce]
    assert query["code_challenge"] == [challenge(req.code_verifier)]


def test_authenticate_returns_verified_user(fake: FakeInstance) -> None:
    user = fake.client.authenticate(code="auth-code", state="state-1", **STORED)

    assert user.id == "user-1"
    assert user.email == "ada@acme.com"
    assert user.name == "Ada"
    assert user.organization_id == "org-1"
    assert user.access_token == "access-abc"
    assert user.refresh_token == "refresh-abc"
    assert user.expires_in == 3600


def test_refresh_exchanges_for_rotated_tokens(fake: FakeInstance) -> None:
    fake.set_token_response(
        {
            "access_token": "access-2",
            "refresh_token": "refresh-2",
            "expires_in": 3600,
            "scope": "openid offline_access",
        }
    )
    tokens = fake.client.refresh("refresh-abc")
    assert tokens.access_token == "access-2"
    assert tokens.refresh_token == "refresh-2"
    assert tokens.expires_in == 3600
    assert tokens.scope == "openid offline_access"


def test_authenticate_rejects_mismatched_state(fake: FakeInstance) -> None:
    with pytest.raises(InvalidStateError):
        fake.client.authenticate(code="auth-code", state="forged", **STORED)


def test_authenticate_surfaces_provider_error(fake: FakeInstance) -> None:
    with pytest.raises(AuthenticationError, match="access_denied"):
        fake.client.authenticate(code=None, state="state-1", error="access_denied", **STORED)


def test_authenticate_rejects_replayed_nonce(fake: FakeInstance) -> None:
    token = fake.sign_id_token(
        {"iss": ISSUER, "aud": CLIENT_ID, "sub": "user-1", "nonce": "different"}
    )
    fake.set_token_response({"access_token": "access-abc", "id_token": token})

    with pytest.raises(AuthenticationError, match="nonce"):
        fake.client.authenticate(code="auth-code", state="state-1", **STORED)


def test_authenticate_rejects_wrong_issuer(fake: FakeInstance) -> None:
    token = fake.sign_id_token(
        {"iss": "https://evil.test", "aud": CLIENT_ID, "sub": "user-1", "nonce": NONCE}
    )
    fake.set_token_response({"access_token": "access-abc", "id_token": token})

    with pytest.raises(AuthenticationError):
        fake.client.authenticate(code="auth-code", state="state-1", **STORED)


def test_authenticate_rejects_wrong_audience(fake: FakeInstance) -> None:
    token = fake.sign_id_token(
        {"iss": ISSUER, "aud": "someone-else", "sub": "user-1", "nonce": NONCE}
    )
    fake.set_token_response({"access_token": "access-abc", "id_token": token})

    with pytest.raises(AuthenticationError):
        fake.client.authenticate(code="auth-code", state="state-1", **STORED)


def test_authenticate_rejects_foreign_key_signature(fake: FakeInstance) -> None:
    # Signed with a key the JWKS does not advertise; the signature must fail. A
    # regression that skipped the signature check would let this token through.
    token = fake.sign_foreign_id_token(
        {"iss": ISSUER, "aud": CLIENT_ID, "sub": "user-1", "nonce": NONCE}
    )
    fake.set_token_response({"access_token": "access-abc", "id_token": token})

    with pytest.raises(AuthenticationError):
        fake.client.authenticate(code="auth-code", state="state-1", **STORED)


def test_authenticate_rejects_tampered_payload(fake: FakeInstance) -> None:
    valid = fake.sign_id_token({"iss": ISSUER, "aud": CLIENT_ID, "sub": "user-1", "nonce": NONCE})
    tampered = _tamper_claim(valid, "sub", "attacker")
    fake.set_token_response({"access_token": "access-abc", "id_token": tampered})

    with pytest.raises(AuthenticationError):
        fake.client.authenticate(code="auth-code", state="state-1", **STORED)


def test_authenticate_rejects_expired_token(fake: FakeInstance) -> None:
    token = fake.sign_id_token(
        {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "user-1",
            "nonce": NONCE,
            "exp": int(time.time()) - 60,  # overrides the default +5m expiry
        }
    )
    fake.set_token_response({"access_token": "access-abc", "id_token": token})

    with pytest.raises(AuthenticationError):
        fake.client.authenticate(code="auth-code", state="state-1", **STORED)


def test_machine_token(fake: FakeInstance) -> None:
    assert fake.client.machine_token(scopes=["reports.read"]) == "machine-token"


def test_introspect(fake: FakeInstance) -> None:
    assert fake.client.introspect("some-token")["active"] is True


def test_revoke_posts_token_and_hint_with_client_auth(fake: FakeInstance) -> None:
    assert fake.client.revoke("refresh-abc", "refresh_token") is None

    expected = base64.b64encode(f"{CLIENT_ID}:secret-xyz".encode()).decode()
    assert fake.revocations == [{"token": "refresh-abc", "token_type_hint": "refresh_token"}]
    assert fake.revocation_auth == [f"Basic {expected}"]


def test_revoke_omits_the_hint_when_not_given(fake: FakeInstance) -> None:
    fake.client.revoke("access-abc")

    assert fake.revocations == [{"token": "access-abc"}]


def test_revoke_requires_a_client_secret(fake: FakeInstance) -> None:
    public_client = CboxIdClient(
        CboxIdConfig(
            issuer=ISSUER, client_id=CLIENT_ID, redirect_uri="https://app.test/auth/callback"
        ),
        http_client=fake.http,
    )
    with pytest.raises(ConfigurationError):
        public_client.revoke("some-token")

    assert fake.revocations == []


def test_accepts_an_es256_id_token(fake: FakeInstance) -> None:
    # An instance that rotated to EC signing keys must not break login.
    token = fake.sign_es256_id_token(
        {"iss": ISSUER, "aud": CLIENT_ID, "sub": "user-1", "nonce": NONCE}
    )
    fake.set_token_response({"access_token": "access-abc", "id_token": token})

    assert fake.client.authenticate(code="auth-code", state="state-1", **STORED).id == "user-1"


def test_refetches_the_jwks_when_the_kid_rotates_mid_ttl(fake: FakeInstance) -> None:
    # Warm the JWKS cache with the pre-rotation key set.
    fake.client.authenticate(code="auth-code", state="state-1", **STORED)
    fetches_before = fake.jwks_fetches

    fake.rotate_signing_key()
    token = fake.sign_id_token({"iss": ISSUER, "aud": CLIENT_ID, "sub": "user-1", "nonce": NONCE})
    fake.set_token_response({"access_token": "access-abc", "id_token": token})

    # Without the kid-miss refetch this raises "No matching key" until the TTL lapses.
    assert fake.client.authenticate(code="auth-code", state="state-1", **STORED).id == "user-1"
    assert fake.jwks_fetches == fetches_before + 1


def test_kid_miss_refetches_only_once_within_the_cooldown(fake: FakeInstance) -> None:
    fake.client.authenticate(code="auth-code", state="state-1", **STORED)
    fetches_before = fake.jwks_fetches

    # A token whose kid the instance never advertised: refetch once, then stop, so a
    # bogus kid cannot turn every login into a JWKS request.
    bogus = jwt.encode(
        {"iss": ISSUER, "aud": CLIENT_ID, "sub": "user-1", "exp": int(time.time()) + 300},
        "a" * 32,
        algorithm="HS256",
        headers={"kid": "no-such-key"},
    )
    fake.set_token_response({"access_token": "access-abc", "id_token": bogus})

    for _ in range(3):
        with pytest.raises(AuthenticationError, match="No matching key"):
            fake.client.authenticate(code="auth-code", state="state-1", **STORED)

    assert fake.jwks_fetches == fetches_before + 1


def test_profile_url(fake: FakeInstance) -> None:
    assert fake.client.profile_url() == f"{ISSUER}/settings"
    assert fake.client.profile_url("https://app.test/home") == (
        f"{ISSUER}/settings?return_to=https%3A%2F%2Fapp.test%2Fhome"
    )


def test_logout_url(fake: FakeInstance) -> None:
    assert fake.client.logout_url("https://app.test") == (
        f"{ISSUER}/oauth/logout?post_logout_redirect_uri=https%3A%2F%2Fapp.test"
    )
