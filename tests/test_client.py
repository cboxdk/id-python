from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest

from cbox_id import AuthenticationError, InvalidStateError
from cbox_id.pkce import challenge

from .conftest import CLIENT_ID, ISSUER, NONCE, FakeInstance

STORED = {"expected_state": "state-1", "code_verifier": "verifier-1", "nonce": NONCE}


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


def test_authenticate_rejects_mismatched_state(fake: FakeInstance) -> None:
    with pytest.raises(InvalidStateError):
        fake.client.authenticate(code="auth-code", state="forged", **STORED)


def test_authenticate_surfaces_provider_error(fake: FakeInstance) -> None:
    with pytest.raises(AuthenticationError, match="access_denied"):
        fake.client.authenticate(
            code=None, state="state-1", error="access_denied", **STORED
        )


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


def test_machine_token(fake: FakeInstance) -> None:
    assert fake.client.machine_token(scopes=["reports.read"]) == "machine-token"


def test_introspect(fake: FakeInstance) -> None:
    assert fake.client.introspect("some-token")["active"] is True


def test_profile_url(fake: FakeInstance) -> None:
    assert fake.client.profile_url() == f"{ISSUER}/settings"
    assert fake.client.profile_url("https://app.test/home") == (
        f"{ISSUER}/settings?return_to=https%3A%2F%2Fapp.test%2Fhome"
    )


def test_logout_url(fake: FakeInstance) -> None:
    assert fake.client.logout_url("https://app.test") == (
        f"{ISSUER}/oauth/logout?post_logout_redirect_uri=https%3A%2F%2Fapp.test"
    )
