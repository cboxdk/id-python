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
    assert fake.revocations == [
        {"token": "refresh-abc", "client_id": CLIENT_ID, "token_type_hint": "refresh_token"}
    ]
    assert fake.revocation_auth == [f"Basic {expected}"]


def test_revoke_omits_the_hint_when_not_given(fake: FakeInstance) -> None:
    fake.client.revoke("access-abc")

    assert fake.revocations == [{"token": "access-abc", "client_id": CLIENT_ID}]


def test_revoke_works_for_a_public_client(fake: FakeInstance) -> None:
    """The clients that most need revocation were the ones that could not call it.

    A PKCE app authenticates with ``none`` and holds no secret — and it is exactly the
    case where a refresh token sits in storage on a device somebody has just signed out
    of. ``revoke`` raised ``ConfigurationError`` before reaching the network, so every
    such sign-out left the token valid for its whole lifetime.

    The server opened this on 2026-08-12 and advertises ``none`` among its revocation
    auth methods. The assertion this replaces described the world before that.
    """
    public_client = CboxIdClient(
        CboxIdConfig(
            issuer=ISSUER, client_id=CLIENT_ID, redirect_uri="https://app.test/auth/callback"
        ),
        http_client=fake.http,
    )

    assert public_client.revoke("some-token") is None

    assert fake.revocations == [{"token": "some-token", "client_id": CLIENT_ID}]
    # No secret to build one from, and an empty Basic header would authenticate as a
    # confidential client with a blank password — which the server must refuse.
    assert fake.revocation_auth == [None]


def test_oauth_error_code_survives_the_boundary(fake: FakeInstance) -> None:
    """``invalid_grant`` means sign in again; a 503 means retry the same token.

    Collapsing both into one message string is what leaves callers matching on prose,
    and then either retrying what can never succeed or signing out somebody who did not
    need to be.
    """
    fake.fail_next_token({"error": "invalid_grant", "error_description": "Token revoked."}, 400)

    with pytest.raises(AuthenticationError) as caught:
        fake.client.refresh("spent-token")

    assert caught.value.error == "invalid_grant"
    assert caught.value.error_description == "Token revoked."
    assert caught.value.status == 400


def test_does_not_invent_an_error_code(fake: FakeInstance) -> None:
    """A proxy or captive portal answers HTML; the code must stay absent."""
    fake.fail_next_token("<html>502 Bad Gateway</html>", 502)

    with pytest.raises(AuthenticationError) as caught:
        fake.client.refresh("some-token")

    assert caught.value.error is None
    assert caught.value.status == 502


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
    # `/account`, not `/settings`. The latter is the organization-admin page: it
    # redirects a non-admin to `/account` and drops `return_to` on the way, so a
    # member sent there arrived at the right screen having lost the page they came
    # from. Pinned, because the wrong default reads perfectly plausible.
    assert fake.client.profile_url() == f"{ISSUER}/account"
    assert fake.client.profile_url("https://app.test/home") == (
        f"{ISSUER}/account?return_to=https%3A%2F%2Fapp.test%2Fhome"
    )


def test_logout_url_always_carries_client_id(fake: FakeInstance) -> None:
    # The server validates post_logout_redirect_uri against the requesting client's
    # registered allow-list, so a logout URL without client_id can never redirect —
    # it strands the user on a bare "signed out" page. Assert on the parsed query so
    # a regression that drops client_id fails loudly.
    url = fake.client.logout_url("https://app.test")
    assert url is not None
    parsed = urlparse(url)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == f"{ISSUER}/oauth/logout"
    query = parse_qs(parsed.query)
    assert query["client_id"] == [CLIENT_ID]
    assert query["post_logout_redirect_uri"] == ["https://app.test"]
    assert "id_token_hint" not in query

    bare = fake.client.logout_url()
    assert bare is not None
    bare_query = parse_qs(urlparse(bare).query)
    assert bare_query["client_id"] == [CLIENT_ID]
    assert "post_logout_redirect_uri" not in bare_query


def test_logout_url_passes_an_id_token_hint(fake: FakeInstance) -> None:
    url = fake.client.logout_url("https://app.test", id_token_hint="header.payload.sig")
    assert url is not None
    query = parse_qs(urlparse(url).query)
    assert query["id_token_hint"] == ["header.payload.sig"]
    assert query["client_id"] == [CLIENT_ID]


def test_logout_url_omits_an_empty_id_token_hint(fake: FakeInstance) -> None:
    # `session.get("id_token", "")` is the natural caller idiom, and an empty
    # `id_token_hint=` names no subject — a stricter OP may reject it. id-js, id-go
    # and laravel-id-client all drop it; Python must not be the outlier. parse_qs
    # discards blank values, so assert on the raw query string too.
    url = fake.client.logout_url("https://app.test", id_token_hint="")
    assert url is not None
    assert "id_token_hint" not in urlparse(url).query
    assert parse_qs(urlparse(url).query)["client_id"] == [CLIENT_ID]

    bare = fake.client.logout_url(id_token_hint="")
    assert bare is not None
    assert "id_token_hint" not in urlparse(bare).query
