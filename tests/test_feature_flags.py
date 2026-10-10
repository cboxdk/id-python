"""The feature_flags claim on a signed-in user and on a raw claim set."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest

from cbox_id import (
    FEATURE_FLAGS_SCOPE,
    CboxIdClient,
    CboxIdConfig,
    feature_flags,
    has_feature,
)

from .conftest import CLIENT_ID, ISSUER, NONCE, FakeInstance

STORED = {"expected_state": "state-1", "code_verifier": "verifier-1", "nonce": NONCE}


def test_the_user_carries_the_flags_and_answers_has_feature(fake: FakeInstance) -> None:
    fake.userinfo_response = {"sub": "user-1", "feature_flags": ["acme-beta", "new-dashboard"]}

    user = fake.client.authenticate(code="auth-code", state="state-1", **STORED)

    assert user.feature_flags == ["acme-beta", "new-dashboard"]
    assert user.has_feature("new-dashboard")
    assert not user.has_feature("old-reports")
    assert has_feature(user, "acme-beta")


def test_an_absent_claim_is_none_not_empty(fake: FakeInstance) -> None:
    user = fake.client.authenticate(code="auth-code", state="state-1", **STORED)

    assert user.feature_flags is None
    assert not user.has_feature("anything")


def test_the_scope_is_requested_like_any_other(fake: FakeInstance) -> None:
    config = CboxIdConfig(
        issuer=ISSUER,
        client_id=CLIENT_ID,
        redirect_uri="https://app.test/auth/callback",
        scopes=["openid", FEATURE_FLAGS_SCOPE],
    )
    request = CboxIdClient(config, http_client=fake.http).create_authorization_request()

    assert FEATURE_FLAGS_SCOPE == "feature_flags"
    assert parse_qs(urlparse(request.url).query)["scope"] == ["openid feature_flags"]


def test_not_requested_and_nothing_on_are_different() -> None:
    assert feature_flags({}) is None
    assert feature_flags({"feature_flags": []}) == []
    assert not has_feature({"feature_flags": []}, "x")


def test_anything_that_is_not_a_key_is_dropped_and_matching_is_exact() -> None:
    claims = {"feature_flags": ["billing.v2", 7, "", None]}

    assert feature_flags(claims) == ["billing.v2"]
    assert has_feature(claims, "billing.v2")
    assert not has_feature(claims, "billing")


@pytest.mark.parametrize("claim", ["new-dashboard", {"new-dashboard": True}, 1])
def test_a_malformed_claim_reads_as_absent_never_as_on(claim: object) -> None:
    assert feature_flags({"feature_flags": claim}) is None
    assert not has_feature({"feature_flags": claim}, "new-dashboard")
