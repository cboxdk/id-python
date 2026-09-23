"""Organization selection, switching, and the claims a bound session carries."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

from cbox_id import (
    ActiveOrganization,
    Actor,
    AuthenticationError,
    AuthorizationPrompt,
    CboxUser,
    ConfigurationError,
    OrganizationRole,
    actor,
    has_permission,
    has_role,
    is_support_session,
    organization,
    permissions,
    roles,
)

from .conftest import CLIENT_ID, ISSUER, NONCE, FakeInstance

STORED = {"expected_state": "state-1", "code_verifier": "verifier-1", "nonce": NONCE}


def _query(url: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(url).query)


def _issue(fake: FakeInstance, **claims: Any) -> None:
    """Make the next sign-in return an id_token carrying ``claims`` on top of the basics."""
    token = fake.sign_id_token(
        {"iss": ISSUER, "aud": CLIENT_ID, "sub": "user-1", "nonce": NONCE, **claims}
    )
    fake.set_token_response({"access_token": "access-abc", "id_token": token})
    # UserInfo agrees on the subject and carries no org of its own, so what the user ends
    # up with is what the signed token said.
    fake.userinfo_response = {"sub": "user-1"}


# -- the authorization request -----------------------------------------------------


def test_sends_organization_and_echoes_it_for_the_callback(fake: FakeInstance) -> None:
    req = fake.client.create_authorization_request(organization="org-2")

    assert _query(req.url)["organization"] == ["org-2"]
    assert req.organization == "org-2"


def test_sends_an_organization_hint_without_binding(fake: FakeInstance) -> None:
    req = fake.client.create_authorization_request(
        prompt=AuthorizationPrompt.SELECT_ORGANIZATION, organization_hint="org-2"
    )

    query = _query(req.url)
    assert query["organization_hint"] == ["org-2"]
    assert query["prompt"] == ["select_organization"]
    assert "organization" not in query
    # A hint binds nothing, so there is nothing for the callback to hold the tokens to.
    assert req.organization is None


def test_a_plain_sign_in_sends_no_organization(fake: FakeInstance) -> None:
    req = fake.client.create_authorization_request()

    query = _query(req.url)
    assert "organization" not in query
    assert "organization_hint" not in query
    assert "prompt" not in query
    assert req.organization is None


@pytest.mark.parametrize(
    ("prompt", "sent"),
    [
        ("login", "login"),
        ("login consent", "login consent"),
        (["login", "consent", "login"], "login consent"),
        (AuthorizationPrompt.CREATE_ORGANIZATION, "create_organization"),
        (
            [AuthorizationPrompt.LOGIN, AuthorizationPrompt.SELECT_ORGANIZATION],
            "login select_organization",
        ),
    ],
)
def test_prompt_is_sent_space_separated_and_deduplicated(
    fake: FakeInstance, prompt: Any, sent: str
) -> None:
    req = fake.client.create_authorization_request(prompt=prompt)

    assert _query(req.url)["prompt"] == [sent]


@pytest.mark.parametrize("prompt", [["none", "login"], "none consent", ["none", "none", "login"]])
def test_refuses_prompt_none_combined_with_another_value(fake: FakeInstance, prompt: Any) -> None:
    with pytest.raises(ConfigurationError, match="`prompt='none'` cannot be combined"):
        fake.client.create_authorization_request(prompt=prompt)


def test_allows_prompt_none_on_its_own(fake: FakeInstance) -> None:
    req = fake.client.create_authorization_request(prompt=["none", "none"])

    assert _query(req.url)["prompt"] == ["none"]


def test_refuses_organization_with_the_picker_prompt(fake: FakeInstance) -> None:
    with pytest.raises(ConfigurationError, match="Use `organization_hint` to preselect"):
        fake.client.create_authorization_request(
            organization="org-2", prompt=["login", "select_organization"]
        )


def test_refuses_organization_with_the_create_prompt(fake: FakeInstance) -> None:
    with pytest.raises(ConfigurationError, match="creates a new one. Send one or the other"):
        fake.client.create_authorization_request(
            organization="org-2", prompt=AuthorizationPrompt.CREATE_ORGANIZATION
        )


def test_refuses_an_empty_organization(fake: FakeInstance) -> None:
    with pytest.raises(ConfigurationError, match="`organization` is empty"):
        fake.client.create_authorization_request(organization="")


def test_refuses_an_empty_organization_hint(fake: FakeInstance) -> None:
    with pytest.raises(ConfigurationError, match="`organization_hint` is empty"):
        fake.client.create_authorization_request(organization_hint="")


def test_switch_organization_is_a_bound_authorization_request(fake: FakeInstance) -> None:
    req = fake.client.switch_organization("org-2", prompt="login")

    query = _query(req.url)
    assert query["organization"] == ["org-2"]
    assert query["prompt"] == ["login"]
    assert query["code_challenge_method"] == ["S256"]
    assert req.organization == "org-2"


def test_switch_organization_refuses_the_picker_prompt(fake: FakeInstance) -> None:
    with pytest.raises(ConfigurationError, match="has nothing to choose"):
        fake.client.switch_organization("org-2", prompt="select_organization")


# -- the callback ------------------------------------------------------------------


def test_accepts_tokens_for_the_organization_it_was_bound_to(fake: FakeInstance) -> None:
    _issue(fake, org="org-2", org_name="Globex", org_role="admin")

    user = fake.client.authenticate(
        code="auth-code", state="state-1", organization="org-2", **STORED
    )

    assert user.organization_id == "org-2"
    assert user.organization == ActiveOrganization("org-2", "Globex", OrganizationRole.ADMIN)


def test_refuses_tokens_for_another_organization(fake: FakeInstance) -> None:
    # An instance that predates the parameter ignores it and answers for the old org.
    _issue(fake, org="org-1", org_name="Acme")

    with pytest.raises(AuthenticationError) as caught:
        fake.client.authenticate(code="auth-code", state="state-1", organization="org-2", **STORED)

    assert str(caught.value) == (
        "The sign-in was bound to organization org-2, but the tokens are for org-1. "
        "The instance may not support organization selection."
    )


def test_refuses_tokens_bound_to_no_organization(fake: FakeInstance) -> None:
    _issue(fake)

    with pytest.raises(AuthenticationError, match="but the tokens are for no organization"):
        fake.client.authenticate(code="auth-code", state="state-1", organization="org-2", **STORED)


def test_an_unbound_sign_in_accepts_whatever_organization_comes_back(fake: FakeInstance) -> None:
    _issue(fake, org="org-9")

    # `session.get("organization", "")` is how a caller reads a value it never stored.
    user = fake.client.authenticate(code="auth-code", state="state-1", organization="", **STORED)

    assert user.organization_id == "org-9"


def test_the_callback_error_code_reaches_the_caller(fake: FakeInstance) -> None:
    with pytest.raises(AuthenticationError) as caught:
        fake.client.authenticate(
            code=None,
            state="state-1",
            error="access_denied",
            error_description="Not a member of that organization.",
            organization="org-2",
            **STORED,
        )

    assert caught.value.error == "access_denied"
    assert caught.value.error_description == "Not a member of that organization."
    assert str(caught.value) == (
        "Cbox ID returned an error: access_denied (Not a member of that organization.)"
    )


# -- the user and its claims -------------------------------------------------------


def test_the_user_carries_typed_organization_roles_permissions_and_session(
    fake: FakeInstance,
) -> None:
    _issue(
        fake,
        org="org-2",
        org_name="Globex",
        org_role="owner",
        roles=["billing-admin", "", 7],
        permissions=["invoices:create", None],
        sid="sess-1",
    )

    user = fake.client.authenticate(code="auth-code", state="state-1", **STORED)

    assert user.organization is not None
    assert user.organization.role is OrganizationRole.OWNER
    assert user.roles == ["billing-admin"]
    assert user.permissions == ["invoices:create"]
    assert user.has_role("billing-admin")
    assert user.has_permission("invoices:create")
    assert not user.has_permission("invoices:delete")
    assert user.actor is None
    assert user.is_support_session is False
    assert user.session_id == "sess-1"


def test_a_support_session_names_its_actor(fake: FakeInstance) -> None:
    _issue(fake, act={"sub": "staff-7"})

    user = fake.client.authenticate(code="auth-code", state="state-1", **STORED)

    assert user.actor == Actor("staff-7")
    assert user.is_support_session is True
    assert is_support_session(user) is True


def test_session_id_comes_from_the_signed_token_only(fake: FakeInstance) -> None:
    _issue(fake)
    fake.userinfo_response = {"sub": "user-1", "sid": "chosen-by-userinfo"}

    user = fake.client.authenticate(code="auth-code", state="state-1", **STORED)

    assert user.session_id is None


def test_organization_reads_a_raw_claim_set() -> None:
    claims = {"org": "org-1", "org_name": "Acme", "org_role": "developer"}

    assert organization(claims) == ActiveOrganization("org-1", "Acme", OrganizationRole.DEVELOPER)


@pytest.mark.parametrize("org", [None, "", 42])
def test_no_organization_without_an_org_id(org: object) -> None:
    assert organization({"org": org, "org_name": "Acme", "org_role": "owner"}) is None


@pytest.mark.parametrize("tier", ["superadmin", "OWNER", "", 1, ["owner"]])
def test_an_unknown_tier_reads_as_none_never_as_a_guess(tier: object) -> None:
    active = organization({"org": "org-1", "org_role": tier})

    assert active is not None
    assert active.role is None


def test_an_empty_org_name_reads_as_none() -> None:
    active = organization({"org": "org-1", "org_name": ""})

    assert active is not None
    assert active.name is None


def test_an_ordinary_session_has_no_actor() -> None:
    assert actor({"sub": "user-1"}) is None
    assert actor({"sub": "user-1", "act": None}) is None
    assert is_support_session({"sub": "user-1"}) is False


@pytest.mark.parametrize("act", ["staff-7", ["staff-7"], 1, False, "", {}, {"sub": 7}])
def test_a_malformed_act_is_still_a_support_session(act: object) -> None:
    # Fail-closed: a claim the SDK cannot read is not evidence that nobody else is driving.
    assert is_support_session({"sub": "user-1", "act": act}) is True
    assert actor({"sub": "user-1", "act": act}) == Actor(None)


def test_a_chained_actor_is_read_in_order() -> None:
    claims = {"act": {"sub": "staff-7", "act": {"sub": "service-1"}}}

    assert actor(claims) == Actor("staff-7", Actor("service-1"))


def test_actor_nesting_is_bounded_but_still_acted() -> None:
    claim: dict[str, Any] = {"sub": "deepest"}
    for level in range(50):
        claim = {"sub": f"level-{level}", "act": claim}

    found = actor({"act": claim})

    depth = 0
    while found is not None:
        depth += 1
        found = found.actor
    assert depth == 8
    assert is_support_session({"act": claim}) is True


def test_role_and_permission_helpers_read_a_raw_claim_set() -> None:
    claims = {"roles": ["viewer"], "permissions": ["invoices:*", "invoices:read"]}

    assert roles(claims) == ["viewer"]
    assert permissions(claims) == ["invoices:*", "invoices:read"]
    assert has_role(claims, "viewer")
    assert not has_role(claims, "admin")
    # Exact match only: nothing on the issuing side mints a wildcard.
    assert has_permission(claims, "invoices:read")
    assert not has_permission(claims, "invoices:delete")


@pytest.mark.parametrize("value", [None, "invoices:read", {"invoices:read": True}])
def test_a_non_list_claim_grants_nothing(value: object) -> None:
    assert permissions({"permissions": value}) == []
    assert not has_permission({"permissions": value}, "invoices:read")


def test_helpers_read_a_user_through_its_claims() -> None:
    user = CboxUser(
        id="user-1",
        email=None,
        name=None,
        organization_id=None,
        claims={
            "org": "org-1",
            "org_role": "viewer",
            "roles": ["viewer"],
            "permissions": ["reports:read"],
            "act": {"sub": "staff-7"},
        },
        access_token="access",
        refresh_token=None,
        id_token=None,
        expires_in=0,
    )

    active = organization(user)
    assert active is not None
    assert active.role is OrganizationRole.VIEWER
    assert has_role(user, "viewer")
    assert has_permission(user, "reports:read")
    assert actor(user) == Actor("staff-7")


def test_organization_role_compares_as_its_wire_value() -> None:
    assert OrganizationRole.OWNER == "owner"
    assert OrganizationRole("admin") is OrganizationRole.ADMIN
