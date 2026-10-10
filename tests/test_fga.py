"""Feature flag evaluation and fine-grained authorization through the environment client."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest

from cbox_id.management import fga_tuple

from .management_helpers import API, FakeApi, env_client, json_response

CHECK = {
    "allowed": True,
    "resource_type": "document",
    "resource_id": "leave",
    "relation": "viewer",
    "subject": {"type": "user", "id": "alice", "relation": None},
    "consistency_token": "7.9f3c1a7be2d0",
}


def test_evaluates_every_flag_for_a_user_in_an_organization() -> None:
    data = {
        "user_id": "usr_1",
        "organization_id": "org_1",
        "feature_flags": ["acme-beta"],
        "evaluations": [
            {"key": "acme-beta", "enabled": True, "reason": "organization_target"},
            {"key": "old-reports", "enabled": False, "reason": "disabled"},
        ],
    }
    fake = FakeApi(json_response({"data": data}))

    result = env_client(fake).feature_flags.evaluate(
        {"user_id": "usr_1", "organization_id": "org_1"}
    )

    assert fake.calls[0].url == f"{API}/feature-flags/evaluate?user_id=usr_1&organization_id=org_1"
    assert result.data["feature_flags"] == ["acme-beta"]
    assert result.data["evaluations"][1]["reason"] == "disabled"


def test_writes_then_checks_at_least_as_fresh_as_the_write() -> None:
    fake = FakeApi(
        json_response({"data": {"written": 1, "deleted": 0, "consistency_token": "7.9f"}}),
        json_response({"data": CHECK}),
    )
    env = env_client(fake)

    written = env.fga.tuples.write(
        {
            "tuples": [
                {
                    "resource_type": "group",
                    "resource_id": "eng",
                    "relation": "member",
                    "subject": {"type": "user", "id": "alice"},
                }
            ]
        }
    )
    answer = env.fga.check(
        {
            "resource_type": "document",
            "resource_id": "leave",
            "relation": "viewer",
            "subject_type": "user",
            "subject_id": "alice",
            "consistency_token": written.data["consistency_token"],
        }
    )

    assert fake.calls[0].method == "POST"
    assert fake.calls[0].url == f"{API}/fga/tuples"
    assert fake.calls[0].headers.get("idempotency-key")
    assert parse_qs(urlparse(fake.calls[1].url).query)["consistency_token"] == ["7.9f"]
    assert answer.data["allowed"] is True


def test_sends_a_batch_as_checks_in_the_tuple_notation() -> None:
    fake = FakeApi(
        json_response(
            {"data": {"results": [CHECK, {**CHECK, "allowed": False}], "consistency_token": "7"}}
        )
    )

    result = env_client(fake).fga.check_batch(
        {
            "checks": [
                fga_tuple(
                    {
                        "resource_type": "document",
                        "resource_id": "leave",
                        "relation": "viewer",
                        "subject": {"type": "user", "id": "alice"},
                    }
                ),
                "document:readme#editor@user:alice",
            ]
        }
    )

    url = urlparse(fake.calls[0].url)
    assert url.path == "/api/v1/fga/check/batch"
    assert parse_qs(url.query)["checks[]"] == [
        "document:leave#viewer@user:alice",
        "document:readme#editor@user:alice",
    ]
    assert [r["allowed"] for r in result.data["results"]] == [True, False]


def test_deletes_lists_and_reads_and_replaces_the_schema() -> None:
    schema = {
        "defined": True,
        "schema": "type user",
        "version": 2,
        "types": [],
        "updated_at": None,
        "consistency_token": "8.b",
    }
    page = {"has_more": False, "next_cursor": None}
    fake = FakeApi(
        json_response({"data": {"written": 0, "deleted": 1, "consistency_token": "8.a"}}),
        json_response({"data": [{"type": "document", "id": "leave"}], "meta": page}),
        json_response({"data": [{"type": "user", "id": "alice"}], "meta": page}),
        json_response({"data": schema}),
        json_response({"data": schema}),
    )
    env = env_client(fake)
    tuple_ = {
        "resource_type": "group",
        "resource_id": "eng",
        "relation": "member",
        "subject": {"type": "user", "id": "alice"},
    }

    assert env.fga.tuples.delete({"tuples": [tuple_]}).data["deleted"] == 1
    resources = env.fga.resources.list(
        {
            "resource_type": "document",
            "relation": "viewer",
            "subject_type": "user",
            "subject_id": "alice",
        }
    )
    subjects = env.fga.subjects.list(
        {
            "resource_type": "document",
            "resource_id": "leave",
            "relation": "viewer",
            "subject_type": "user",
            "consistency_token": "8.a",
        }
    )
    env.fga.schema.get()
    env.fga.schema.update({"schema": "type user"})

    assert [f"{c.method} {urlparse(c.url).path}" for c in fake.calls] == [
        "POST /api/v1/fga/tuples/delete",
        "GET /api/v1/fga/resources",
        "GET /api/v1/fga/subjects",
        "GET /api/v1/fga/schema",
        "PUT /api/v1/fga/schema",
    ]
    assert parse_qs(urlparse(fake.calls[2].url).query)["consistency_token"] == ["8.a"]
    assert fake.calls[4].body == {"schema": "type user"}
    assert resources.data == [{"type": "document", "id": "leave"}]
    assert subjects.data[0]["id"] == "alice"


def test_fga_tuple_writes_one_subject_and_a_userset() -> None:
    assert (
        fga_tuple(
            {
                "resource_type": "folder",
                "resource_id": "policies",
                "relation": "viewer",
                "subject": {"type": "group", "id": "eng", "relation": "member"},
            }
        )
        == "folder:policies#viewer@group:eng#member"
    )
    # Ids are the app's own and may carry a colon.
    assert (
        fga_tuple(
            {
                "resource_type": "doc",
                "resource_id": "a:b",
                "relation": "viewer",
                "subject": {"type": "user", "id": "u:1"},
            }
        )
        == "doc:a:b#viewer@user:u:1"
    )


@pytest.mark.parametrize(
    ("resource_type", "resource_id", "subject_id"),
    [("doc", "a#b", "x"), ("doc", "a", "x@y"), ("doc:x", "a", "x"), ("doc", "", "x")],
)
def test_fga_tuple_refuses_what_the_notation_cannot_carry(
    resource_type: str, resource_id: str, subject_id: str
) -> None:
    with pytest.raises(ValueError):
        fga_tuple(
            {
                "resource_type": resource_type,
                "resource_id": resource_id,
                "relation": "viewer",
                "subject": {"type": "user", "id": subject_id},
            }
        )


def test_an_action_that_answers_202_returns_its_own_body() -> None:
    directory = {"id": "dir_1", "name": "Workday"}
    fake = FakeApi(json_response({"data": directory}, 202))

    result = env_client(fake).directories.sync("dir_1", {"full": True})

    assert len(fake.calls) == 1
    assert result.status == 202
    assert result.data["id"] == "dir_1"
