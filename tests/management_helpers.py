"""A fake management API: answers from a queue and records every request it saw."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

from cbox_id.management import EnvironmentClient, RetryOptions

HOST = "https://acme.test"
API = f"{HOST}/api/v1"
KEY = "cbid_env_test_key"


@dataclass
class Call:
    method: str
    url: str
    headers: httpx.Headers
    body: Any


Reply = httpx.Response | Exception | Callable[[Call], httpx.Response | Exception]


class FakeApi:
    def __init__(self, *replies: Reply) -> None:
        self.replies: list[Reply] = list(replies)
        self.calls: list[Call] = []
        self.transport = httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        content = request.read()
        call = Call(
            method=request.method,
            url=str(request.url),
            headers=request.headers,
            body=json.loads(content) if content else None,
        )
        self.calls.append(call)

        if not self.replies:
            raise AssertionError(f"unexpected request {call.method} {call.url}")

        reply = self.replies.pop(0)
        answer = reply(call) if callable(reply) else reply

        if isinstance(answer, Exception):
            raise answer

        return answer


def json_response(
    body: object, status: int = 200, headers: dict[str, str] | None = None
) -> httpx.Response:
    return httpx.Response(status, json=body, headers=headers or {})


def env_client(fake: FakeApi, **options: Any) -> EnvironmentClient:
    settings: dict[str, Any] = {
        "base_url": HOST,
        "api_key": KEY,
        "transport": fake.transport,
        "retry": RetryOptions(base_delay=0),
        "approval_poll_interval": 0,
        **options,
    }
    return EnvironmentClient(**settings)


def held(apr: str = "apr_1", poll_url: str | None = None) -> httpx.Response:
    return json_response(
        {
            "error": "approval_required",
            "message": "This action needs approval.",
            "approval": {
                "id": apr,
                "status": "pending",
                "binding_code": "K7-4Q",
                "expires_at": "2999-01-01T00:00:00Z",
                "poll_url": poll_url or f"{API}/action-approvals/{apr}",
            },
        },
        202,
        {"Retry-After": "0"},
    )


def approval_status(status: str, apr: str = "apr_1") -> httpx.Response:
    return json_response({"data": {"id": apr, "status": status}}, 200, {"Retry-After": "0"})
