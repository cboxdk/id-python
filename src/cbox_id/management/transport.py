"""The hand-written core every generated management client runs on.

Authentication, idempotency keys, retries, the approval loop, error typing and pagination
live here. Generated code only describes operations; it never talks to the network itself.
"""

from __future__ import annotations

import json
import math
import random
import time
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Literal, overload
from urllib.parse import quote, urljoin, urlsplit

import httpx

from ..errors import CboxIdError, ConfigurationError
from .dpop import DPoPSigner
from .errors import (
    ApprovalDeniedError,
    ApprovalError,
    ApprovalExpiredError,
    CboxIdApiError,
    ManagementNetworkError,
)
from .models import (
    ApiResponse,
    ApprovalContext,
    ApprovalMode,
    HttpMethod,
    OperationSpec,
    PendingApproval,
    PendingApprovalResult,
    Plane,
)

#: A delegated access token, or a callable returning one (called before every request, so
#: it can refresh).
AccessToken = str | Callable[[], str]

#: Called when a write is held for a person's approval, before the client starts polling.
ApprovalHandler = Callable[[PendingApproval, ApprovalContext], None]

_KEY_PREFIX: dict[str, str | None] = {
    "environment": "cbid_env_",
    "workspace": "cbid_ws_",
    "platform": None,
    "account": None,
}

#: Where each plane serves ``GET …/action-approvals/{id}``, relative to ``/api/v1``.
_APPROVAL_MOUNT: dict[str, str] = {
    "environment": "",
    "workspace": "/workspace",
    "platform": "/platform",
    "account": "/me",
}

_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

#: How many approvals one call will go through before giving up (a policy loop guard).
_MAX_APPROVAL_ROUNDS = 3

_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})


@dataclass(frozen=True, slots=True)
class RetryOptions:
    """Retries for network failures, ``5xx``, ``429`` and ``409 idempotency_in_progress``."""

    #: Retries after the first attempt. ``0`` turns retrying off.
    max_retries: int = 3
    #: First backoff delay (seconds), doubled per attempt with jitter.
    base_delay: float = 0.5
    #: The longest the client waits before one retry (seconds). A ``Retry-After`` longer
    #: than this is not waited out: the ``429``/``503`` is raised, with ``retry_after`` set.
    max_delay: float = 30.0


def retry_after_seconds(headers: httpx.Headers) -> float | None:
    """``Retry-After`` in seconds, from delta-seconds or an HTTP date.

    ``None`` when the header is absent or unparseable.
    """
    raw = headers.get("retry-after", "").strip()

    if raw == "":
        return None

    if raw.isdigit():
        return float(raw)

    try:
        when = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None

    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)

    return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())


def _normalize_base_url(raw: str) -> str:
    parts = urlsplit(raw)

    if parts.scheme == "" or parts.hostname is None:
        raise ConfigurationError("Management client `base_url` is not a valid URL.")

    loopback = parts.hostname in _LOOPBACK

    if parts.scheme != "https" and not (parts.scheme == "http" and loopback):
        # Every request carries a management credential. Over http a network attacker reads it.
        raise ConfigurationError(
            f"Management client `base_url` must be https (got {parts.scheme}://{parts.hostname})."
        )

    path = parts.path.rstrip("/")
    path = path if path.endswith("/api/v1") else f"{path}/api/v1"

    return f"{parts.scheme}://{parts.netloc}{path}"


def _origin(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url)
    default = {"https": 443, "http": 80}.get(parts.scheme)
    return (parts.scheme, (parts.hostname or "").lower(), parts.port or default)


def _query_pairs(query: Mapping[str, Any]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []

    def add(key: str, value: Any) -> None:
        if value is None:
            return

        if isinstance(value, (list, tuple)):
            for item in value:
                add(f"{key}[]", item)
            return

        if isinstance(value, bool):
            # Laravel's `boolean` rule takes 1/0, not the strings "true"/"false".
            pairs.append((key, "1" if value else "0"))
            return

        if isinstance(value, Mapping):
            pairs.append((key, json.dumps(value, separators=(",", ":"))))
            return

        pairs.append((key, str(value)))

    for key, value in query.items():
        add(key, value)

    return pairs


def _read_json(response: httpx.Response) -> Any:
    if not response.content:
        return None

    try:
        return response.json()
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class _Held:
    approval: PendingApproval
    retry_after: float | None


@dataclass(frozen=True, slots=True)
class _Request:
    method: str
    url: str
    params: tuple[tuple[str, str], ...] | None
    payload: Any
    has_body: bool
    idempotency_key: str | None
    headers: Mapping[str, str] | None


class ManagementTransport:
    """Runs operations for one plane: credentials, retries, approvals and paging.

    Every generated client holds one as ``client.core``. ``call()`` takes an
    :class:`OperationSpec`, so a route the generator does not know can still be called with
    one you build yourself — or through ``client.request(method, path, …)``.
    """

    def __init__(
        self,
        plane: Plane,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        access_token: AccessToken | None = None,
        environment: str | None = None,
        dpop: DPoPSigner | None = None,
        on_approval_required: ApprovalHandler | None = None,
        approval_poll_interval: float = 2.0,
        retry: RetryOptions | None = None,
        timeout: float = 30.0,
        headers: Mapping[str, str] | None = None,
        transport: httpx.BaseTransport | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        if base_url is None or base_url == "":
            raise ConfigurationError(
                f"The {plane} management client needs a `base_url` (the environment's own host)."
            )

        has_key = api_key is not None
        has_token = access_token is not None

        if has_key == has_token:
            raise ConfigurationError(
                "Pass exactly one of `api_key` and `access_token` to a management client."
            )

        if api_key is not None:
            expected = _KEY_PREFIX[plane]

            if api_key == "":
                raise ConfigurationError("Management client `api_key` is empty.")

            if expected is None:
                raise ConfigurationError(
                    f"The {plane} plane accepts no management key — only an access token a "
                    "person delegated (`access_token`)."
                )

            for prefix in _KEY_PREFIX.values():
                if prefix is not None and prefix != expected and api_key.startswith(prefix):
                    # Credentials never cross planes: the server would answer 401 to every request.
                    raise ConfigurationError(
                        f"A `{prefix}…` key cannot call the {plane} plane; "
                        f"it takes `{expected}…` keys."
                    )

            if dpop is not None:
                raise ConfigurationError(
                    "`dpop` applies to an `access_token`, not a management key."
                )

        if environment is not None:
            if plane != "environment":
                raise ConfigurationError(
                    f"`environment` applies to the environment plane, not the {plane} plane."
                )

            if environment == "":
                raise ConfigurationError("Management client `environment` is empty.")

            if has_key:
                raise ConfigurationError(
                    "`environment` names the environment for a root access token. A "
                    "`cbid_env_…` key is bound to its own environment's host: use that host "
                    "as `base_url` instead."
                )

        self.plane: Plane = plane
        self.base_url = _normalize_base_url(base_url)
        self._api_key = api_key
        self._access_token = access_token
        self._environment = environment
        self._dpop = dpop
        self._dpop_nonce: str | None = None
        self._on_approval_required = on_approval_required
        self._poll_interval = max(0.0, approval_poll_interval)
        options = retry or RetryOptions()
        self._max_retries = max(0, options.max_retries)
        self._base_delay = max(0.0, options.base_delay)
        self._max_delay = max(0.0, options.max_delay)
        self._timeout = timeout
        self._headers = dict(headers or {})
        self._owns_client = http_client is None
        self._http = http_client or httpx.Client(timeout=timeout, transport=transport)
        #: Sleeps between retries and polls. Replaceable, e.g. to cap waits in tests.
        self.sleep: Callable[[float], None] = time.sleep

    def close(self) -> None:
        """Close the HTTP client, when this transport created it."""
        if self._owns_client:
            self._http.close()

    # ── Calls ────────────────────────────────────────────────────────────────────────────

    @overload
    def call(
        self,
        op: OperationSpec,
        path_args: Sequence[str],
        input: Any = None,
        *,
        approval: Literal["wait"] = "wait",
        idempotency_key: str | None = None,
        approval_id: str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> ApiResponse[Any]: ...

    @overload
    def call(
        self,
        op: OperationSpec,
        path_args: Sequence[str],
        input: Any = None,
        *,
        approval: ApprovalMode,
        idempotency_key: str | None = None,
        approval_id: str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> ApiResponse[Any] | PendingApprovalResult[Any]: ...

    def call(
        self,
        op: OperationSpec,
        path_args: Sequence[str],
        input: Any = None,
        *,
        approval: ApprovalMode = "wait",
        idempotency_key: str | None = None,
        approval_id: str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> ApiResponse[Any] | PendingApprovalResult[Any]:
        """Run one operation. Generated methods call this; so can you, with an OperationSpec."""
        url = self._url(op, path_args)
        params = None if op.body or not isinstance(input, Mapping) else _query_pairs(input)
        key = (idempotency_key or str(uuid.uuid4())) if op.method in _WRITE_METHODS else None
        request = _Request(
            method=op.method,
            url=url,
            params=tuple(params) if params else None,
            payload=input if op.body else None,
            has_body=op.body and input is not None,
            idempotency_key=key,
            headers=headers,
        )
        context = ApprovalContext(
            action=op.action, danger=op.danger, method=op.method, path=op.path
        )

        response = self._send(request, approval_id)
        held = self._held_approval(response)

        if held is not None and approval == "return":
            return PendingApprovalResult(
                approval=held.approval,
                idempotency_key=key,
                action=op.action,
                _resume=lambda: self._approve_and_repeat(request, held, context, notify=False),
            )

        if held is not None:
            return self._approve_and_repeat(request, held, context, notify=True)

        return self._result(response, key)

    def paginate(
        self,
        op: OperationSpec,
        path_args: Sequence[str],
        query: Mapping[str, Any] | None = None,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> Iterator[Any]:
        """Every item of a paged list, fetching pages as the iteration reaches them.

        Works for both cursor (``after`` / ``meta.next_cursor``) and numbered (``page`` /
        ``meta.next_page``) lists.
        """
        current: dict[str, Any] = dict(query or {})

        while True:
            page = self.call(op, path_args, current, headers=headers)
            items = page.data if isinstance(page.data, list) else []

            yield from items

            meta = page.meta or {}

            if not items or meta.get("has_more") is not True:
                return

            if op.pagination == "page":
                raw = current.get("page", 1)
                number = raw if isinstance(raw, int) else int(str(raw))
                next_page = meta.get("next_page")
                current = {**current, "page": next_page if next_page is not None else number + 1}
            else:
                cursor = meta.get("next_cursor")

                if not isinstance(cursor, str) or cursor == "":
                    return

                current = {**current, "after": cursor}

    @overload
    def request(
        self,
        method: HttpMethod,
        path: str,
        *,
        query: Mapping[str, Any] | None = None,
        body: Any = None,
        approval: Literal["wait"] = "wait",
        idempotency_key: str | None = None,
        approval_id: str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> ApiResponse[Any]: ...

    @overload
    def request(
        self,
        method: HttpMethod,
        path: str,
        *,
        query: Mapping[str, Any] | None = None,
        body: Any = None,
        approval: ApprovalMode,
        idempotency_key: str | None = None,
        approval_id: str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> ApiResponse[Any] | PendingApprovalResult[Any]: ...

    def request(
        self,
        method: HttpMethod,
        path: str,
        *,
        query: Mapping[str, Any] | None = None,
        body: Any = None,
        approval: ApprovalMode = "wait",
        idempotency_key: str | None = None,
        approval_id: str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> ApiResponse[Any] | PendingApprovalResult[Any]:
        """Call a route the generated surface does not cover. ``path`` is relative to ``/api/v1``.

        Writes get an ``Idempotency-Key`` and the approval loop like any operation.
        """
        op = OperationSpec(
            action=None,
            operation_id=None,
            method=method,
            path=path,
            path_params=(),
            scope=None,
            danger=None,
            approval=True,
            body=body is not None,
            pagination=None,
        )

        return self.call(
            op,
            (),
            body if body is not None else query,
            approval=approval,
            idempotency_key=idempotency_key,
            approval_id=approval_id,
            headers=headers,
        )

    # ── Internals ────────────────────────────────────────────────────────────────────────

    def _url(self, op: OperationSpec, path_args: Sequence[str]) -> str:
        args = list(path_args)
        path = op.path
        start = 0

        while (open_at := path.find("{", start)) != -1:
            close_at = path.index("}", open_at)
            name = path[open_at + 1 : close_at]
            value = args.pop(0) if args else ""

            if not isinstance(value, str) or value == "":
                raise TypeError(f"{op.action or op.path}: missing path parameter `{name}`.")

            encoded = quote(value, safe="")
            path = f"{path[:open_at]}{encoded}{path[close_at + 1 :]}"
            start = open_at + len(encoded)

        return f"{self.base_url}{path}"

    def _token(self) -> str:
        source = self._access_token
        token = source() if callable(source) else source

        if not isinstance(token, str) or token == "":
            raise ConfigurationError(
                "The management client `access_token` provider returned no token."
            )

        return token

    def _build(self, request: _Request, approval_id: str | None) -> httpx.Request:
        headers = httpx.Headers({**self._headers, **(request.headers or {})})
        headers["Accept"] = "application/json"

        if request.has_body:
            headers["Content-Type"] = "application/json"

        if request.idempotency_key is not None:
            headers["Idempotency-Key"] = request.idempotency_key

        if approval_id is not None:
            headers["Cbox-Approval"] = approval_id

        if self._environment is not None:
            headers["Cbox-Environment"] = self._environment

        if self._api_key is not None:
            headers["Authorization"] = f"Bearer {self._api_key}"
        else:
            token = self._token()

            if self._dpop is None:
                headers["Authorization"] = f"Bearer {token}"
            else:
                headers["Authorization"] = f"DPoP {token}"
                headers["DPoP"] = self._dpop.proof(
                    method=request.method,
                    url=request.url,
                    access_token=token,
                    nonce=self._dpop_nonce,
                )

        content = json.dumps(request.payload).encode() if request.has_body else None

        return self._http.build_request(
            request.method,
            request.url,
            params=request.params,
            headers=headers,
            content=content,
            timeout=self._timeout,
        )

    def _exchange(self, request: _Request, approval_id: str | None) -> httpx.Response:
        """One HTTP exchange, plus the single DPoP-nonce challenge retry RFC 9449 §8 describes."""
        nonce_retry = 0

        while True:
            response = self._http.send(self._build(request, approval_id))
            nonce = response.headers.get("dpop-nonce")

            if nonce is not None and self._dpop is not None:
                challenged = (
                    response.status_code == 401 and nonce != self._dpop_nonce and nonce_retry == 0
                )
                self._dpop_nonce = nonce

                if challenged:
                    response.close()
                    nonce_retry += 1
                    continue

            return response

    def _should_retry(self, response: httpx.Response) -> bool:
        if response.status_code >= 500 or response.status_code == 429:
            return True

        if response.status_code == 409:
            # The first request with this Idempotency-Key is still running: its answer is coming.
            body = _read_json(response)
            return isinstance(body, dict) and body.get("error") == "idempotency_in_progress"

        return False

    def _backoff(self, attempt: int) -> float:
        exponential: float = self._base_delay * 2**attempt
        return min(self._max_delay, exponential / 2 + random.random() * (exponential / 2))

    def _send(self, request: _Request, approval_id: str | None) -> httpx.Response:
        """Send with retries. Every attempt carries the SAME Idempotency-Key: a write lands once."""
        attempt = 0

        while True:
            try:
                response = self._exchange(request, approval_id)
            except httpx.TransportError as exc:
                if attempt >= self._max_retries:
                    path = urlsplit(request.url).path
                    raise ManagementNetworkError(
                        f"{request.method} {path} failed: {exc}", request.idempotency_key
                    ) from exc

                self.sleep(self._backoff(attempt))
                attempt += 1
                continue

            if attempt >= self._max_retries or not self._should_retry(response):
                return response

            delay = retry_after_seconds(response.headers)
            delay = self._backoff(attempt) if delay is None else delay

            if delay > self._max_delay:
                return response

            response.close()
            self.sleep(delay)
            attempt += 1

    def _held_approval(self, response: httpx.Response) -> _Held | None:
        if response.status_code != 202:
            return None

        body = _read_json(response)

        if not isinstance(body, dict) or body.get("error") != "approval_required":
            return None

        approval = body.get("approval")

        if not isinstance(approval, dict):
            return None

        approval_id = approval.get("id")

        if not isinstance(approval_id, str) or approval_id == "":
            return None

        def text(name: str, default: str) -> str:
            value = approval.get(name)
            return value if isinstance(value, str) else default

        mount = _APPROVAL_MOUNT[self.plane]
        fallback = f"{self.base_url}{mount}/action-approvals/{quote(approval_id, safe='')}"

        return _Held(
            approval=PendingApproval(
                id=approval_id,
                status=text("status", "pending"),
                binding_code=text("binding_code", ""),
                expires_at=text("expires_at", ""),
                poll_url=text("poll_url", fallback),
            ),
            retry_after=retry_after_seconds(response.headers),
        )

    def _approve_and_repeat(
        self, request: _Request, first: _Held, context: ApprovalContext, *, notify: bool
    ) -> ApiResponse[Any]:
        held = first
        round_ = 1

        while True:
            if (notify or round_ > 1) and self._on_approval_required is not None:
                self._on_approval_required(held.approval, context)

            self._await_approval(held.approval, held.retry_after)

            response = self._send(request, held.approval.id)
            again = self._held_approval(response)

            if again is None:
                return self._result(response, request.idempotency_key)

            if round_ >= _MAX_APPROVAL_ROUNDS:
                raise ApprovalError(
                    f"The request was held for approval {round_} times; giving up.",
                    "consumed",
                    again.approval,
                )

            held = again
            round_ += 1

    def _await_approval(self, approval: PendingApproval, initial_delay: float | None) -> None:
        """Poll an approval until the person decides. Returns on ``approved``; raises otherwise."""
        poll_url = urljoin(self.base_url, approval.poll_url)

        if _origin(poll_url) != _origin(self.base_url):
            # The poll carries the same credential as the request. Never hand it to another host.
            scheme, host, _ = _origin(poll_url)
            raise CboxIdError(
                f"Refusing to poll approval {approval.id} at another origin ({scheme}://{host})."
            )

        expires_at = _parse_time(approval.expires_at)
        delay = initial_delay if initial_delay is not None else self._poll_interval
        poll = _Request("GET", poll_url, None, None, False, None, None)

        while True:
            self.sleep(min(delay, 60.0))

            response = self._send(poll, None)

            if not response.is_success:
                raise self._error(response)

            body = _read_json(response)
            data = body.get("data") if isinstance(body, dict) else None
            status = data.get("status") if isinstance(data, dict) else None

            if status == "approved":
                return
            if status == "denied":
                raise ApprovalDeniedError(approval)
            if status == "expired":
                raise ApprovalExpiredError(approval)
            if status == "consumed":
                raise ApprovalError(
                    f"Approval {approval.id} was already used by another request.",
                    "consumed",
                    approval,
                )

            if expires_at is not None and time.time() > expires_at + 30:
                raise ApprovalExpiredError(approval)

            retry = retry_after_seconds(response.headers)
            delay = retry if retry is not None else self._poll_interval

    def _result(self, response: httpx.Response, idempotency_key: str | None) -> ApiResponse[Any]:
        if not response.is_success:
            raise self._error(response)

        body = None if response.status_code == 204 else _read_json(response)
        envelope = isinstance(body, dict) and "data" in body
        meta = body.get("meta") if isinstance(body, dict) and envelope else None

        return ApiResponse(
            status=response.status_code,
            data=body["data"] if isinstance(body, dict) and envelope else body,
            meta=meta if isinstance(meta, dict) else None,
            body=body,
            replayed=response.headers.get("idempotent-replayed", "").lower() == "true",
            idempotency_key=idempotency_key,
            request_id=response.headers.get("x-request-id"),
            headers=response.headers,
        )

    def _error(self, response: httpx.Response) -> CboxIdApiError:
        body = _read_json(response)
        fields: dict[str, Any] = body if isinstance(body, dict) else {}
        code = fields.get("error")
        code = code if isinstance(code, str) else f"http_{response.status_code}"
        # A bearer challenge (RFC 6750) says `error_description`, the management envelope `message`.
        message = fields.get("message")

        if not isinstance(message, str):
            description = fields.get("error_description")
            message = (
                description if isinstance(description, str) else f"HTTP {response.status_code}"
            )

        errors: dict[str, list[str]] = {}
        raw_errors = fields.get("errors")

        if isinstance(raw_errors, dict):
            for name, messages in raw_errors.items():
                errors[str(name)] = (
                    [str(m) for m in messages] if isinstance(messages, list) else [str(messages)]
                )

        retry_after = retry_after_seconds(response.headers)
        # The envelope's `request_id` first: a proxy in between may rewrite or drop the header.
        request_id = fields.get("request_id")

        if not isinstance(request_id, str) or request_id == "":
            request_id = response.headers.get("x-request-id")

        return CboxIdApiError(
            status=response.status_code,
            error=code,
            message=message,
            errors=errors,
            request_id=request_id,
            retry_after=None if retry_after is None else math.ceil(retry_after),
        )


def _parse_time(value: str) -> float | None:
    if value == "":
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.timestamp()
