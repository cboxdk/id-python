"""The base every generated management client extends."""

from __future__ import annotations

from collections.abc import Mapping
from types import TracebackType
from typing import Any, ClassVar, Literal, overload

import httpx
from typing_extensions import Self

from .dpop import DPoPSigner
from .models import ApiResponse, ApprovalMode, HttpMethod, PendingApprovalResult, Plane
from .transport import AccessToken, ApprovalHandler, ManagementTransport, RetryOptions


class ManagementClient:
    """Options and lifecycle shared by the four plane clients.

    Exactly one of ``api_key`` and ``access_token``. Server-side code only: every client
    holds a management credential.

    :param base_url: Where the plane is served: an environment's own host
        (``https://acme.cboxid.com``) for the environment and account planes, the
        platform-root host for the workspace and platform planes. ``/api/v1`` is appended
        unless it is already there.
    :param api_key: A management key: ``cbid_env_…`` (environment plane) or ``cbid_ws_…``
        (workspace plane).
    :param access_token: A delegated OAuth access token, or a callable returning one (called
        before every request, so it can refresh). Platform and account planes accept nothing
        else.
    :param environment: Environment plane only, with a person's access token on the
        PLATFORM ROOT's host: the environment to act in, by id or slug, sent as
        ``Cbox-Environment`` on every request.
    :param dpop: Present ``access_token`` as a DPoP-bound token, with a proof per request.
    :param on_approval_required: Called when a write is held for a person's approval, before
        the client starts polling — show ``approval.binding_code`` so they can match it on
        their device.
    :param approval_poll_interval: Seconds between approval polls when the server sends no
        ``Retry-After``.
    :param retry: Retry behaviour (see :class:`RetryOptions`).
    :param timeout: Per-attempt timeout, in seconds.
    :param headers: Headers sent on every request. Cannot override ``Authorization``.
    :param transport: An ``httpx`` transport (e.g. ``httpx.MockTransport`` in tests).
    :param http_client: An ``httpx.Client`` of your own (proxy, custom TLS). Not closed by
        :meth:`close`.
    """

    _plane: ClassVar[Plane]
    _default_base_url: ClassVar[str | None] = None

    #: The transport every method runs on — authentication, retries, approvals.
    core: ManagementTransport

    def __init__(
        self,
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
        self.core = ManagementTransport(
            self._plane,
            base_url=base_url or self._default_base_url,
            api_key=api_key,
            access_token=access_token,
            environment=environment,
            dpop=dpop,
            on_approval_required=on_approval_required,
            approval_poll_interval=approval_poll_interval,
            retry=retry,
            timeout=timeout,
            headers=headers,
            transport=transport,
            http_client=http_client,
        )
        self._bind(self.core)

    def _bind(self, core: ManagementTransport) -> None:
        """Attach the generated namespaces. Overridden by every generated client."""

    @property
    def base_url(self) -> str:
        """The plane's base URL, ending in ``/api/v1``."""
        return self.core.base_url

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
        """Call a route by method and path (relative to ``/api/v1``): anything not generated."""
        return self.core.request(
            method,
            path,
            query=query,
            body=body,
            approval=approval,
            idempotency_key=idempotency_key,
            approval_id=approval_id,
            headers=headers,
        )

    def close(self) -> None:
        """Close the HTTP client, when the client created it."""
        self.core.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
