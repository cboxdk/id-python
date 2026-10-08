"""Value types shared by every management plane: operation specs, responses, approvals."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Generic, Literal, TypeVar

import httpx

#: How much harm an action can do, as the server declares it (``x-danger``).
Danger = Literal["read", "write", "destructive", "critical"]

#: How a list operation pages: an opaque ``after`` cursor, or a ``page`` number.
Pagination = Literal["cursor", "page"]

#: The HTTP methods the management planes use.
HttpMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]

#: ``"wait"`` (default): on ``202 approval_required``, call ``on_approval_required``, poll
#: until the person decides, and repeat the request. ``"return"``: hand the pending
#: approval back as a :class:`PendingApprovalResult` instead.
ApprovalMode = Literal["wait", "return"]

#: The four management planes, each with its own OpenAPI document.
Plane = Literal["environment", "workspace", "platform", "account"]

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class OperationSpec:
    """What the generator knows about one operation.

    Exported per plane (``ENVIRONMENT_OPERATIONS`` …) so tooling can show an action's scope
    and danger before running it.
    """

    #: The action name (``x-action``), e.g. ``apps.secrets.rotate``. ``None`` for a route
    #: that is not an action.
    action: str | None
    operation_id: str | None
    method: HttpMethod
    #: Path relative to ``/api/v1``, with ``{param}`` placeholders.
    path: str
    #: Path parameter names, in the order the method takes them.
    path_params: tuple[str, ...]
    #: The scope the credential must carry, when the spec names one.
    scope: str | None
    danger: Danger | None
    #: Whether the operation can answer ``202 approval_required``.
    approval: bool
    #: Whether the input travels as a JSON body (otherwise as the query string).
    body: bool
    pagination: Pagination | None


@dataclass(frozen=True, slots=True)
class PendingApproval:
    """An approval a key's policy asked for — what a ``202 approval_required`` carries."""

    id: str
    status: str
    #: Show this to the person: the same code appears on the device they approve on.
    binding_code: str
    expires_at: str
    poll_url: str


@dataclass(frozen=True, slots=True)
class ApprovalContext:
    """Handed to ``on_approval_required`` alongside the approval."""

    #: The action held, e.g. ``apps.secrets.rotate``.
    action: str | None
    danger: Danger | None
    method: str
    path: str


@dataclass(frozen=True)
class ApiResponse(Generic[T]):
    """A successful answer. ``data`` is the envelope's ``data``; ``body`` is the whole document."""

    status: int
    data: T
    #: The envelope's ``meta`` (paging, on lists), when there is one.
    meta: dict[str, Any] | None
    body: Any
    #: True when the server answered from its idempotency store (``Idempotent-Replayed:
    #: true``): this is the FIRST request's answer, and any secret it carried (a client
    #: secret, a key's token) is ``None`` — it was shown once, to the request that made it.
    replayed: bool
    #: The ``Idempotency-Key`` a write was sent with.
    idempotency_key: str | None
    #: The id the server served the request under (``X-Request-Id``).
    request_id: str | None
    headers: httpx.Headers = field(repr=False)

    @property
    def pending(self) -> Literal[False]:
        """Always ``False``: this call finished. See :class:`PendingApprovalResult`."""
        return False


@dataclass(frozen=True)
class PendingApprovalResult(Generic[T]):
    """A write held for approval, returned instead of waited on (``approval="return"``).

    ``resume()`` polls until the person decides and repeats the request with the approval
    and the same ``Idempotency-Key``.
    """

    approval: PendingApproval
    idempotency_key: str | None
    #: The action that was held, e.g. ``apps.secrets.rotate``.
    action: str | None
    _resume: Callable[[], ApiResponse[T]] = field(repr=False, compare=False)

    @property
    def pending(self) -> Literal[True]:
        """Always ``True``: the call is waiting for a person's approval."""
        return True

    @property
    def status(self) -> Literal[202]:
        return 202

    def resume(self) -> ApiResponse[T]:
        """Poll the approval until the person decides, then repeat the request.

        Raises :class:`~cbox_id.management.ApprovalDeniedError` or
        :class:`~cbox_id.management.ApprovalExpiredError` when it is not approved.
        """
        return self._resume()
