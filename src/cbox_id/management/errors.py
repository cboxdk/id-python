"""Exceptions raised by the management clients."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Literal

from ..errors import CboxIdError
from .models import PendingApproval


class CboxIdApiError(CboxIdError):
    """The management API answered with an error.

    Every plane answers a failure with the same envelope — ``{error, message}``, plus a
    field-keyed ``errors`` map on ``validation_failed`` — so one class covers them all.
    Branch on ``error`` (the stable machine code), never on ``message`` (prose, reworded
    freely).

    The REQUEST body is never part of the error: management writes carry secrets (a
    password you set, a key's scopes, a webhook secret) and production apps log exceptions.
    """

    def __init__(
        self,
        *,
        status: int,
        error: str,
        message: str,
        errors: Mapping[str, Sequence[str]] | None = None,
        request_id: str | None = None,
        retry_after: int | None = None,
    ) -> None:
        super().__init__(message)
        #: HTTP status.
        self.status = status
        #: The stable machine code, e.g. ``validation_failed``, ``slug_taken``, ``not_found``.
        self.error = error
        #: The server's human-readable explanation.
        self.message = message
        #: On ``validation_failed`` only: the offending request fields, each mapped to its
        #: messages (``{"name": ["The name field is required."]}``). Empty otherwise.
        self.errors: dict[str, list[str]] = {k: list(v) for k, v in (errors or {}).items()}
        #: The id the server served the request under (the envelope's ``request_id``, else
        #: the ``X-Request-Id`` header). Quote it when reporting a problem.
        self.request_id = request_id
        #: Seconds to wait, off ``Retry-After`` — set on a ``429``/``503`` the client gave up
        #: retrying.
        self.retry_after = retry_after

    @property
    def is_validation_error(self) -> bool:
        """Whether this is a ``422 validation_failed`` with field errors."""
        return self.error == "validation_failed"

    def __repr__(self) -> str:
        return (
            f"CboxIdApiError(status={self.status}, error={self.error!r}, "
            f"message={self.message!r}, request_id={self.request_id!r})"
        )


class ManagementNetworkError(CboxIdError):
    """The request never got an answer: DNS, TLS, a reset connection, a timeout.

    Raised after every retry the client was allowed. A write may or may not have happened;
    repeating it with the same ``idempotency_key`` (``exc.idempotency_key``) is safe and
    tells you which.
    """

    def __init__(self, message: str, idempotency_key: str | None) -> None:
        super().__init__(message)
        #: The ``Idempotency-Key`` the write was sent with, to repeat it safely.
        self.idempotency_key = idempotency_key


ApprovalFailure = Literal["denied", "expired", "consumed"]


class ApprovalError(CboxIdError):
    """An action held for a person's approval did not get it.

    ``reason`` says how: ``denied`` (they said no), ``expired`` (nobody answered in time),
    or ``consumed`` (the approval was already spent by another request).
    """

    def __init__(self, message: str, reason: ApprovalFailure, approval: PendingApproval) -> None:
        super().__init__(message)
        self.reason: ApprovalFailure = reason
        self.approval = approval


class ApprovalDeniedError(ApprovalError):
    """The person declined the action on their device. Do not retry it unprompted."""

    def __init__(self, approval: PendingApproval) -> None:
        super().__init__(f"Approval {approval.id} was denied.", "denied", approval)


class ApprovalExpiredError(ApprovalError):
    """Nobody approved the action before the approval expired. Ask again with a new request."""

    def __init__(self, approval: PendingApproval) -> None:
        super().__init__(
            f"Approval {approval.id} expired before it was approved.", "expired", approval
        )
