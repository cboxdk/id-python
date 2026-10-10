"""Typed clients for Cbox ID's management planes.

Generated from the OpenAPI documents the server publishes (see ``openapi/`` and
``python -m scripts.generate_management``):

- :class:`EnvironmentClient`: one environment's tenancy, on its own host (``cbid_env_…``
  key or a delegated access token).
- :class:`WorkspaceClient`: the workspace above its environments (``cbid_ws_…`` key).
- :class:`PlatformClient`: the deployment itself, for operators (delegated token only).
- :class:`AccountClient`: a person's own account (delegated token only).

Server-side code only: every client holds a management credential. Schema and operation
types live in the plane's module, e.g. ``cbox_id.management.generated.environment.App``.
"""

from __future__ import annotations

from ..errors import CboxIdError, ConfigurationError
from .audit_logs import (
    AUDIT_CHAIN_GENESIS,
    MAX_AUDIT_BATCH,
    AuditChainVerification,
    AuditLogEventInput,
    AuditLogExportError,
    AuditLogger,
    AuditLogRecord,
    audit_event_document,
    audit_event_hash,
    canonical_json,
    export_audit_logs,
    verify_audit_chain,
    verify_audit_log_chain,
)
from .client import ManagementClient
from .dpop import DPoPSigner, ES256DPoPSigner, generate_dpop_key
from .errors import (
    ApprovalDeniedError,
    ApprovalError,
    ApprovalExpiredError,
    CboxIdApiError,
    ManagementNetworkError,
)
from .fga import fga_tuple
from .generated import account as account_api
from .generated import environment as environment_api
from .generated import platform as platform_api
from .generated import workspace as workspace_api
from .generated.account import ACCOUNT_OPERATIONS, AccountClient
from .generated.environment import ENVIRONMENT_OPERATIONS, EnvironmentClient
from .generated.platform import PLATFORM_OPERATIONS, PlatformClient
from .generated.workspace import WORKSPACE_OPERATIONS, WorkspaceClient
from .models import (
    ApiResponse,
    ApprovalContext,
    ApprovalMode,
    Danger,
    HttpMethod,
    OperationSpec,
    Pagination,
    PendingApproval,
    PendingApprovalResult,
    Plane,
)
from .transport import ManagementTransport, RetryOptions, retry_after_seconds

__all__ = [
    "ACCOUNT_OPERATIONS",
    "AUDIT_CHAIN_GENESIS",
    "ENVIRONMENT_OPERATIONS",
    "MAX_AUDIT_BATCH",
    "PLATFORM_OPERATIONS",
    "WORKSPACE_OPERATIONS",
    "AccountClient",
    "ApiResponse",
    "ApprovalContext",
    "ApprovalDeniedError",
    "ApprovalError",
    "ApprovalExpiredError",
    "ApprovalMode",
    "AuditChainVerification",
    "AuditLogEventInput",
    "AuditLogExportError",
    "AuditLogRecord",
    "AuditLogger",
    "CboxIdApiError",
    "CboxIdError",
    "ConfigurationError",
    "DPoPSigner",
    "Danger",
    "ES256DPoPSigner",
    "EnvironmentClient",
    "HttpMethod",
    "ManagementClient",
    "ManagementNetworkError",
    "ManagementTransport",
    "OperationSpec",
    "Pagination",
    "PendingApproval",
    "PendingApprovalResult",
    "Plane",
    "PlatformClient",
    "RetryOptions",
    "WorkspaceClient",
    "account_api",
    "audit_event_document",
    "audit_event_hash",
    "canonical_json",
    "environment_api",
    "export_audit_logs",
    "fga_tuple",
    "generate_dpop_key",
    "platform_api",
    "retry_after_seconds",
    "verify_audit_chain",
    "verify_audit_log_chain",
    "workspace_api",
]
