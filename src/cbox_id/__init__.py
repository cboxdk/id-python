"""Turnkey Cbox ID client for Python."""

from __future__ import annotations

from .authz import AuthzManifest, Permission, Role
from .claims import (
    FEATURE_FLAGS_SCOPE,
    ClaimSource,
    actor,
    feature_flags,
    has_feature,
    has_permission,
    has_role,
    is_support_session,
    organization,
    permissions,
    roles,
)
from .client import CboxIdClient
from .errors import (
    AuthenticationError,
    CboxIdError,
    ConfigurationError,
    FrontendApiError,
    InvalidStateError,
    ManifestPublishError,
    PipeLeaseDeniedError,
    PipeLeaseError,
    PipeNotConnectedError,
    PipeReauthorizationRequiredError,
    PipeTemporarilyUnavailableError,
)
from .frontend import FrontendClient, FrontendConfig, FrontendSession
from .legacy import LegacyUser, handle_legacy_login
from .models import (
    ActiveOrganization,
    Actor,
    AuthorizationPrompt,
    AuthorizationRequest,
    CboxIdConfig,
    CboxUser,
    OrganizationRole,
    RefreshedTokens,
)
from .pipes import (
    PipeProvider,
    PipesClient,
    PipeToken,
    pipe_connect_url,
    with_connect_return,
)
from .pkce import challenge, create_verifier, random_token
from .webhook import verify_standard_webhook, verify_webhook

__all__ = [
    "FEATURE_FLAGS_SCOPE",
    "PipeLeaseDeniedError",
    "PipeLeaseError",
    "PipeNotConnectedError",
    "PipeProvider",
    "PipeReauthorizationRequiredError",
    "PipeTemporarilyUnavailableError",
    "PipeToken",
    "PipesClient",
    "feature_flags",
    "has_feature",
    "pipe_connect_url",
    "with_connect_return",
    "FrontendClient",
    "FrontendConfig",
    "FrontendSession",
    "LegacyUser",
    "handle_legacy_login",
    "ActiveOrganization",
    "Actor",
    "AuthenticationError",
    "AuthorizationPrompt",
    "AuthorizationRequest",
    "AuthzManifest",
    "CboxIdClient",
    "CboxIdConfig",
    "CboxIdError",
    "CboxUser",
    "ClaimSource",
    "ConfigurationError",
    "FrontendApiError",
    "InvalidStateError",
    "ManifestPublishError",
    "OrganizationRole",
    "Permission",
    "RefreshedTokens",
    "Role",
    "actor",
    "challenge",
    "create_verifier",
    "has_permission",
    "has_role",
    "is_support_session",
    "organization",
    "permissions",
    "random_token",
    "roles",
    "verify_standard_webhook",
    "verify_webhook",
]
