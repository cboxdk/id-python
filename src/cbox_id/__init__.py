"""Turnkey Cbox ID client for Python."""

from __future__ import annotations

from .authz import AuthzManifest, Permission, Role
from .claims import (
    ClaimSource,
    actor,
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
from .pkce import challenge, create_verifier, random_token
from .webhook import verify_webhook

__all__ = [
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
    "verify_webhook",
]
