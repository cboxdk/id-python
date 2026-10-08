# Changelog

All notable changes to `cbox-id-client` are recorded here. Earlier releases are described
by their tags and commit history.

## [Unreleased]

### Added

- `cbox_id.management`: typed clients for Cbox ID's management planes, generated from the
  OpenAPI documents the server publishes. `EnvironmentClient` (an environment's own host,
  `cbid_env_…` key or delegated token), `WorkspaceClient` (`cbid_ws_…` key),
  `PlatformClient` (operator token) and `AccountClient` (a person's own token). Methods are
  named after the server's actions (`env.apps.secrets.rotate(id, body)`,
  `workspace.environments.create(body)`), with `TypedDict` bodies, queries and responses
  that pass `mypy --strict`. Synchronous, on `httpx`, like the rest of the package.
- Every write sends an `Idempotency-Key` (a fresh UUID unless you pass one) and is retried
  with the same key on network failures, `5xx`, `429` and `409 idempotency_in_progress`,
  respecting `Retry-After`. `ApiResponse.replayed` reports `Idempotent-Replayed`.
- Approvals: a `202 approval_required` calls `on_approval_required` (show the binding code),
  polls the approval on the plane's own host only, and repeats the request with
  `Cbox-Approval` and the same key. `ApprovalDeniedError` and `ApprovalExpiredError` when it
  is not approved; `approval="return"` hands back a `PendingApprovalResult` with `resume()`.
- `CboxIdApiError` (`status`, `error`, `message`, `errors`, `request_id` from the envelope's
  `request_id` or `X-Request-Id`, `retry_after`) and `ManagementNetworkError` (with the
  `idempotency_key` to repeat safely).
- `environment=` on `EnvironmentClient`: with a person's root access token and the platform
  root as `base_url`, it sends `Cbox-Environment` so one token can drive any environment of
  the workspace.
- Audit Logs helpers: `AuditLogger` (buffers events and sends batches of up to 100, each
  with its own Idempotency-Key, on size, interval and `flush()`), `export_audit_logs()`
  (creates an export and polls it until ready), and `verify_audit_chain()` /
  `verify_audit_log_chain()` with `canonical_json()` and `audit_event_hash()`, which
  recompute an organization's hash chain byte for byte as the server does — checked against
  a vector the server's own code computed.
- `…_all` iterators on every paged list (cursor and page-number paging).
- DPoP-bound access tokens: `ES256DPoPSigner` and `generate_dpop_key()`, with
  `DPoP-Nonce` challenge handling.
- Operation tables (`ENVIRONMENT_OPERATIONS`, …) with each action's method, path, scope,
  danger and whether it can be held for approval.
- `python -m scripts.generate_management` regenerates the clients from the vendored specs in
  `openapi/`; `--fetch <plane>=<host>` refreshes a spec from a running server first, and
  `--check` fails when the generated code is stale. So does the test suite.

### Changed

- New runtime dependency: `typing-extensions>=4.7` (`NotRequired` and `TypedDict` on
  Python 3.10). The `dev` extra adds `pyyaml` and `types-PyYAML` for the generator.

## [0.9.0] - 2026-09-24

Organization selection, support sessions, and staff roles. Needs a Cbox ID instance that
understands the `organization` / `organization_hint` authorize parameters, emits
`org_role` and `act`, and reads `tenant_assignable` in a manifest (laravel-id 1.19).
Against an older instance the new fields stay empty, and a switch fails at the callback
instead of silently landing in the old organization (see below).

### Added

- `create_authorization_request()` accepts `organization` (bind the sign-in to one
  organization), `organization_hint` (preselect it in the hosted picker), and the prompts
  `select_organization` and `create_organization`.
- `client.switch_organization(org_id)`: a new authorization bound to another organization.
- The organization a sign-in was bound to is echoed as `AuthorizationRequest.organization`
  and verified by `authenticate(organization=…)`: tokens for any other organization are
  refused.
- `CboxUser` gains typed `organization` (`ActiveOrganization(id, name, role)` from `org`,
  `org_name`, `org_role`), `roles`, `permissions`, `actor` (the RFC 8693 `act` claim) and
  `session_id` (the id_token's `sid`, for back-channel logout), plus
  `is_support_session`, `has_role()` and `has_permission()`.
- Claim helpers that work on a `CboxUser` or on a claim mapping you verified yourself:
  `organization()`, `actor()`, `is_support_session()`, `roles()`, `permissions()`,
  `has_role()`, `has_permission()`.
- Exported types `AuthorizationPrompt`, `OrganizationRole`, `ActiveOrganization`, `Actor`
  and `ClaimSource`.
- Manifest flags: `role(..., tenant_assignable=False)` declares a staff role only your own
  operators can grant; `permission(..., tenant_assignable=True)` lets a customer's
  administrators grant a permission on its own. Each is sent, and hashed, only in its
  non-default state, so a manifest that uses neither keeps its version.
- `authenticate()` accepts `error_description`, carried on the raised error.

### Changed

- An error returned to the callback (`?error=access_denied`) now sets
  `AuthenticationError.error` and `.error_description`, as the back-channel errors already
  did. A refused organization switch is `access_denied`, and an app answers it by switching
  back, not by signing the person out — which it could not tell apart before.
- `prompt` accepts an `AuthorizationPrompt`, a list of values, or a string (split on
  whitespace, de-duplicated). `prompt="none"` combined with another value is refused
  (OIDC Core §3.1.2.1).
- `organization` together with the `select_organization` or `create_organization` prompt,
  or an empty `organization` / `organization_hint`, raises `ConfigurationError` before any
  redirect.
- `CboxUser.organization_id` is `None` for an empty `org` claim, as `organization` is.
- A manifest flag that is not a real `bool` (the string `"false"` from a config file)
  raises `ConfigurationError` instead of being read by truthiness — which would have
  published a staff role as one every tenant can grant.

### Fixed

- The manifest version de-duplicates a role's permission refs, as the server does before
  it hashes. A role listing one permission twice no longer reads as a change on every
  deploy.
- README: the install line pinned v0.6.1; the prerequisites named JavaScript option names;
  and it said revocation needs a `client_secret`, which stopped being true in 0.6.2.
