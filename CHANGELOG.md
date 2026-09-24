# Changelog

All notable changes to `cbox-id-client` are recorded here. Earlier releases are described
by their tags and commit history.

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
