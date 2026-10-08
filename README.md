# cbox-id-client

Turnkey [Cbox ID](https://github.com/cboxdk/laravel-id) client for Python. It speaks
standard OpenID Connect against a Cbox ID instance — so integrating is a redirect and
a callback, not a rewrite — and adds the conveniences a hosted-identity product needs:

- **Login** — PKCE (S256), a CSRF `state`, a nonce, and full `id_token` verification
  (signature against the instance's JWKS via [PyJWT](https://pyjwt.readthedocs.io),
  plus issuer, audience and nonce).
- **Organizations** — bind a sign-in to one organization, switch between them, and read
  the person's tier, roles and permissions there — and whether a support agent is acting
  as them.
- **Hosted profile management** — a redirect to the instance's own account page.
- **Back-channel calls** — machine (client-credentials) tokens, UserInfo, RFC 7662
  introspection, RFC 7009 revocation.
- **Webhook / action verification** — confirm an inbound `X-Cbox-Signature`.

Framework-agnostic: works with Flask, FastAPI, Django or plain scripts.

## In a browser-facing page (publishable keys)

Everything above needs a client secret. A **publishable key** is the opposite — public on
purpose, and useful only from the origins you registered. Reading the environment's own
sign-in configuration lets a Django or Flask template render a themed sign-in box without
shipping a JavaScript SDK to do it:

```python
from cbox_id import FrontendClient

frontend = FrontendClient("https://id.acme.com", "pk_live_…")

config = frontend.config()  # endpoints, social buttons, the customer's theme
session = frontend.session(token)  # session.user is None when nobody is signed in
```

Signed-out is a state rather than an error, and the key grants nothing on its own: the
access token is the entire authority for `session()`. Passing a client secret raises
immediately rather than failing later as an opaque 401.

**Before any of this works**, an operator has to turn the Frontend API on
(`CBOX_ID_FRONTEND_API=true` — it is off by default) and mint a publishable key under
**Developers → Frontend keys**, listing the exact origins allowed to use it. Exact matches
only: `https://acme.com` does not cover `https://www.acme.com`.


## Migrating off an old login

Cbox ID can ask your system whether an email and password it has never seen are good, and
import that person on the yes. You write the lookup; the handler owns the signature, the
freshness window and the constant-time compare:

Your handler has **3 seconds** to answer, must be reachable over **HTTPS** (plain `http`,
including `http://localhost`, is refused — the body is a live password), and is resolved
through an SSRF guard that blocks private ranges unless an operator relaxes
`cbox-id.migration.verify_url` for an endpoint on their own network. A slow bcrypt under
load therefore reads to the person signing in as a wrong password.

```python
from cbox_id import LegacyUser, handle_legacy_login


@app.post("/cbox-legacy")
def cbox_legacy():
    status, body = handle_legacy_login(
        request.get_data(as_text=True),  # the RAW body — the signature covers it
        request.headers.get("X-Cbox-Signature"),
        secret=os.environ["CBOX_LEGACY_SECRET"],
        verify=lambda email, password: (
            LegacyUser(email, row.name, password_hash=row.hash)
            if (row := lookup(email)) and check(password, row.hash)
            else None
        ),
    )
    return jsonify(body), status
```

Return `None` for a wrong password. **Raising is different**: it means your store could not
decide, and is answered with 503 so Cbox ID refuses the sign-in rather than reading an
outage as a bad credential.

It takes the raw body and header rather than a request object, because Flask, Django,
FastAPI and Starlette all differ — adapting three lines is a smaller imposition than a
request abstraction invented to avoid them.

## Install

> **Where do `issuer`, `client_id` and `redirect_uri` come from?**
> Register an application in your environment console — see
> [Integrate your app](https://github.com/cboxdk/cbox-id/blob/main/docs/getting-started/integrate-your-app.md).

> **Not on PyPI, and not planned.** `pip install cbox-id-client` installs nothing — this
> package has never been published and there is no release pipeline for it. Everything
> below works; you install it from source.

```bash
pip install git+https://github.com/cboxdk/id-python@v0.8.0
```

## Log in users

```python
from cbox_id import CboxIdClient, CboxIdConfig

client = CboxIdClient(
    CboxIdConfig(
        issuer="https://id.acme.com",
        client_id="client_...",
        client_secret="secret_...",
        redirect_uri="https://app.acme.com/auth/callback",
    )
)

# Start login — persist state/code_verifier/nonce (e.g. in the session).
req = client.create_authorization_request()
session["cbox"] = {"state": req.state, "verifier": req.code_verifier, "nonce": req.nonce}
# redirect the user to req.url ...

# On the callback:
stored = session["cbox"]
user = client.authenticate(
    code=request.args.get("code"),
    state=request.args.get("state"),
    expected_state=stored["state"],
    code_verifier=stored["verifier"],
    nonce=stored["nonce"],
)
# key your local account on user.id (the stable subject)
```

A callback that carried an error raises `AuthenticationError` with the code on
`exc.error` (and `exc.error_description`), so you can branch on `access_denied` without
matching on the message. Pass `error=request.args.get("error")` and
`error_description=request.args.get("error_description")` through to `authenticate`.

## Organizations

A sign-in can be bound to one organization. The tokens then carry `org`, `org_name`, the
person's membership tier in it (`org_role`), and the app `roles` / `permissions` they hold
**there** — so switching organization means a new authorization, not a flag on the old
session.

```python
from cbox_id import AuthorizationPrompt

# Bind to an organization you already know (the person must be an active member):
req = client.create_authorization_request(organization="org_2x…")

# Always show the hosted organization picker, with your guess preselected:
req = client.create_authorization_request(
    prompt=AuthorizationPrompt.SELECT_ORGANIZATION,
    organization_hint="org_2x…",
)

# Hosted "create a team" step; the person becomes its owner and the sign-in
# continues bound to the new organization:
req = client.create_authorization_request(prompt=AuthorizationPrompt.CREATE_ORGANIZATION)
```

| Argument | Sent as | Meaning |
|---|---|---|
| `organization` | `organization` | Bind the sign-in to this organization. |
| `organization_hint` | `organization_hint` | Preselect it in the picker; the person may choose another. |
| `prompt=AuthorizationPrompt.SELECT_ORGANIZATION` | `prompt=select_organization` | Always show the picker. |
| `prompt=AuthorizationPrompt.CREATE_ORGANIZATION` | `prompt=create_organization` | Create an organization first. |

`prompt` takes one value or a list (plain strings work too, and a space-separated string
is split). `organization` cannot be combined with either organization prompt — it has
already made the choice they ask the person to make — so the SDK raises
`ConfigurationError` rather than sending it; use `organization_hint` with the picker
instead. An empty `organization` or `organization_hint`, and `prompt="none"` combined
with anything else, are refused the same way.

### Switching

`client.switch_organization(org_id)` is `create_authorization_request(organization=org_id)`
under a name that says what it is for. Persist and redirect exactly as for a sign-in;
Cbox ID already has the person's session, so they normally come straight back without
seeing a form.

**The binding is checked, not trusted.** The request echoes `req.organization`: persist it
with the rest and pass it back to `authenticate(organization=…)`, which refuses tokens for
any other organization. An instance that predates organization selection ignores the
parameter and answers for whichever organization the session already had — without the
check, your app would show the new organization's name over the old one's data.

```python
from cbox_id import AuthenticationError


@app.get("/auth/switch-organization")
def switch_organization():
    req = client.switch_organization(request.args["org"])
    session["cbox"] = {
        "state": req.state,
        "verifier": req.code_verifier,
        "nonce": req.nonce,
        "organization": req.organization,
    }
    return redirect(req.url)


# On the callback:
stored = session["cbox"]
try:
    user = client.authenticate(
        code=request.args.get("code"),
        state=request.args.get("state"),
        error=request.args.get("error"),
        expected_state=stored["state"],
        code_verifier=stored["verifier"],
        nonce=stored["nonce"],
        organization=stored.get("organization"),
    )
except AuthenticationError as exc:
    if exc.error == "access_denied":
        ...  # not a member of that organization — send them back to the one they were in
    raise
```

Replace your session with the user the callback returns rather than patching the old one:
`org_role`, `roles` and `permissions` can all differ between organizations.

### Reading the claims

The signed-in user carries them typed:

```python
user.organization  # ActiveOrganization(id, name, role) or None
user.organization.role  # OrganizationRole.OWNER / ADMIN / DEVELOPER / MEMBER / VIEWER, or None
user.roles  # list[str]
user.permissions  # list[str]
user.actor  # Actor(sub, actor) or None — see support sessions below
user.session_id  # the id_token's `sid`, for back-channel logout
user.has_permission("invoices:create")
```

The same helpers work on the user and on a claim mapping you verified yourself, such as an
access token's payload on a resource server:

```python
from cbox_id import OrganizationRole, has_permission, is_support_session, organization

if not has_permission(payload, "invoices:create"):
    abort(403)

org = organization(user)
if org and org.role is OrganizationRole.OWNER:
    show_billing()
```

Matching is exact — `invoices:*` does not grant `invoices:delete`. An `org_role` this SDK
version does not recognise reads as `None`, never as a tier it would have to guess.

### Support sessions

A staff member can act as one of your users for a limited time (at most an hour, no refresh
token, with a recorded reason). Those tokens carry the RFC 8693 `act` claim naming the
staff member, and `is_support_session()` reports it:

```python
if user.is_support_session:  # or is_support_session(payload) on a resource server
    ...  # show a banner, and refuse password, email and payout changes
```

It is **fail-closed**: any `act` claim counts, including one whose shape the SDK cannot
read (`user.actor.sub` is then `None`). A claim it cannot parse is not evidence that nobody
else is at the keyboard.

## Hosted profile management

```python
return redirect(client.profile_url(return_to="https://app.acme.com/dashboard"))
```

## Back-channel calls

```python
token = client.machine_token(scopes=["reports.read"])  # as your app
claims = client.userinfo(user.access_token)  # as a user
result = client.introspect(some_token)  # RFC 7662
client.revoke(user.refresh_token, "refresh_token")  # RFC 7009
```

Revoking a refresh token drops the whole token family — that's what "sign out
everywhere" needs. Machine tokens and introspection are confidential-client calls and
require a `client_secret`; revocation also works for a public (PKCE) client, which names
itself in the request body instead.

## Declare roles & permissions

Your app declares its authorization **roles** and **permissions** in code and publishes
that catalog to Cbox ID on deploy. Cbox ID owns identity and who holds which role; your
app owns what a role *means*. Publishing is idempotent — an unchanged catalog is a
server-side no-op.

```python
from cbox_id import AuthzManifest

manifest = (
    AuthzManifest()
    .permission("invoices:create", "Create invoices")
    .role("billing-admin", "Billing Admin", permissions=["invoices:create"])
)
summary = client.publish_manifest(manifest)  # run on deploy
```

Two flags decide who may grant what:

```python
manifest = (
    AuthzManifest()
    .permission("support:impersonate", "Act as a customer")
    .permission("reports:read", "Read reports", tenant_assignable=True)
    .role(
        "support",
        "Support",
        permissions=["support:impersonate"],
        tenant_assignable=False,  # a staff role: only your own operators grant it
    )
)
```

- **A role** is assignable by each customer's administrators unless you pass
  `tenant_assignable=False`, which makes it a staff role only your own operators can grant.
- **A permission** is internal — reachable only through the roles you declare — unless you
  pass `tenant_assignable=True`, which lets a customer's administrators grant it on its own.

Both must be real booleans: `"false"` from a config file raises `ConfigurationError`
rather than publishing a staff role every tenant can hand out.

`publish_manifest` mints a client-credentials token with the `apps.manifest` scope, POSTs
the manifest to `{issuer}/api/v1/apps/manifest`, and returns the server's sync summary
(`unchanged`, `roles_declared`, `permissions_declared`, `orphaned_roles`, …). It needs a
`client_secret` and raises `ManifestPublishError` if the push is rejected.

## Verify webhooks

```python
from cbox_id import verify_webhook

ok = verify_webhook(
    payload=raw_body,  # the exact bytes received
    signature_header=request.headers.get("X-Cbox-Signature"),
    secret=os.environ["CBOX_ID_WEBHOOK_SECRET"],
)
```

## Management API

`cbox_id.management` is a typed client for Cbox ID's management planes. It is generated from
the OpenAPI documents the server publishes, so every method, path, scope and type matches the
server it was generated from. Use it from server code only: every client holds a management
credential.

| Client | Plane | Credential | `base_url` |
| --- | --- | --- | --- |
| `EnvironmentClient` | One environment's tenancy: organizations, users, apps, roles, SSO, audit logs… | `cbid_env_…` key, or a delegated access token | The environment's own host, or the platform root with `environment` |
| `WorkspaceClient` | The workspace above its environments: projects, environments, team, keys | `cbid_ws_…` key, or a person's root token | `https://api.cboxid.com` (default) |
| `PlatformClient` | The deployment itself, for operators | Delegated operator token only | `https://api.cboxid.com` (default) |
| `AccountClient` | A person's own account | Delegated token only | The environment's own host |

Method names are the server's action names: `apps.secrets.rotate` is
`env.apps.secrets.rotate(...)`, and `sso.saml_metadata.import` is
`env.sso.saml_metadata.import_(...)`. Path parameters come first, in path order, then the body
(or the query, for a read) as a dict, then keyword-only options. Every call returns an
`ApiResponse` with `data`, `meta`, `body`, `status`, `replayed`, `idempotency_key`,
`request_id` and `headers`. Bodies, queries and `data` are `TypedDict`s, so mypy and your
editor check the keys.

The client is synchronous, on `httpx`, like the rest of this package.

### Create an app and rotate its secret

```python
import os

from cbox_id.management import ApprovalDeniedError, CboxIdApiError, EnvironmentClient

env = EnvironmentClient(
    base_url="https://acme.cboxid.com",
    api_key=os.environ["CBOX_ID_ENV_KEY"],  # cbid_env_…
    on_approval_required=lambda approval, ctx: print(
        f"Approve {ctx.action} on your device. Code: {approval.binding_code}"
    ),
)

app = env.apps.create(
    {"name": "Billing", "type": "web", "redirect_uris": ["https://billing.acme.com/callback"]}
).data
# app["client_secret"] is in this response and in no other. Store it now.

try:
    secret = env.apps.secrets.rotate(app["id"], {"grace_seconds": 3600}).data
    # secret["client_secret"]: the new secret, shown once.
except ApprovalDeniedError:
    print("Rotation was declined.")
except CboxIdApiError as exc:
    if not exc.is_validation_error:
        raise
    print(exc.errors)
```

When a key's policy holds an action for a person's approval, the server answers
`202 approval_required`. By default the client calls `on_approval_required` (show the
`binding_code` so the person can match it on their device), polls the approval, and repeats
the request with `Cbox-Approval: <id>` and the same `Idempotency-Key` once it is approved.
`ApprovalDeniedError` and `ApprovalExpiredError` are raised when it is denied or expires. The
poll goes only to the plane's own host: a `poll_url` on another origin is refused rather than
handed the credential. If you do not want to wait in the same call, pass `approval="return"`:

```python
from cbox_id.management import PendingApprovalResult

outcome = env.apps.secrets.rotate(app["id"], {"grace_seconds": 0}, approval="return")
if isinstance(outcome, PendingApprovalResult):
    print(f"Code: {outcome.approval.binding_code}")
    secret = outcome.resume().data  # polls, then repeats the request
```

### Bootstrap an environment from a workspace key

```python
from cbox_id.management import EnvironmentClient, WorkspaceClient

workspace = WorkspaceClient(api_key=os.environ["CBOX_ID_WS_KEY"])  # cbid_ws_…

created = workspace.environments.create(
    {
        "name": "Staging",
        "type": "sandbox",
        "initial_key": {"name": "bootstrap", "scopes": ["apps:write", "organizations:write"]},
    }
).data

# The first management key, returned once. On an idempotent replay its token is None.
initial_key = created["initial_key"]
assert initial_key is not None and initial_key["token"] is not None
env = EnvironmentClient(base_url=created["issuer"], api_key=initial_key["token"])
env.organizations.create({"name": "Acme", "slug": "acme"})
```

### Idempotency, retries and errors

- Every `POST`, `PUT`, `PATCH` and `DELETE` sends an `Idempotency-Key`, a fresh UUID unless
  you pass `idempotency_key=`. Network failures, `5xx`, `429` and
  `409 idempotency_in_progress` are retried with the **same** key
  (`retry=RetryOptions(max_retries=3, base_delay=0.5, max_delay=30.0)`, in seconds).
  `Retry-After` is respected; one longer than `max_delay` is raised instead of waited out.
  `replayed` is `True` when the server returned the first request's stored answer
  (`Idempotent-Replayed`). A secret in a replayed answer is `None`.
- A failed call raises `CboxIdApiError` with `status`, `error` (the stable code), `message`,
  `errors` (field-keyed, on `validation_failed`), `request_id` (the envelope's `request_id`,
  else the `X-Request-Id` header; quote it when reporting a problem) and `retry_after`. A call
  that never got an answer raises `ManagementNetworkError`, which carries the
  `idempotency_key` so you can repeat the request safely. Both are `CboxIdError`s.
- The client never logs. Secrets in responses are returned as they arrive, and request
  bodies are never put in an error.

### One token for every environment

A person's access token issued at the platform root reaches the workspace, account and
operator planes there, and any environment of their workspace when the request names it with
`Cbox-Environment`. Pass `environment` (an id or slug) and the root host as `base_url`:

```python
staging = EnvironmentClient(
    base_url="https://api.cboxid.com",
    access_token=tokens.current,  # a str, or a callable called before every request
    environment="acme-staging",  # sent as Cbox-Environment on every request
)
staging.organizations.portal_links.create(org_id, {"intents": ["sso", "dsync"]})
```

What the token may do there is bounded by the person's role and the token's scopes. A
`cbid_env_…` key is bound to its own environment's host, so `environment` is refused with one.

### Lists

Every paged list also has a `…_all` variant that iterates every item, fetching pages as you
reach them. It follows `meta.next_cursor` on the environment plane and `meta.next_page` on the
workspace plane:

```python
for org in env.organizations.list_all({"limit": 100}):
    print(org["id"], org["name"])
```

### Audit Logs

Your app records what its users did, per organization (your customer), and Cbox ID keeps
each organization's events in a tamper-evident hash chain. `AuditLogger` buffers events and
sends them in batches of up to 100, each batch under its own `Idempotency-Key`. It sends a
batch when it is full, every `flush_interval` seconds (default 5, from a daemon thread), and on
`flush()` / `close()`. A batch that fails stays queued with the same key, so sending it again
never records an event twice:

```python
from collections.abc import Sequence

from cbox_id.management import AuditLogEventInput, AuditLogger

def report(exc: Exception, batch: Sequence[AuditLogEventInput]) -> None:
    log.warning("audit flush failed (%d events kept for the next one): %s", len(batch), exc)


with AuditLogger(env, on_error=report) as audit:
    audit.record(
        {
            "organization_id": org["id"],
            "action": "invoice.voided",
            "actor": {"id": user.id, "type": "user", "name": user.name},
            "targets": [{"id": invoice.id, "type": "invoice"}],
            "context": {"location": request.remote_addr, "user_agent": request.user_agent.string},
            "metadata": {"reason": "duplicate"},
        }
    )  # occurred_at defaults to now
# Leaving the block (or audit.close()) stops the thread and sends what is left.
```

Read events with `env.audit_logs.events.list_all({"organization_id": …, "actions": […]})`.
To get a CSV, `export_audit_logs(env, filters)` starts an export and polls it until it is
ready. Its `url` is signed and short-lived. To check the chain yourself instead of trusting
the server's `env.audit_logs.verify()`, call `verify_audit_log_chain(env, organization_id)` or
`verify_audit_chain(events)`. They recompute `sha256(prev_hash + canonical JSON)` exactly as
the server does — keys sorted by UTF-8 bytes at every depth, PHP's list and empty-object
rules, PHP's float format, slashes and Unicode unescaped — and report
`AuditChainVerification(valid, reason, broken_at_sequence, …)`.

### Delegated tokens and DPoP

Pass `access_token` (a string, or a callable called before every request so it can refresh)
instead of `api_key`. For a DPoP-bound token, pass a signer built from the P-256 key the token
was bound to:

```python
from cbox_id.management import AccountClient, ES256DPoPSigner

me = AccountClient(
    base_url="https://acme.cboxid.com",
    access_token=tokens.current,
    dpop=ES256DPoPSigner(private_key),  # an EllipticCurvePrivateKey (cryptography)
)
me.sessions.revoke_others()
```

### Types, metadata and regenerating

Schema and operation types live in each plane's module (`cbox_id.management.environment_api.App`,
`cbox_id.management.workspace_api.EnvironmentsCreateBody`). The operation tables
(`ENVIRONMENT_OPERATIONS`, …) list each action's method, path, scope, danger and whether it can
be held for approval, which is useful for showing a confirmation before a `critical` action.
`env.request(method, path, query=…, body=…)` calls a route that is not generated.

The specs are vendored in `openapi/`. `python -m scripts.generate_management` (with the `dev`
extra installed) regenerates `src/cbox_id/management/generated/` from them, and
`python -m scripts.generate_management --fetch environment=https://acme.cboxid.com` (or
`workspace=`, `platform=`, `account=`, `all=`) refreshes a vendored spec from a running server
first. `--check` exits non-zero when the generated code is stale, and the test suite fails
when the generated code and the vendored specs disagree.

## Security & scope

Login is hardened by default — PKCE, `state`, nonce, and full `id_token` verification
via PyJWT, against an explicit allow-list of RS256 and ES256 keyed by JWKS key type,
so `alg:none` and algorithm confusion are both refused. Keep the
client secret and webhook secrets server-side.

This is a **client**. It authenticates users — into a chosen organization, when you ask —
and calls a Cbox ID instance's endpoints. The management client drives the server's own
management API with a credential you hold; SSO, SCIM and the rules behind every action stay
platform capabilities of [`cboxdk/laravel-id`](https://github.com/cboxdk/laravel-id).

Report vulnerabilities via this repo's GitHub **Private Vulnerability Reporting**.

## License

MIT © Cbox.
