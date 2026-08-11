# cbox-id-client

Turnkey [Cbox ID](https://github.com/cboxdk/laravel-id) client for Python. It speaks
standard OpenID Connect against a Cbox ID instance — so integrating is a redirect and
a callback, not a rewrite — and adds the conveniences a hosted-identity product needs:

- **Login** — PKCE (S256), a CSRF `state`, a nonce, and full `id_token` verification
  (signature against the instance's JWKS via [PyJWT](https://pyjwt.readthedocs.io),
  plus issuer, audience and nonce).
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

config = frontend.config()          # endpoints, social buttons, the customer's theme
session = frontend.session(token)   # session.user is None when nobody is signed in
```

Signed-out is a state rather than an error, and the key grants nothing on its own: the
access token is the entire authority for `session()`. Passing a client secret raises
immediately rather than failing later as an opaque 401.

## Migrating off an old login

Cbox ID can ask your system whether an email and password it has never seen are good, and
import that person on the yes. You write the lookup; the handler owns the signature, the
freshness window and the constant-time compare:

```python
from cbox_id import LegacyUser, handle_legacy_login

@app.post("/cbox-legacy")
def cbox_legacy():
    status, body = handle_legacy_login(
        request.get_data(as_text=True),          # the RAW body — the signature covers it
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

> **Where do `issuer`, `clientId` and `redirectUri` come from?**
> Register an application in your environment console — see
> [Integrate your app](https://github.com/cboxdk/cbox-id/blob/main/docs/getting-started/integrate-your-app.md).

```bash
pip install cbox-id-client
```

## Log in users

```python
from cbox_id import CboxIdClient, CboxIdConfig

client = CboxIdClient(CboxIdConfig(
    issuer="https://id.acme.com",
    client_id="client_...",
    client_secret="secret_...",
    redirect_uri="https://app.acme.com/auth/callback",
))

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

## Hosted profile management

```python
return redirect(client.profile_url(return_to="https://app.acme.com/dashboard"))
```

## Back-channel calls

```python
token = client.machine_token(scopes=["reports.read"])   # as your app
claims = client.userinfo(user.access_token)              # as a user
result = client.introspect(some_token)                   # RFC 7662
client.revoke(user.refresh_token, "refresh_token")       # RFC 7009
```

Revoking a refresh token drops the whole token family — that's what "sign out
everywhere" needs. Both calls are confidential-client, so they require a
`client_secret`.

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
summary = client.publish_manifest(manifest)   # run on deploy
```

`publish_manifest` mints a client-credentials token with the `apps.manifest` scope, POSTs
the manifest to `{issuer}/api/v1/apps/manifest`, and returns the server's sync summary
(`unchanged`, `roles_declared`, `permissions_declared`, `orphaned_roles`, …). It needs a
`client_secret` and raises `ManifestPublishError` if the push is rejected.

## Verify webhooks

```python
from cbox_id import verify_webhook

ok = verify_webhook(
    payload=raw_body,                       # the exact bytes received
    signature_header=request.headers.get("X-Cbox-Signature"),
    secret=os.environ["CBOX_ID_WEBHOOK_SECRET"],
)
```

## Security & scope

Login is hardened by default — PKCE, `state`, nonce, and full `id_token` verification
via PyJWT, against an explicit allow-list of RS256 and ES256 keyed by JWKS key type,
so `alg:none` and algorithm confusion are both refused. Keep the
client secret and webhook secrets server-side.

This is a **client**. It authenticates users and calls a Cbox ID instance's standard
endpoints; it does not configure SSO, run SCIM, or manage organizations — those are
platform capabilities of [`cboxdk/laravel-id`](https://github.com/cboxdk/laravel-id).

Report vulnerabilities via this repo's GitHub **Private Vulnerability Reporting**.

## License

MIT © Cbox.
