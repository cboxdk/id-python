"""The Cbox ID client — a hardened OpenID Connect relying party."""

from __future__ import annotations

import hmac
import json
import time
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from .authz import AuthzManifest
from .errors import (
    AuthenticationError,
    ConfigurationError,
    InvalidStateError,
    ManifestPublishError,
)
from .models import AuthorizationRequest, CboxIdConfig, CboxUser, RefreshedTokens
from .pkce import challenge, create_verifier, random_token
from .webhook import verify_webhook

# The id_token signature algorithms we accept, by JWKS key type. An explicit
# allow-list: a key type or alg outside this map is refused rather than trusted,
# and `none` can never appear.
_ID_TOKEN_ALGORITHMS: dict[str, tuple[str, ...]] = {
    "RSA": ("RS256",),
    "EC": ("ES256",),
}

# How long to wait before a second JWKS refetch after a kid miss. Without it a token
# bearing a bogus kid would force a JWKS request on every verification.
_JWKS_REFETCH_COOLDOWN_SECONDS = 60.0


class CboxIdClient:
    """Turnkey Cbox ID client.

    Speaks standard OpenID Connect against a Cbox ID instance — integrating is a
    redirect and a callback, not a rewrite — and adds the conveniences a
    hosted-identity product needs: a redirect to the instance's hosted profile page,
    and back-channel helpers (machine tokens, userinfo, introspection, webhook
    verification).

    Login is hardened by default: PKCE (S256), a CSRF state check, a nonce, and full
    id_token signature + issuer + audience verification against the instance's JWKS
    (via PyJWT).
    """

    def __init__(self, config: CboxIdConfig, http_client: httpx.Client | None = None) -> None:
        if not config.issuer:
            raise ConfigurationError("Cbox ID config `issuer` is required.")
        if not config.client_id:
            raise ConfigurationError("Cbox ID config `client_id` is required.")
        if not config.redirect_uri:
            raise ConfigurationError("Cbox ID config `redirect_uri` is required.")

        self._config = config
        self._http = http_client or httpx.Client(timeout=config.timeout_seconds)
        self._discovery_cache: tuple[dict[str, Any], float] | None = None
        self._jwks_cache: tuple[dict[str, Any], float] | None = None
        self._jwks_refetched_at: float = 0.0

    # -- login ---------------------------------------------------------------

    def create_authorization_request(
        self,
        *,
        scopes: list[str] | None = None,
        state: str | None = None,
        prompt: str | None = None,
        redirect_uri: str | None = None,
    ) -> AuthorizationRequest:
        """Begin login. Persist the returned ``state``/``code_verifier``/``nonce``."""
        code_verifier = create_verifier()
        the_state = state or random_token(16)
        nonce = random_token(16)

        params: dict[str, str] = {
            "response_type": "code",
            "client_id": self._config.client_id,
            "redirect_uri": redirect_uri or self._config.redirect_uri,
            "scope": " ".join(scopes or self._config.scopes),
            "state": the_state,
            "nonce": nonce,
            "code_challenge": challenge(code_verifier),
            "code_challenge_method": "S256",
        }
        if prompt:
            params["prompt"] = prompt

        url = f"{self._endpoint('authorization_endpoint')}?{urlencode(params)}"
        return AuthorizationRequest(
            url=url, state=the_state, code_verifier=code_verifier, nonce=nonce
        )

    def authenticate(
        self,
        *,
        code: str | None,
        state: str | None,
        expected_state: str | None,
        code_verifier: str | None,
        nonce: str | None,
        error: str | None = None,
        redirect_uri: str | None = None,
    ) -> CboxUser:
        """Complete login on your callback route; return the authenticated user.

        Raises :class:`InvalidStateError` when state does not match, and
        :class:`AuthenticationError` on any other failure.
        """
        if not state or not expected_state or not hmac.compare_digest(state, expected_state):
            raise InvalidStateError(
                "The login state did not match — the request may be forged or stale."
            )
        if error:
            raise AuthenticationError(f"Cbox ID returned an error: {error}")
        if not code or not code_verifier:
            raise AuthenticationError("The callback was missing an authorization code.")

        tokens = self._exchange(code, code_verifier, redirect_uri)
        access_token = tokens.get("access_token")
        if not isinstance(access_token, str):
            raise AuthenticationError("No access token was returned.")

        id_token = tokens.get("id_token")
        claims: dict[str, Any] = {}
        if isinstance(id_token, str):
            claims = self._verify_id_token(id_token, nonce)
        claims = {**claims, **self.userinfo(access_token)}

        sub = claims.get("sub")
        if not isinstance(sub, str) or sub == "":
            raise AuthenticationError("The verified token carried no subject.")

        expires_in = tokens.get("expires_in")
        return CboxUser(
            id=sub,
            email=claims.get("email") if isinstance(claims.get("email"), str) else None,
            name=claims.get("name") if isinstance(claims.get("name"), str) else None,
            organization_id=claims.get("org") if isinstance(claims.get("org"), str) else None,
            claims=claims,
            access_token=access_token,
            refresh_token=tokens.get("refresh_token")
            if isinstance(tokens.get("refresh_token"), str)
            else None,
            id_token=id_token if isinstance(id_token, str) else None,
            expires_in=int(expires_in) if isinstance(expires_in, int | float) else 0,
        )

    # -- hosted profile & logout ---------------------------------------------

    def profile_url(self, return_to: str | None = None) -> str:
        """URL of the instance's hosted account page."""
        base = f"{self._config.issuer.rstrip('/')}{self._account_path()}"
        return base if return_to is None else f"{base}?{urlencode({'return_to': return_to})}"

    def logout_url(
        self, return_to: str | None = None, *, id_token_hint: str | None = None
    ) -> str | None:
        """RP-initiated logout URL, or ``None`` when the instance advertises none.

        ``client_id`` is always sent, even without a ``return_to``: the server checks
        ``post_logout_redirect_uri`` against the registered allow-list of *that*
        client (OIDC RP-Initiated Logout 1.0 §2). If the request does not name the
        relying party there is no list to check, so the return URL is dropped and the
        user lands on a bare "you are signed out" page. ``id_token_hint`` — the
        user's ``id_token``, when you still hold it — is the spec's other way to
        identify the client, and also tells the server whose session is ending.

        **Pass the hint if you want "sign out everywhere".** Cbox ID revokes every
        session the person holds only when a hint it can *verify* names the subject
        holding the browser; with no hint it signs this browser out and leaves their
        other devices alone. That is deliberate rather than an omission: the endpoint
        is unauthenticated and reached by a redirect, so a request carrying no proof
        of who it concerns could otherwise be forged into ending anyone's sessions
        everywhere. See laravel-id ``UPGRADING.md`` for 1.8.0.
        """
        endpoint = self._optional_endpoint("end_session_endpoint")
        if endpoint is None:
            return None
        params = {"client_id": self._config.client_id}
        if return_to is not None:
            params["post_logout_redirect_uri"] = return_to
        # Truthiness, not `is not None`: callers reach for
        # `session.get("id_token", "")`, and an empty `id_token_hint=` is a hint that
        # names nobody — a stricter OP than Cbox ID may reject it outright. The other
        # SDKs (id-js, id-go, laravel-id-client) all drop the empty string; match them.
        if id_token_hint:
            params["id_token_hint"] = id_token_hint
        return f"{endpoint}?{urlencode(params)}"

    # -- back-channel --------------------------------------------------------

    def machine_token(self, *, scopes: list[str] | None = None, resource: str | None = None) -> str:
        """A machine (client-credentials) token for calling APIs as your app."""
        data: dict[str, str] = {
            "grant_type": "client_credentials",
            "client_id": self._config.client_id,
            "client_secret": self._require_secret(),
        }
        if scopes:
            data["scope"] = " ".join(scopes)
        if resource:
            data["resource"] = resource

        response = self._http.post(self._endpoint("token_endpoint"), data=data)
        if response.status_code >= 400:
            raise AuthenticationError.from_response("Machine token request failed", response)
        token = response.json().get("access_token")
        if not isinstance(token, str):
            raise AuthenticationError("The token response had no access_token.")
        return token

    def refresh(self, refresh_token: str) -> RefreshedTokens:
        """Exchange a refresh token for a fresh access token (OAuth 2.0 refresh_token).

        Cbox ID rotates refresh tokens and detects reuse, so ALWAYS persist the
        returned ``refresh_token`` and discard the one you passed — presenting a
        rotated token again revokes the entire token family.
        """
        data: dict[str, str] = {
            "grant_type": "refresh_token",
            "client_id": self._config.client_id,
            "refresh_token": refresh_token,
        }
        if self._config.client_secret:
            data["client_secret"] = self._config.client_secret

        response = self._http.post(self._endpoint("token_endpoint"), data=data)
        if response.status_code >= 400:
            # invalid_grant here means the session is over; a 503 means the same token
            # is still good shortly. One message string for both is what makes callers guess.
            raise AuthenticationError.from_response("Token refresh failed", response)

        tokens: dict[str, Any] = response.json()
        access_token = tokens.get("access_token")
        if not isinstance(access_token, str):
            raise AuthenticationError("The refresh response carried no access token.")

        expires_in = tokens.get("expires_in")
        scope = tokens.get("scope")
        rotated = tokens.get("refresh_token")
        return RefreshedTokens(
            access_token=access_token,
            # Keep the presented token when the server does not rotate (OAuth 2.0 §6);
            # callers persist this value, so it must never be None.
            refresh_token=rotated if isinstance(rotated, str) else refresh_token,
            id_token=tokens.get("id_token") if isinstance(tokens.get("id_token"), str) else None,
            expires_in=int(expires_in) if isinstance(expires_in, int | float) else 0,
            scope=scope if isinstance(scope, str) else None,
        )

    def userinfo(self, access_token: str) -> dict[str, Any]:
        """The OIDC userinfo claims for an access token."""
        endpoint = self._optional_endpoint("userinfo_endpoint")
        if endpoint is None:
            return {}
        response = self._http.get(endpoint, headers={"Authorization": f"Bearer {access_token}"})
        if response.status_code >= 400:
            raise AuthenticationError.from_response("Userinfo request failed", response)
        result: dict[str, Any] = response.json()
        return result

    def introspect(self, token: str) -> dict[str, Any]:
        """RFC 7662 token introspection (confidential-client auth)."""
        response = self._http.post(
            self._endpoint("introspection_endpoint"),
            data={"token": token},
            auth=(self._config.client_id, self._require_secret()),
        )
        if response.status_code >= 400:
            raise AuthenticationError.from_response("Introspection request failed", response)
        result: dict[str, Any] = response.json()
        return result

    def revoke(self, token: str, token_type_hint: str | None = None) -> None:
        """RFC 7009 token revocation.

        Revokes an access or refresh token; revoking a refresh token also drops the
        whole token family, so this is what a real "sign out everywhere" does.

        PUBLIC CLIENTS TOO. This called ``_require_secret()`` and raised before the
        request left the process, so the clients that most need revocation were the
        ones that could not call it: a PKCE app authenticates with ``none``, holds no
        secret, and is exactly the case where a refresh token sits in storage on a
        device somebody has just signed out of. Cbox ID's revocation endpoint accepts
        a public client and advertises ``none`` among its revocation auth methods; RFC
        7009 §2.1 scopes each revocation to the calling client, so the only capability
        opened is destroying a token you are already holding.

        Per RFC 7009 the server answers 200 for an unknown or already-revoked token,
        so a successful call means "the token is not valid any more", not "it
        existed". ``token_type_hint`` (``access_token`` / ``refresh_token``) only
        tells the server which store to search first.
        """
        data = {"token": token, "client_id": self._config.client_id}
        if token_type_hint:
            data["token_type_hint"] = token_type_hint

        # A confidential client still authenticates with Basic; a public one names
        # itself in the body. An empty Basic header would authenticate as a
        # confidential client with a blank password, which the server must refuse.
        secret = self._config.client_secret
        url = self._endpoint("revocation_endpoint")

        # Branched rather than passing ``auth=None``: httpx types the argument as
        # "credentials or the client default", and None is neither — a public client
        # simply does not send the header.
        if secret:
            response = self._http.post(url, data=data, auth=(self._config.client_id, secret))
        else:
            response = self._http.post(url, data=data)
        if response.status_code >= 400:
            raise AuthenticationError.from_response("Revocation request failed", response)

    def publish_manifest(self, manifest: AuthzManifest) -> dict[str, Any]:
        """Publish this app's declared roles & permissions manifest to Cbox ID.

        Run this on deploy. It mints a client-credentials token with the
        ``apps.manifest`` scope, then POSTs the manifest to
        ``{issuer}/api/v1/apps/manifest``. The app owns what roles mean; Cbox ID owns
        who holds them. Republishing an unchanged catalog is a server-side no-op.

        Returns the server's sync summary (``unchanged``, ``roles_declared``,
        ``permissions_declared``, ``orphaned_roles`` …). Raises
        :class:`ManifestPublishError` when the push is rejected.
        """
        if not self._config.client_secret:
            raise ConfigurationError(
                "Publishing a manifest requires issuer, client_id and client_secret."
            )

        token = self.machine_token(scopes=["apps.manifest"])
        url = f"{self._config.issuer.rstrip('/')}/api/v1/apps/manifest"
        response = self._http.post(
            url,
            json=manifest.to_dict(),
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        if response.status_code >= 400:
            raise ManifestPublishError(
                f"Manifest push failed: HTTP {response.status_code} {response.text}"
            )
        result: dict[str, Any] = response.json()
        return result

    def verify_webhook(
        self,
        payload: str,
        signature_header: str | None,
        secret: str,
        tolerance_seconds: int = 300,
    ) -> bool:
        """Verify a Cbox ID webhook / inline-action signature."""
        return verify_webhook(payload, signature_header, secret, tolerance_seconds)

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._http.close()

    def __enter__(self) -> CboxIdClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- internals -----------------------------------------------------------

    def _exchange(self, code: str, verifier: str, redirect_uri: str | None) -> dict[str, Any]:
        data: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri or self._config.redirect_uri,
            "client_id": self._config.client_id,
            "code_verifier": verifier,
        }
        if self._config.client_secret:
            data["client_secret"] = self._config.client_secret

        response = self._http.post(self._endpoint("token_endpoint"), data=data)
        if response.status_code >= 400:
            raise AuthenticationError.from_response("Token exchange failed", response)
        result: dict[str, Any] = response.json()
        return result

    def _verify_id_token(self, id_token: str, nonce: str | None) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(id_token)
            key_data = self._signing_key(header.get("kid"))
            if key_data is None:
                raise AuthenticationError("No matching key for the id_token.")

            kty = key_data.get("kty")
            algorithms = _ID_TOKEN_ALGORITHMS.get(kty if isinstance(kty, str) else "")
            if algorithms is None:
                raise AuthenticationError(f"Unsupported id_token signing key type: {kty!r}.")

            # RSA and EC keys need different JWK parsers; the alg allow-list stays
            # explicit either way, so an instance rotating to EC keys keeps working.
            parse = RSAAlgorithm.from_jwk if kty == "RSA" else ECAlgorithm.from_jwk
            public_key = parse(json.dumps(key_data))
            claims: dict[str, Any] = jwt.decode(
                id_token,
                public_key,  # type: ignore[arg-type]
                algorithms=list(algorithms),
                audience=self._config.client_id,
                issuer=self._config.issuer,
            )
        except AuthenticationError:
            raise
        except Exception as exc:  # noqa: BLE001 — surface any verification failure uniformly
            raise AuthenticationError(f"The id_token could not be verified: {exc}") from exc

        if nonce and claims.get("nonce") != nonce:
            raise AuthenticationError("The id_token nonce did not match — possible replay.")
        return claims

    def _discovery(self) -> dict[str, Any]:
        if self._discovery_cache and self._discovery_cache[1] > time.time():
            return self._discovery_cache[0]
        url = f"{self._config.issuer.rstrip('/')}/.well-known/openid-configuration"
        response = self._http.get(url)
        if response.status_code >= 400:
            raise AuthenticationError(
                f"Discovery request failed with status {response.status_code}."
            )
        doc: dict[str, Any] = response.json()
        if not isinstance(doc.get("issuer"), str):
            raise AuthenticationError("The discovery document was missing an issuer.")
        self._discovery_cache = (doc, time.time() + self._config.cache_ttl_seconds)
        return doc

    def _signing_key(self, kid: Any) -> dict[str, Any] | None:
        """The JWKS key for ``kid``, refetching once when the cached set lacks it.

        The instance can roll its signing key inside our cache TTL; without a refetch
        every login would fail until the TTL lapsed. The refetch is on a cooldown so
        a token bearing a bogus kid cannot turn each verification into a JWKS request.
        """
        key = _find_key(self._jwks(), kid)
        if key is not None:
            return key

        now = time.time()
        if now - self._jwks_refetched_at < _JWKS_REFETCH_COOLDOWN_SECONDS:
            return None

        self._jwks_refetched_at = now
        self._jwks_cache = None
        return _find_key(self._jwks(), kid)

    def _jwks(self) -> dict[str, Any]:
        if self._jwks_cache and self._jwks_cache[1] > time.time():
            return self._jwks_cache[0]
        response = self._http.get(self._endpoint("jwks_uri"))
        if response.status_code >= 400:
            raise AuthenticationError("JWKS request failed.")
        jwks: dict[str, Any] = response.json()
        self._jwks_cache = (jwks, time.time() + self._config.cache_ttl_seconds)
        return jwks

    def _endpoint(self, name: str) -> str:
        value = self._discovery().get(name)
        if not isinstance(value, str) or value == "":
            raise ConfigurationError(f"The instance does not advertise a {name}.")
        return value

    def _optional_endpoint(self, name: str) -> str | None:
        value = self._discovery().get(name)
        return value if isinstance(value, str) and value != "" else None

    def _account_path(self) -> str:
        path = self._config.account_path
        return f"/{path.lstrip('/')}" if path else "/settings"

    def _require_secret(self) -> str:
        if not self._config.client_secret:
            raise ConfigurationError(
                "This call requires a `client_secret`, but none is configured."
            )
        return self._config.client_secret


def _find_key(jwks: dict[str, Any], kid: Any) -> dict[str, Any] | None:
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        return None
    return next(
        (k for k in keys if isinstance(k, dict) and k.get("kid") == kid),
        None,
    )
