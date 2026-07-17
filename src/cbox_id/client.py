"""The Cbox ID client — a hardened OpenID Connect relying party."""

from __future__ import annotations

import hmac
import json
import time
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

from .authz import AuthzManifest
from .errors import (
    AuthenticationError,
    ConfigurationError,
    InvalidStateError,
    ManifestPublishError,
)
from .models import AuthorizationRequest, CboxIdConfig, CboxUser
from .pkce import challenge, create_verifier, random_token
from .webhook import verify_webhook


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

    # -- login ---------------------------------------------------------------

    def create_authorization_request(
        self,
        *,
        scopes: list[str] | None = None,
        state: str | None = None,
        prompt: str | None = None,
        login_hint: str | None = None,
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
        if login_hint:
            params["login_hint"] = login_hint

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

    def logout_url(self, return_to: str | None = None) -> str | None:
        """RP-initiated logout URL, or ``None`` when the instance advertises none."""
        endpoint = self._optional_endpoint("end_session_endpoint")
        if endpoint is None:
            return None
        if return_to is None:
            return endpoint
        return f"{endpoint}?{urlencode({'post_logout_redirect_uri': return_to})}"

    # -- back-channel --------------------------------------------------------

    def machine_token(
        self, *, scopes: list[str] | None = None, resource: str | None = None
    ) -> str:
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
            raise AuthenticationError(f"Machine token request failed: {response.text}")
        token = response.json().get("access_token")
        if not isinstance(token, str):
            raise AuthenticationError("The token response had no access_token.")
        return token

    def userinfo(self, access_token: str) -> dict[str, Any]:
        """The OIDC userinfo claims for an access token."""
        endpoint = self._optional_endpoint("userinfo_endpoint")
        if endpoint is None:
            return {}
        response = self._http.get(
            endpoint, headers={"Authorization": f"Bearer {access_token}"}
        )
        if response.status_code >= 400:
            raise AuthenticationError("Userinfo request failed.")
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
            raise AuthenticationError("Introspection request failed.")
        result: dict[str, Any] = response.json()
        return result

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

    def _exchange(
        self, code: str, verifier: str, redirect_uri: str | None
    ) -> dict[str, Any]:
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
            raise AuthenticationError(f"Token exchange failed: {response.text}")
        result: dict[str, Any] = response.json()
        return result

    def _verify_id_token(self, id_token: str, nonce: str | None) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(id_token)
            kid = header.get("kid")
            key_data = next(
                (k for k in self._jwks().get("keys", []) if k.get("kid") == kid), None
            )
            if key_data is None:
                raise AuthenticationError("No matching key for the id_token.")
            public_key = RSAAlgorithm.from_jwk(json.dumps(key_data))
            claims: dict[str, Any] = jwt.decode(
                id_token,
                public_key,  # type: ignore[arg-type]
                algorithms=["RS256"],
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
