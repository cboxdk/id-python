"""A fake Cbox ID instance backed by a real RSA keypair and PyJWT-signed tokens.

Tests run against genuine crypto (real RS256 keys, real JWKS, real signed id_tokens)
served through an httpx MockTransport — not stubbed success.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from cbox_id import CboxIdClient, CboxIdConfig

ISSUER = "https://id.test"
CLIENT_ID = "client-abc"
NONCE = "test-nonce"

DISCOVERY = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/oauth/authorize",
    "token_endpoint": f"{ISSUER}/oauth/token",
    "jwks_uri": f"{ISSUER}/oauth/jwks",
    "userinfo_endpoint": f"{ISSUER}/oauth/userinfo",
    "introspection_endpoint": f"{ISSUER}/oauth/introspect",
    "revocation_endpoint": f"{ISSUER}/oauth/revoke",
    "end_session_endpoint": f"{ISSUER}/oauth/logout",
}


@dataclass
class FakeInstance:
    client: CboxIdClient
    sign_id_token: Callable[[dict[str, Any]], str]
    # Signs with a DIFFERENT key than the JWKS advertises (kid still "test-key"), so
    # the signature must fail to verify.
    sign_foreign_id_token: Callable[[dict[str, Any]], str]
    # Signs ES256 with the EC key the JWKS also advertises (kid "test-key-ec").
    sign_es256_id_token: Callable[[dict[str, Any]], str]
    # Rolls the RSA signing key to a new kid and re-serves the JWKS, as an instance
    # does when it rotates signing material inside a client's cache TTL.
    rotate_signing_key: Callable[[], None]
    # The mock-transport HTTP client, so a test can build a differently-configured
    # client against the same fake instance.
    http: httpx.Client
    token_response: dict[str, Any] = field(default_factory=dict)
    # Recorded by the endpoints, for assertions.
    revocations: list[dict[str, Any]] = field(default_factory=list)
    revocation_auth: list[str | None] = field(default_factory=list)
    # A one-shot failure for the token endpoint, so a test can assert what the SDK makes
    # of an RFC 6749 §5.2 error body without breaking the fake for every later call.
    next_token_failure: tuple[object, int, dict[str, str]] | None = None
    jwks_fetches: int = 0

    def set_token_response(self, response: dict[str, Any]) -> None:
        self.token_response.clear()
        self.token_response.update(response)

    def fail_next_token(
        self, body: object, status: int, headers: dict[str, str] | None = None
    ) -> None:
        """Make the NEXT token-endpoint call fail, once.

        A dict is served as JSON (an RFC 6749 §5.2 error body); a string is served
        verbatim, which is how a proxy or captive portal answers.
        """
        self.next_token_failure = (body, status, headers or {})


@pytest.fixture
def fake() -> FakeInstance:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk.update({"kid": "test-key", "alg": "RS256", "use": "sig"})

    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_jwk = json.loads(ECAlgorithm.to_jwk(ec_key.public_key()))
    ec_jwk.update({"kid": "test-key-ec", "alg": "ES256", "use": "sig"})

    foreign_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # The key material the instance is signing with right now, and the set its JWKS
    # advertises. rotate_signing_key() swaps both, exactly as a key roll does.
    signing = {"key": private_key, "kid": "test-key"}
    served_keys = [jwk, ec_jwk]

    def sign_id_token(claims: dict[str, Any]) -> str:
        payload = {"iat": int(time.time()), "exp": int(time.time()) + 300, **claims}
        return jwt.encode(
            payload, signing["key"], algorithm="RS256", headers={"kid": signing["kid"]}
        )

    def sign_foreign_id_token(claims: dict[str, Any]) -> str:
        payload = {"iat": int(time.time()), "exp": int(time.time()) + 300, **claims}
        return jwt.encode(payload, foreign_key, algorithm="RS256", headers={"kid": "test-key"})

    def sign_es256_id_token(claims: dict[str, Any]) -> str:
        payload = {"iat": int(time.time()), "exp": int(time.time()) + 300, **claims}
        return jwt.encode(payload, ec_key, algorithm="ES256", headers={"kid": "test-key-ec"})

    def rotate_signing_key() -> None:
        rotated = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rotated_jwk = json.loads(RSAAlgorithm.to_jwk(rotated.public_key()))
        rotated_jwk.update({"kid": "test-key-2", "alg": "RS256", "use": "sig"})
        signing["key"] = rotated
        signing["kid"] = "test-key-2"
        served_keys[:] = [rotated_jwk, ec_jwk]

    default_id_token = sign_id_token(
        {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "user-1",
            "nonce": NONCE,
            "email": "ada@acme.com",
            "name": "Ada",
            "org": "org-1",
        }
    )

    state = FakeInstance(
        client=None,  # type: ignore[arg-type]
        sign_id_token=sign_id_token,
        sign_foreign_id_token=sign_foreign_id_token,
        sign_es256_id_token=sign_es256_id_token,
        rotate_signing_key=rotate_signing_key,
        http=None,  # type: ignore[arg-type]
    )
    state.token_response = {
        "access_token": "access-abc",
        "id_token": default_id_token,
        "refresh_token": "refresh-abc",
        "expires_in": 3600,
        "token_type": "Bearer",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json=DISCOVERY)
        if url == DISCOVERY["jwks_uri"]:
            state.jwks_fetches += 1
            return httpx.Response(200, json={"keys": list(served_keys)})
        if url == DISCOVERY["token_endpoint"]:
            if state.next_token_failure is not None:
                body, status, headers = state.next_token_failure
                state.next_token_failure = None

                # A string is served verbatim — that is how a proxy or captive portal
                # answers, and the case where the SDK must not invent an error code.
                if isinstance(body, str):
                    return httpx.Response(status, text=body, headers=headers)

                return httpx.Response(status, json=body, headers=headers)

            form = dict(parse_qsl(request.content.decode()))
            if form.get("grant_type") == "client_credentials":
                return httpx.Response(200, json={"access_token": "machine-token"})
            return httpx.Response(200, json=state.token_response)
        if url == DISCOVERY["userinfo_endpoint"]:
            return httpx.Response(
                200,
                json={"sub": "user-1", "email": "ada@acme.com", "name": "Ada", "org": "org-1"},
            )
        if url == DISCOVERY["introspection_endpoint"]:
            return httpx.Response(200, json={"active": True, "sub": "user-1", "scope": "openid"})
        if url == DISCOVERY["revocation_endpoint"]:
            state.revocations.append(dict(parse_qsl(request.content.decode())))
            state.revocation_auth.append(request.headers.get("authorization"))
            # RFC 7009: a successful revocation carries an empty 200 body.
            return httpx.Response(200)
        return httpx.Response(404)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    state.http = http_client
    config = CboxIdConfig(
        issuer=ISSUER,
        client_id=CLIENT_ID,
        client_secret="secret-xyz",
        redirect_uri="https://app.test/auth/callback",
    )
    state.client = CboxIdClient(config, http_client=http_client)
    return state
