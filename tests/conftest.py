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
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

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
    "end_session_endpoint": f"{ISSUER}/oauth/logout",
}


@dataclass
class FakeInstance:
    client: CboxIdClient
    sign_id_token: Callable[[dict[str, Any]], str]
    token_response: dict[str, Any] = field(default_factory=dict)

    def set_token_response(self, response: dict[str, Any]) -> None:
        self.token_response.clear()
        self.token_response.update(response)


@pytest.fixture
def fake() -> FakeInstance:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    jwk = json.loads(RSAAlgorithm.to_jwk(public_key))
    jwk.update({"kid": "test-key", "alg": "RS256", "use": "sig"})

    def sign_id_token(claims: dict[str, Any]) -> str:
        payload = {"iat": int(time.time()), "exp": int(time.time()) + 300, **claims}
        return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-key"})

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

    state = FakeInstance(client=None, sign_id_token=sign_id_token)  # type: ignore[arg-type]
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
            return httpx.Response(200, json={"keys": [jwk]})
        if url == DISCOVERY["token_endpoint"]:
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
        return httpx.Response(404)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    config = CboxIdConfig(
        issuer=ISSUER,
        client_id=CLIENT_ID,
        client_secret="secret-xyz",
        redirect_uri="https://app.test/auth/callback",
    )
    state.client = CboxIdClient(config, http_client=http_client)
    return state
