"""DPoP (RFC 9449) proofs for a sender-constrained access token.

A DPoP-bound token (its ``cnf.jkt`` names a key) is presented as ``Authorization: DPoP
<token>`` with a fresh proof per request, signed by that key: ``htm`` and ``htu`` pin the
request, ``ath`` pins the token, ``jti`` and ``iat`` make it single-use. A stolen token
without the private key is useless.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit, urlunsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from ..errors import ConfigurationError


@runtime_checkable
class DPoPSigner(Protocol):
    """Produces the ``DPoP`` header value for one request."""

    @property
    def jkt(self) -> str:
        """The RFC 7638 thumbprint of the public key — the ``jkt`` a bound token's ``cnf`` names."""
        ...

    def proof(
        self, *, method: str, url: str, access_token: str, nonce: str | None = None
    ) -> str: ...


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sha256(text: str) -> str:
    return _b64url(hashlib.sha256(text.encode("utf-8")).digest())


def generate_dpop_key() -> ec.EllipticCurvePrivateKey:
    """A fresh P-256 private key for :class:`ES256DPoPSigner`."""
    return ec.generate_private_key(ec.SECP256R1())


class ES256DPoPSigner:
    """Signs ES256 proofs with the key the access token was bound to when it was issued
    (the same one the token request's own DPoP proof used)."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise ConfigurationError("A DPoP key must be an ECDSA P-256 key.")

        numbers = private_key.public_key().public_numbers()
        self._key = private_key
        #: The public key as a JWK, in RFC 7638's member order.
        self.jwk: dict[str, str] = {
            "crv": "P-256",
            "kty": "EC",
            "x": _b64url(numbers.x.to_bytes(32, "big")),
            "y": _b64url(numbers.y.to_bytes(32, "big")),
        }
        # RFC 7638: the required members, lexicographic order, no whitespace.
        self._jkt = _sha256(json.dumps(self.jwk, separators=(",", ":"), sort_keys=True))

    @property
    def jkt(self) -> str:
        return self._jkt

    def proof(self, *, method: str, url: str, access_token: str, nonce: str | None = None) -> str:
        parts = urlsplit(url)
        payload: dict[str, object] = {
            "jti": str(uuid.uuid4()),
            "htm": method.upper(),
            # RFC 9449 §4.2: the URI without query and fragment.
            "htu": urlunsplit((parts.scheme, parts.netloc, parts.path, "", "")),
            "iat": int(time.time()),
            "ath": _sha256(access_token),
        }

        if nonce is not None:
            payload["nonce"] = nonce

        return jwt.encode(
            payload,
            self._key,
            algorithm="ES256",
            headers={"typ": "dpop+jwt", "jwk": self.jwk},
        )
