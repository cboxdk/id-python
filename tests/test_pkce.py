from __future__ import annotations

import re

from cbox_id.pkce import challenge, create_verifier, random_token


def test_verifier_is_url_safe_without_padding() -> None:
    verifier = create_verifier()
    assert re.fullmatch(r"[A-Za-z0-9_-]+", verifier)
    assert len(verifier) >= 43


def test_random_tokens_differ() -> None:
    assert random_token() != random_token()


def test_challenge_matches_rfc7636_vector() -> None:
    # RFC 7636 Appendix B.
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
