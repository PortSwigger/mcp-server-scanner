from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import time
from enum import StrEnum
from typing import Any

from jwt.algorithms import RSAAlgorithm

from mcp_test_server.oauth.signer import KEY_ID, JwtSigner
from mcp_test_server.weakness import WeaknessSet


class JwtWeakness(StrEnum):
    FORGED_SIGNATURE = "forged_signature"
    ALG_NONE = "alg_none"
    HS256_KEY_CONFUSION = "hs256_key_confusion"
    EMPTY_KEY_UNKNOWN_KID = "empty_key_unknown_kid"
    WRONG_AUDIENCE = "wrong_audience"
    WRONG_ISSUER = "wrong_issuer"
    EXPIRED = "expired"


class InvalidToken(Exception):
    pass


class TokenVerifier:
    def __init__(self, signer: JwtSigner, weaknesses: WeaknessSet[JwtWeakness]) -> None:
        self._signer = signer
        self._weaknesses = weaknesses

    def accepts(self, token: str) -> bool:
        try:
            self.verify(token)
        except InvalidToken:
            return False
        return True

    def verify(self, token: str) -> dict[str, Any]:
        header, claims, signing_input, signature = _split(token)
        self._verify_signature(header, signing_input, signature)
        self._verify_claims(claims)
        return claims

    def _verify_signature(self, header: dict[str, Any], signing_input: bytes, signature: bytes) -> None:
        algorithm = str(header.get("alg"))
        if algorithm.lower() == "none":
            self._require(JwtWeakness.ALG_NONE, not signature)
        elif algorithm == "HS256":
            self._verify_hmac(header, signing_input, signature)
        elif algorithm == "RS256":
            if not self._rsa_valid(signing_input, signature):
                self._require(JwtWeakness.FORGED_SIGNATURE, True)
        else:
            raise InvalidToken(f"Unsupported algorithm {algorithm}")

    def _verify_claims(self, claims: dict[str, Any]) -> None:
        if claims.get("iss") != self._signer.issuer:
            self._require(JwtWeakness.WRONG_ISSUER, True)
        if not self._audience_matches(claims.get("aud")):
            self._require(JwtWeakness.WRONG_AUDIENCE, True)
        expiry = claims.get("exp")
        if not isinstance(expiry, int | float) or expiry <= time.time():
            self._require(JwtWeakness.EXPIRED, True)

    def _require(self, weakness: JwtWeakness, condition: bool) -> None:
        if not (condition and self._weaknesses.active(weakness)):
            raise InvalidToken(f"Rejected by {weakness.value} validation")

    def _audience_matches(self, audience: Any) -> bool:
        audiences = audience if isinstance(audience, list) else [audience]
        return self._signer.audience in audiences

    def _rsa_valid(self, signing_input: bytes, signature: bytes) -> bool:
        return bool(RSAAlgorithm(RSAAlgorithm.SHA256).verify(signing_input, self._signer.public_key, signature))

    def _verify_hmac(self, header: dict[str, Any], signing_input: bytes, signature: bytes) -> None:
        if self._weaknesses.active(JwtWeakness.HS256_KEY_CONFUSION) and self._hmac_with_public_key(
                signing_input, signature):
            return
        unknown_kid = isinstance(header.get("kid"), str) and header.get("kid") != KEY_ID
        self._require(JwtWeakness.EMPTY_KEY_UNKNOWN_KID,
                      unknown_kid and _hmac_matches(b"", signing_input, signature))

    def _hmac_with_public_key(self, signing_input: bytes, signature: bytes) -> bool:
        pem = self._signer.public_key_pem()
        return any(_hmac_matches(key, signing_input, signature) for key in {pem, pem.rstrip(b"\n")})


def _hmac_matches(key: bytes, signing_input: bytes, signature: bytes) -> bool:
    return hmac.compare_digest(hmac.new(key, signing_input, hashlib.sha256).digest(), signature)


def _split(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    parts = token.split(".")
    if len(parts) != 3:
        raise InvalidToken("Malformed JWT")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        claims = json.loads(_b64url_decode(parts[1]))
        signature = _b64url_decode(parts[2])
    except (ValueError, binascii.Error) as error:
        raise InvalidToken("Malformed JWT") from error
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise InvalidToken("Malformed JWT")
    return header, claims, f"{parts[0]}.{parts[1]}".encode(), signature


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
