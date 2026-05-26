"""Tests for Ed25519 sign/verify."""
from __future__ import annotations
import time

import pytest


class TestSignVerify:
    def test_roundtrip(self):
        from crypto import sign_license, verify_license
        mid = "abc123def456" + "0" * 12
        token = sign_license("monthly", mid, license_id=42, duration_days=30)
        t = verify_license(token)
        assert t.tier == "monthly"
        assert t.machine_id == mid[:24]
        assert t.license_id == 42
        assert not t.is_lifetime
        assert not t.is_expired
        assert 28 <= t.days_remaining() <= 30

    def test_lifetime_token(self):
        from crypto import sign_license, verify_license
        mid = "abc123def456" + "0" * 12
        token = sign_license("lifetime", mid, license_id=1, duration_days=None)
        t = verify_license(token)
        assert t.is_lifetime
        assert t.expires_at == 0
        assert t.days_remaining() is None

    def test_tampered_payload_rejected(self):
        from crypto import sign_license, verify_license, LicenseTokenError
        mid = "abc123def456" + "0" * 12
        token = sign_license("monthly", mid, 1, 30)
        # flip a char in the payload portion (before the dot)
        payload, sig = token.split(".", 1)
        bad = payload[:-1] + ("Z" if payload[-1] != "Z" else "Y") + "." + sig
        with pytest.raises(LicenseTokenError, match="signature"):
            verify_license(bad)

    def test_tampered_signature_rejected(self):
        from crypto import sign_license, verify_license, LicenseTokenError
        mid = "abc123def456" + "0" * 12
        token = sign_license("monthly", mid, 1, 30)
        payload, sig = token.split(".", 1)
        bad = payload + "." + (sig[:-1] + ("A" if sig[-1] != "A" else "B"))
        with pytest.raises(LicenseTokenError):
            verify_license(bad)

    def test_wrong_keypair_rejected(self):
        """A token signed by KEYPAIR_A must NOT verify against KEYPAIR_B's pubkey."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        from crypto import sign_license, verify_license, LicenseTokenError
        mid = "abc123def456" + "0" * 12
        token = sign_license("monthly", mid, 1, 30)
        # New unrelated keypair
        other_pk = Ed25519PrivateKey.generate().public_key()
        other_pem = other_pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        with pytest.raises(LicenseTokenError):
            verify_license(token, public_key_pem_or_obj=other_pem)

    def test_each_token_unique(self):
        from crypto import sign_license
        mid = "abc123def456" + "0" * 12
        tokens = {sign_license("monthly", mid, i, 30) for i in range(10)}
        assert len(tokens) == 10   # nonce + license_id ensure uniqueness

    def test_public_key_pem_loadable(self):
        from crypto import public_key_pem
        pem = public_key_pem()
        assert "BEGIN PUBLIC KEY" in pem
        assert "END PUBLIC KEY" in pem

    def test_peek_decodes_without_verify(self):
        from crypto import sign_license, peek_token
        mid = "abc123def456" + "0" * 12
        token = sign_license("annual", mid, 7, 365)
        peeked = peek_token(token)
        assert peeked["tier"] == "annual"
        assert peeked["license_id"] == 7
