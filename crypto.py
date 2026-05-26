"""Ed25519 signing for license tokens.

Why Ed25519 instead of HMAC
---------------------------
HMAC requires the same secret on both sides — anyone holding the secret
can mint codes. Ed25519 is asymmetric: the PRIVATE key on this server
signs, the PUBLIC key shipped in the customer's bot only verifies.

A customer can extract the public key from the bot binary; that gives them
nothing — they cannot produce a new signature without the private key.

Format
------
A "license token" is the JSON payload + base64-url-encoded signature, joined
with a dot:

    base64url(json_payload).base64url(signature)

Example:
    eyJ0aWVyIjoibW9udGhseSIsLi4ufQ.<sig>

The JSON payload includes everything we need to enforce:

    {
      "version": 1,
      "tier": "monthly",
      "machine_id": "<24 hex chars>",
      "issued_at": 1700000000,
      "expires_at": 1702592000,        # 0 = lifetime
      "license_id": 42,                # server's DB row id
      "nonce": "<8 random bytes hex>"  # replay protection
    }
"""
from __future__ import annotations
import base64
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)


# -------------------------------------------------------------------------
# Key loading
# -------------------------------------------------------------------------
def _key_path(name: str) -> Path:
    """Resolve key path from env or default to ./state/<name>."""
    env = os.getenv(f"MASTER_{name.upper()}_PATH")
    if env:
        return Path(env)
    base = Path(os.getenv("LICENSE_STATE_DIR", "state"))
    base.mkdir(parents=True, exist_ok=True)
    return base / f"master_{name}.pem"


def load_private_key() -> Ed25519PrivateKey:
    """Load the server's Ed25519 private key.

    Looks for (in order):
      1. MASTER_PRIVATE_KEY env var (PEM string — for Railway/Fly secrets)
      2. MASTER_PRIVATE_KEY_PATH env var (file path)
      3. ./state/master_private.pem (local dev)
    """
    pem_raw = os.getenv("MASTER_PRIVATE_KEY")
    if pem_raw:
        return serialization.load_pem_private_key(pem_raw.encode("utf-8"), password=None)
    path = _key_path("private")
    if not path.exists():
        raise FileNotFoundError(
            f"private key not found at {path}. "
            f"Run `python scripts/generate_master_keys.py` first."
        )
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key() -> Ed25519PublicKey:
    """Load the matching public key. Used only by this server for sanity
    checks; the customer's bot embeds its own copy."""
    sk = load_private_key()
    return sk.public_key()


def public_key_pem() -> str:
    """Serialize public key as PEM — copy this into the customer's bot."""
    pk = load_public_key()
    pem = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("ascii")


# -------------------------------------------------------------------------
# Encode helpers
# -------------------------------------------------------------------------
def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad))


# -------------------------------------------------------------------------
# Sign / verify
# -------------------------------------------------------------------------
class LicenseTokenError(ValueError):
    """Raised when a token fails to decode or verify."""


@dataclass
class LicenseToken:
    version: int
    tier: str
    machine_id: str
    issued_at: int
    expires_at: int       # 0 = lifetime
    license_id: int
    nonce: str
    raw_token: str

    @property
    def is_lifetime(self) -> bool:
        return self.expires_at == 0

    @property
    def is_expired(self) -> bool:
        return (not self.is_lifetime) and self.expires_at < int(time.time())

    def days_remaining(self) -> Optional[int]:
        if self.is_lifetime:
            return None
        return max(0, (self.expires_at - int(time.time())) // 86400)


def sign_license(tier: str, machine_id: str, license_id: int,
                 duration_days: Optional[int]) -> str:
    """Mint a fresh license token signed with the server's private key.

    duration_days=None means lifetime (expires_at=0).
    """
    issued = int(time.time())
    expires = 0 if duration_days is None else issued + duration_days * 86400

    payload = {
        "version": 1,
        "tier": tier,
        "machine_id": machine_id[:24].lower(),
        "issued_at": issued,
        "expires_at": expires,
        "license_id": license_id,
        "nonce": secrets.token_hex(8),
    }
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    sk = load_private_key()
    sig = sk.sign(payload_bytes)
    return _b64u(payload_bytes) + "." + _b64u(sig)


def verify_license(token: str, public_key_pem_or_obj=None) -> LicenseToken:
    """Verify a token's signature. Used both server-side (for sanity) and
    client-side (the customer's bot ships only the public key).
    """
    if "." not in token:
        raise LicenseTokenError("token missing signature separator '.'")
    payload_b64, sig_b64 = token.split(".", 1)
    try:
        payload_bytes = _b64u_decode(payload_b64)
        sig = _b64u_decode(sig_b64)
    except Exception as e:
        raise LicenseTokenError(f"base64 decode failed: {e}")

    # Resolve public key
    if public_key_pem_or_obj is None:
        pk = load_public_key()
    elif isinstance(public_key_pem_or_obj, str):
        pk = serialization.load_pem_public_key(public_key_pem_or_obj.encode("utf-8"))
    else:
        pk = public_key_pem_or_obj

    try:
        pk.verify(sig, payload_bytes)
    except InvalidSignature:
        raise LicenseTokenError("invalid signature")

    try:
        d = json.loads(payload_bytes)
    except json.JSONDecodeError as e:
        raise LicenseTokenError(f"payload not JSON: {e}")

    if d.get("version") != 1:
        raise LicenseTokenError(f"unsupported token version: {d.get('version')}")
    for field in ("tier", "machine_id", "issued_at", "expires_at", "license_id", "nonce"):
        if field not in d:
            raise LicenseTokenError(f"token missing field: {field}")

    return LicenseToken(
        version=d["version"], tier=d["tier"],
        machine_id=d["machine_id"], issued_at=d["issued_at"],
        expires_at=d["expires_at"], license_id=d["license_id"],
        nonce=d["nonce"], raw_token=token,
    )


def peek_token(token: str) -> dict:
    """Decode payload WITHOUT verifying signature — for UI preview only."""
    try:
        payload_b64 = token.split(".", 1)[0]
        return json.loads(_b64u_decode(payload_b64))
    except Exception as e:
        return {"error": str(e)}
