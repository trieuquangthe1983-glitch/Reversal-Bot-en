"""License server FastAPI app.

Endpoints
---------
GET  /health                       liveness probe
GET  /pricing                      public tier info + payment wallet
GET  /public-key                   the Ed25519 public key (for offline verify)
POST /verify-payment               buyer submits tx_hash + tier -> we verify
                                   on BSC, mint signed token, return it
POST /activate                     buyer submits token + machine_id -> we
                                   re-verify signature, mark activated,
                                   return license JSON
POST /heartbeat                    bot calls periodically with its token;
                                   we update last_heartbeat_at + report
                                   revoked? expired? days_remaining
POST /admin/revoke/{license_id}    seller-only: revoke a license
GET  /admin/list                   seller-only: list licenses
"""
from __future__ import annotations
import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel

from blockchain import (PAYMENT_WALLET_ADDRESS, MIN_CONFIRMATIONS,
                       USDT_BEP20_CONTRACT, PaymentVerifyError,
                       verify_bsc_payment)
from crypto import (LicenseTokenError, peek_token, public_key_pem,
                   sign_license, verify_license)
from db import (ActivationAttemptRepo, LicenseRepo, PaymentProofRepo,
               close_thread_connection, init_db)
from tiers import TIERS


# Rate limit knobs (per-IP)
RATE_LIMIT_FAILURES = int(os.getenv("LICENSE_RATE_LIMIT_FAILURES", "5"))
RATE_LIMIT_WINDOW_MINUTES = int(os.getenv("LICENSE_RATE_LIMIT_WINDOW_MINUTES", "60"))
ADMIN_TOKEN = os.getenv("LICENSE_ADMIN_TOKEN", "")    # required for /admin/*


@asynccontextmanager
async def _lifespan(app: FastAPI):
    init_db()
    # Sanity: keys load
    try:
        _ = public_key_pem()
    except Exception as e:
        raise RuntimeError(
            f"Could not load Ed25519 keys: {e}. Run "
            f"`python scripts/generate_master_keys.py` first."
        )
    yield
    close_thread_connection()


app = FastAPI(title="Reversal Bot License Server", version="1.0.0",
              lifespan=_lifespan)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _client_ip(request: Request) -> str | None:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


def _check_rate_limit(ip: str | None) -> None:
    if not ip:
        return
    fails = ActivationAttemptRepo.count_recent_failures(
        ip, minutes=RATE_LIMIT_WINDOW_MINUTES)
    if fails >= RATE_LIMIT_FAILURES:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"too many failed attempts from {ip} "
            f"({fails} in last {RATE_LIMIT_WINDOW_MINUTES} min). Try again later."
        )


def _require_admin(x_admin_token: str = Header(default="")) -> None:
    if not ADMIN_TOKEN:
        raise HTTPException(503, "admin endpoints not configured "
                                 "(set LICENSE_ADMIN_TOKEN env)")
    if x_admin_token != ADMIN_TOKEN:
        raise HTTPException(401, "bad admin token")


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class VerifyPaymentIn(BaseModel):
    tx_hash: str
    tier: str
    machine_id: str
    customer_email: Optional[str] = None


class ActivateIn(BaseModel):
    token: str
    machine_id: str


class HeartbeatIn(BaseModel):
    token: str


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------
@app.get("/")
def root():
    """Friendly landing for browser visits."""
    return {
        "service": "Reversal Bot License Server",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "GET  /health":       "liveness probe",
            "GET  /pricing":      "tier list + payment wallet",
            "GET  /public-key":   "Ed25519 public key (PEM)",
            "POST /verify-payment": "verify BSC tx + mint signed token",
            "POST /activate":     "register an activation",
            "POST /heartbeat":    "bot status check",
            "GET  /admin/list":   "list licenses (requires x-admin-token)",
            "POST /admin/revoke/{id}": "revoke a license (requires x-admin-token)",
            "GET  /docs":         "interactive API docs (Swagger UI)",
        },
        "support_email": "dht.io.vn@gmail.com",
    }


@app.get("/health")
def health():
    return {"ok": True, "version": "1.0.0"}


@app.get("/pricing")
def pricing():
    return {
        "tiers": [
            {
                "name": t.name, "price_usdt": t.price_usdt,
                "duration_days": t.duration_days, "discount_pct": t.discount_pct,
                "description": t.description, "is_trial": t.is_trial,
                "is_lifetime": t.duration_days is None,
            }
            for t in TIERS.values()
        ],
        "payment": {
            "network": "BSC (BEP20)",
            "token": "USDT",
            "wallet": PAYMENT_WALLET_ADDRESS,
            "usdt_contract": USDT_BEP20_CONTRACT,
            "min_confirmations": MIN_CONFIRMATIONS,
        },
        "support_email": "dht.io.vn@gmail.com",
    }


@app.get("/public-key")
def public_key():
    """Returns the Ed25519 public key in PEM. The bot embeds this so it
    can verify the token offline."""
    return {"public_key_pem": public_key_pem()}


# ---------------------------------------------------------------------------
# Buyer flow
# ---------------------------------------------------------------------------
@app.post("/verify-payment")
def verify_payment(payload: VerifyPaymentIn, request: Request):
    ip = _client_ip(request)
    _check_rate_limit(ip)

    if payload.tier not in TIERS:
        raise HTTPException(400, f"unknown tier: {payload.tier}")
    machine_id = payload.machine_id[:24].lower()
    if len(machine_id) < 12:
        raise HTTPException(400, "machine_id too short (need >= 12 hex chars)")

    # 1. On-chain verify
    try:
        proof = verify_bsc_payment(payload.tx_hash.strip(),
                                   expected_tier=payload.tier)
    except PaymentVerifyError as e:
        ActivationAttemptRepo.record(
            ip=ip, machine_id=machine_id, endpoint="verify-payment",
            tx_hash=payload.tx_hash, success=False,
            error_reason=f"verify_failed:{e}")
        raise HTTPException(400, str(e))

    # 2. tx uniqueness
    existing = PaymentProofRepo.get_by_tx(proof.tx_hash)
    if existing and existing["consumed_by_license_id"]:
        ActivationAttemptRepo.record(
            ip=ip, machine_id=machine_id, endpoint="verify-payment",
            tx_hash=payload.tx_hash, success=False,
            error_reason="tx_already_consumed")
        raise HTTPException(400,
            "this transaction has already been used to mint a license token. "
            "If this is wrong, contact dht.io.vn@gmail.com.")

    # 3. trial one-shot
    if payload.tier == "trial" and LicenseRepo.has_used_trial(machine_id):
        ActivationAttemptRepo.record(
            ip=ip, machine_id=machine_id, endpoint="verify-payment",
            tx_hash=payload.tx_hash, success=False,
            error_reason="trial_already_used")
        raise HTTPException(400,
            "this machine has already used its trial. Choose a paid tier.")

    if not existing:
        PaymentProofRepo.record(
            tx_hash=proof.tx_hash, from_address=proof.from_address,
            to_address=proof.to_address, amount_usdt=proof.amount_usdt,
            matched_tier=proof.matched_tier, block_number=proof.block_number,
            confirmations=proof.confirmations,
            raw_receipt={"logs": len(proof.raw_receipt.get("logs", []))},
        )

    # 4. Insert license row (no token yet)
    tier = TIERS[payload.tier]
    expires_iso: str | None = None
    if tier.duration_days is not None:
        from datetime import datetime, timedelta, timezone
        expires_iso = (datetime.now(timezone.utc)
                       + timedelta(days=tier.duration_days)).isoformat()
    license_id = LicenseRepo.insert(
        tier=payload.tier, machine_id=machine_id,
        expires_at=expires_iso, payment_tx_hash=proof.tx_hash,
        customer_email=payload.customer_email,
    )

    # 5. Sign the token (with the real DB id baked in)
    token = sign_license(payload.tier, machine_id, license_id, tier.duration_days)
    LicenseRepo.set_token(license_id, token)
    PaymentProofRepo.mark_consumed(proof.tx_hash, license_id)

    ActivationAttemptRepo.record(
        ip=ip, machine_id=machine_id, endpoint="verify-payment",
        tx_hash=payload.tx_hash, success=True, error_reason="")

    return {
        "token": token,
        "license_id": license_id,
        "tier": payload.tier,
        "machine_id": machine_id,
        "expires_at": expires_iso,
        "payment": {
            "tx_hash": proof.tx_hash,
            "amount_usdt": proof.amount_usdt,
            "confirmations": proof.confirmations,
        },
    }


@app.post("/activate")
def activate(payload: ActivateIn, request: Request):
    """Customer's bot calls this with the token + the machine_id it's
    running on. We re-verify the signature server-side (defence in depth),
    confirm machine binding, mark activated."""
    ip = _client_ip(request)
    _check_rate_limit(ip)
    machine_id = payload.machine_id[:24].lower()

    try:
        token = verify_license(payload.token)
    except LicenseTokenError as e:
        ActivationAttemptRepo.record(
            ip=ip, machine_id=machine_id, endpoint="activate",
            tx_hash=None, success=False, error_reason=str(e))
        raise HTTPException(400, str(e))

    if token.machine_id != machine_id:
        ActivationAttemptRepo.record(
            ip=ip, machine_id=machine_id, endpoint="activate",
            tx_hash=None, success=False, error_reason="machine_mismatch")
        raise HTTPException(400,
            "token is bound to a different machine. "
            "Email dht.io.vn@gmail.com if you need a transfer.")

    if token.is_expired:
        raise HTTPException(400, "this license has already expired")

    row = LicenseRepo.get(token.license_id)
    if not row:
        raise HTTPException(400, "unknown license id (token might be forged)")
    if row["revoked_at"]:
        raise HTTPException(400, f"license revoked: {row['revoke_reason']}")

    LicenseRepo.mark_activated(token.license_id)
    ActivationAttemptRepo.record(
        ip=ip, machine_id=machine_id, endpoint="activate",
        tx_hash=None, success=True, error_reason="")

    return {
        "ok": True,
        "license_id": token.license_id,
        "tier": token.tier,
        "is_lifetime": token.is_lifetime,
        "expires_at": row["expires_at"],
        "days_remaining": token.days_remaining(),
        "machine_id": token.machine_id,
    }


@app.post("/heartbeat")
def heartbeat(payload: HeartbeatIn, request: Request):
    """Customer's bot pings here periodically (e.g. once per scan loop or
    daily). We update last_seen + report revocation/expiry so the bot can
    stop gracefully."""
    ip = _client_ip(request)
    try:
        token = verify_license(payload.token)
    except LicenseTokenError as e:
        ActivationAttemptRepo.record(
            ip=ip, machine_id=None, endpoint="heartbeat",
            tx_hash=None, success=False, error_reason=str(e))
        raise HTTPException(400, str(e))

    row = LicenseRepo.get(token.license_id)
    if not row:
        raise HTTPException(404, "license not found on server")

    if row["revoked_at"]:
        ActivationAttemptRepo.record(
            ip=ip, machine_id=token.machine_id, endpoint="heartbeat",
            tx_hash=None, success=False,
            error_reason=f"revoked:{row['revoke_reason']}")
        return {
            "ok": False, "is_active": False, "revoked": True,
            "reason": row["revoke_reason"] or "revoked",
        }

    if token.is_expired:
        return {
            "ok": False, "is_active": False, "expired": True,
            "expires_at": row["expires_at"],
        }

    LicenseRepo.mark_heartbeat(token.license_id)
    return {
        "ok": True, "is_active": True,
        "tier": token.tier, "is_lifetime": token.is_lifetime,
        "expires_at": row["expires_at"],
        "days_remaining": token.days_remaining(),
    }


# ---------------------------------------------------------------------------
# Admin (seller-only)
# ---------------------------------------------------------------------------
@app.get("/admin/list")
def admin_list(_=Depends(_require_admin), limit: int = 200):
    return LicenseRepo.list_all(limit=limit)


@app.post("/admin/revoke/{license_id}")
def admin_revoke(license_id: int, reason: str = "manual",
                _=Depends(_require_admin)):
    row = LicenseRepo.get(license_id)
    if not row:
        raise HTTPException(404, "license not found")
    LicenseRepo.revoke(license_id, reason)
    return {"ok": True, "license_id": license_id, "revoked_reason": reason}


@app.post("/admin/peek-token")
def admin_peek_token(payload: HeartbeatIn, _=Depends(_require_admin)):
    """Inspect a token's payload without verifying signature — debug aid."""
    return peek_token(payload.token)
