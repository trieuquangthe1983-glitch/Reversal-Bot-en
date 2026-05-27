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
from fastapi.responses import FileResponse, JSONResponse
from pathlib import Path
from pydantic import BaseModel

from blockchain import (PAYMENT_WALLET_ADDRESS, MIN_CONFIRMATIONS,
                       USDT_BEP20_CONTRACT, PaymentVerifyError,
                       verify_bsc_payment)
from tron import (PAYMENT_WALLET_TRON, USDT_TRC20_BASE58,
                 MIN_CONFIRMATIONS as TRON_MIN_CONFIRMATIONS,
                 TronPaymentVerifyError, verify_tron_payment)
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
    network: str = "bsc"      # "bsc" or "tron"
    customer_email: Optional[str] = None


class ActivateIn(BaseModel):
    token: str
    machine_id: str


class HeartbeatIn(BaseModel):
    token: str


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------
_LANDING_PATH = Path(__file__).parent / "landing.html"
_DOWNLOADS_DIR = Path(__file__).parent / "downloads"
CURRENT_VERSION = "1.0.0"


@app.get("/download")
@app.get("/download/{version}")
def download(version: str = CURRENT_VERSION):
    """Serve the bot ZIP for customer download.

    Usage:
      /download              -> serves current version (CURRENT_VERSION above)
      /download/1.0.0        -> serves a specific version

    The Content-Disposition: attachment header forces browser to save
    (instead of trying to display the binary)."""
    # Basic safety: reject path traversal attempts
    if "/" in version or "\\" in version or ".." in version:
        raise HTTPException(400, "invalid version")
    zip_path = _DOWNLOADS_DIR / f"ReversalBot-v{version}.zip"
    if not zip_path.exists():
        raise HTTPException(404,
            f"version {version} not available. Try /download for the current "
            f"version, or email dht.io.vn@gmail.com.")
    # Lightweight log so we can see downloads in fly logs
    log_msg = f"[download] v{version} served ({zip_path.stat().st_size} bytes)"
    print(log_msg)
    return FileResponse(
        zip_path,
        media_type="application/zip",
        filename=f"ReversalBot-v{version}.zip",
    )


@app.get("/")
def root():
    """Browser visitors get the marketing landing page; bots/scripts that
    want JSON should hit /api/info instead."""
    if _LANDING_PATH.exists():
        return FileResponse(_LANDING_PATH, media_type="text/html")
    return JSONResponse({"error": "landing.html missing"}, status_code=500)


@app.get("/api/info")
def api_info():
    """Machine-readable index of public endpoints."""
    return {
        "service": "Reversal Bot License Server",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "GET  /":             "marketing landing page (HTML)",
            "GET  /health":       "liveness probe",
            "GET  /pricing":      "tier list + payment wallet",
            "GET  /public-key":   "Ed25519 public key (PEM)",
            "GET  /trial-eligible/{machine_id}": "trial availability for a machine",
            "POST /verify-payment": "verify BSC/Tron tx + mint signed token",
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
        # Back-compat: legacy bots read .payment.{network,wallet,...}
        "payment": {
            "network": "BSC (BEP20)",
            "token": "USDT",
            "wallet": PAYMENT_WALLET_ADDRESS,
            "usdt_contract": USDT_BEP20_CONTRACT,
            "min_confirmations": MIN_CONFIRMATIONS,
        },
        # New: list of supported networks. Bots ≥ v2 read .networks
        "networks": [
            {
                "id": "bsc",
                "label": "BSC (BNB Smart Chain)",
                "token": "USDT-BEP20",
                "wallet": PAYMENT_WALLET_ADDRESS,
                "token_contract": USDT_BEP20_CONTRACT,
                "min_confirmations": MIN_CONFIRMATIONS,
                "explorer": "https://bscscan.com/tx/",
                "decimals": 18,
                "native_fee_token": "BNB",
            },
            {
                "id": "tron",
                "label": "Tron (TRC20)",
                "token": "USDT-TRC20",
                "wallet": PAYMENT_WALLET_TRON,
                "token_contract": USDT_TRC20_BASE58,
                "min_confirmations": TRON_MIN_CONFIRMATIONS,
                "explorer": "https://tronscan.org/#/transaction/",
                "decimals": 6,
                "native_fee_token": "TRX",
            },
        ],
        "fee_policy": (
            "Buyer pays network fees in the native token "
            "(BNB on BSC, TRX on Tron). The USDT amount transferred must "
            "exactly match the tier price. Do NOT use exchange withdrawals "
            "that deduct fees from the transfer amount."
        ),
        "support_email": "dht.io.vn@gmail.com",
    }


@app.get("/public-key")
def public_key():
    """Returns the Ed25519 public key in PEM. The bot embeds this so it
    can verify the token offline."""
    return {"public_key_pem": public_key_pem()}


@app.get("/trial-eligible/{machine_id}")
def trial_eligible(machine_id: str):
    """Returns whether the given machine can claim the $29 trial.
    True iff this machine has NO license history of any tier."""
    mid = machine_id[:24].lower()
    eligible = LicenseRepo.is_trial_eligible(mid)
    reason = None
    if not eligible:
        existing = LicenseRepo.get_active_for_machine(mid)
        if existing:
            reason = f"this machine has an active {existing['tier']} license"
        else:
            reason = "this machine has prior license history; trial is only for new machines"
    return {
        "machine_id": mid,
        "trial_eligible": eligible,
        "reason": reason,
    }


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

    network = (payload.network or "bsc").lower()
    if network not in ("bsc", "tron"):
        raise HTTPException(400, f"unsupported network: {network}")

    # 1. On-chain verify (dispatch by network)
    try:
        if network == "tron":
            tron_proof = verify_tron_payment(payload.tx_hash.strip(),
                                             expected_tier=payload.tier)
            # Normalize to the BSC PaymentProof shape so downstream code
            # doesn't care which chain provided the proof.
            from blockchain import PaymentProof
            proof = PaymentProof(
                tx_hash=tron_proof.tx_hash,
                from_address=tron_proof.from_address,
                to_address=tron_proof.to_address,
                amount_usdt=tron_proof.amount_usdt,
                block_number=tron_proof.block_number,
                confirmations=tron_proof.confirmations,
                matched_tier=tron_proof.matched_tier,
                raw_receipt=tron_proof.raw_info,
            )
        else:
            proof = verify_bsc_payment(payload.tx_hash.strip(),
                                       expected_tier=payload.tier)
    except (PaymentVerifyError, TronPaymentVerifyError) as e:
        ActivationAttemptRepo.record(
            ip=ip, machine_id=machine_id, endpoint="verify-payment",
            tx_hash=payload.tx_hash, success=False,
            error_reason=f"verify_failed[{network}]:{e}")
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

    # 3. Trial-must-be-first rule: trial only available if this machine has
    # NO license history of any tier. Once a paid tier is activated, trial
    # is locked forever on this machine (anti-abuse, per business rule).
    if payload.tier == "trial" and not LicenseRepo.is_trial_eligible(machine_id):
        ActivationAttemptRepo.record(
            ip=ip, machine_id=machine_id, endpoint="verify-payment",
            tx_hash=payload.tx_hash, success=False,
            error_reason="trial_not_eligible")
        raise HTTPException(400,
            "Trial is no longer available on this machine — it can only be "
            "used as your FIRST license. Choose a paid tier (monthly/quarterly/"
            "annual/lifetime) or contact dht.io.vn@gmail.com.")

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
