"""Tron (TRC20) USDT payment verification via TronGrid public API.

Tron is NOT EVM. Key differences vs BSC:
  - Native API is TronGrid (https://api.trongrid.io), not JSON-RPC
  - USDT-TRC20 has 6 decimals (vs BEP20's 18)
  - Addresses use base58check with prefix 0x41 (mainnet), shown as "T..."
  - Tx hashes are 32 bytes hex (no 0x prefix on the wire)
"""
from __future__ import annotations
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Optional

import requests

from tiers import TIERS, match_tier_by_amount

# Official USDT-TRC20 contract address (Tether)
USDT_TRC20_BASE58 = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
USDT_TRC20_DECIMALS = 6   # IMPORTANT: 6 on Tron, not 18 like BSC!

# keccak256("Transfer(address,address,uint256)") - same as ERC20
TRANSFER_EVENT_TOPIC = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

PAYMENT_WALLET_TRON = os.getenv(
    "LICENSE_PAYMENT_WALLET_TRON",
    "TDKvfffbFYaznVH7wkin6vuw7NH47LwQJz",
)

DEFAULT_TRON_RPCS = [
    "https://api.trongrid.io",
    "https://api.tronstack.io",
]

MIN_CONFIRMATIONS = int(os.getenv("LICENSE_TRON_MIN_CONFIRMATIONS", "20"))


class TronPaymentVerifyError(RuntimeError):
    pass


@dataclass
class TronPaymentProof:
    tx_hash: str
    from_address: str       # T... base58
    to_address: str         # T... base58
    amount_usdt: float
    block_number: int
    confirmations: int
    matched_tier: Optional[str]
    raw_info: dict


# ---------------------------------------------------------------------------
# Base58check (inline implementation; no external dependency)
# ---------------------------------------------------------------------------
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58_to_hex(addr: str) -> str:
    """Tron base58 address -> 21-byte hex (prefix 0x41 for mainnet)."""
    n = 0
    for c in addr:
        n = n * 58 + _B58_ALPHABET.index(c)
    blob = n.to_bytes(25, "big")
    payload, checksum = blob[:21], blob[21:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if checksum != expected:
        raise ValueError(f"bad Tron address checksum: {addr}")
    return payload.hex()


def hex_to_b58(hex_addr: str) -> str:
    """21-byte hex -> Tron base58. Tron event logs return 20-byte addrs
    (no prefix), so we add 0x41 if missing."""
    h = hex_addr.lower().lstrip("0x")
    if len(h) == 40:        # event-log form, missing 0x41 prefix
        h = "41" + h
    if len(h) != 42:
        raise ValueError(f"bad hex length: {hex_addr}")
    payload = bytes.fromhex(h)
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(payload + checksum, "big")
    result = ""
    while n > 0:
        n, rem = divmod(n, 58)
        result = _B58_ALPHABET[rem] + result
    # leading zero bytes -> leading '1's in base58
    leading_zeros = 0
    for b in payload + checksum:
        if b == 0:
            leading_zeros += 1
        else:
            break
    return "1" * leading_zeros + result


# Pre-compute hex form of our wallet for quick comparison
PAYMENT_WALLET_HEX = b58_to_hex(PAYMENT_WALLET_TRON).lower()
USDT_TRC20_HEX = b58_to_hex(USDT_TRC20_BASE58).lower()


# ---------------------------------------------------------------------------
# TronGrid calls
# ---------------------------------------------------------------------------
def _post(path: str, payload: dict,
          rpcs: list[str] | None = None, timeout: float = 10.0) -> dict:
    rpcs = rpcs or DEFAULT_TRON_RPCS
    last_err: Exception | None = None
    for url in rpcs:
        try:
            r = requests.post(url.rstrip("/") + path,
                              json=payload, timeout=timeout,
                              headers={"Content-Type": "application/json"})
            if r.status_code != 200:
                last_err = RuntimeError(f"{url} returned {r.status_code}")
                continue
            return r.json()
        except (requests.RequestException, json.JSONDecodeError) as e:
            last_err = e
            continue
    raise TronPaymentVerifyError(f"all TronGrid endpoints failed: {last_err}")


def _get_current_block(rpcs: list[str] | None = None) -> int:
    r = _post("/wallet/getnowblock", {}, rpcs=rpcs)
    return int(r["block_header"]["raw_data"]["number"])


def _get_tx_info(tx_hash: str, rpcs: list[str] | None = None) -> dict:
    return _post("/wallet/gettransactioninfobyid",
                 {"value": tx_hash.lower().lstrip("0x")},
                 rpcs=rpcs)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def fetch_tron_payment(tx_hash: str,
                       rpcs: list[str] | None = None,
                       now_block: Optional[int] = None) -> TronPaymentProof:
    """Fetch + parse a Tron TRC20 transaction. Raises TronPaymentVerifyError."""
    clean_hash = tx_hash.lower().lstrip("0x")
    if len(clean_hash) != 64 or not all(c in "0123456789abcdef" for c in clean_hash):
        raise TronPaymentVerifyError(
            f"invalid Tron tx hash format: {tx_hash!r} (expect 64 hex chars)")

    info = _get_tx_info(clean_hash, rpcs=rpcs)
    if not info or "id" not in info:
        raise TronPaymentVerifyError(
            "transaction not found on Tron (still pending? wait ~30s and retry)")

    # Check contract execution result
    receipt = info.get("receipt", {}) or {}
    result = receipt.get("result", "")
    if result and result != "SUCCESS":
        raise TronPaymentVerifyError(f"on-chain execution failed: {result}")

    # Confirmations
    block_no = int(info.get("blockNumber", 0))
    if now_block is None:
        now_block = _get_current_block(rpcs=rpcs)
    confirmations = max(0, now_block - block_no)
    if confirmations < MIN_CONFIRMATIONS:
        raise TronPaymentVerifyError(
            f"only {confirmations} confirmations (need {MIN_CONFIRMATIONS}). "
            f"Wait ~{(MIN_CONFIRMATIONS - confirmations) * 3} seconds.")

    # Find USDT-TRC20 Transfer log to our wallet
    transfer_log = None
    for log in info.get("log", []) or []:
        log_addr_hex = (log.get("address") or "").lower()
        # TronGrid sometimes returns the contract address as 20-byte (no 0x41)
        if len(log_addr_hex) == 40:
            log_addr_hex = "41" + log_addr_hex
        if log_addr_hex != USDT_TRC20_HEX:
            continue
        topics = log.get("topics", []) or []
        if not topics or topics[0].lower() != TRANSFER_EVENT_TOPIC:
            continue
        if len(topics) < 3:
            continue
        # topics[2] = padded "to" address (32 bytes, but Tron stores 20 raw)
        to_raw = topics[2][-40:].lower()
        if "41" + to_raw != PAYMENT_WALLET_HEX:
            continue
        transfer_log = log
        break

    if transfer_log is None:
        raise TronPaymentVerifyError(
            f"no USDT-TRC20 transfer to {PAYMENT_WALLET_TRON} in this tx. "
            f"Did you send USDT on Tron (not TRX, not USDC) "
            f"and to the correct address?")

    raw_amount = int(transfer_log["data"], 16)
    amount_usdt = raw_amount / (10 ** USDT_TRC20_DECIMALS)
    from_raw = transfer_log["topics"][1][-40:].lower()
    from_b58 = hex_to_b58("41" + from_raw)
    to_b58 = hex_to_b58("41" + transfer_log["topics"][2][-40:].lower())

    matched = match_tier_by_amount(amount_usdt)
    return TronPaymentProof(
        tx_hash=clean_hash,
        from_address=from_b58,
        to_address=to_b58,
        amount_usdt=round(amount_usdt, 6),
        block_number=block_no,
        confirmations=confirmations,
        matched_tier=matched.name if matched else None,
        raw_info={"block": block_no, "log_count": len(info.get("log", []) or [])},
    )


def verify_tron_payment(tx_hash: str, expected_tier: Optional[str] = None,
                        rpcs: list[str] | None = None) -> TronPaymentProof:
    proof = fetch_tron_payment(tx_hash, rpcs=rpcs)
    if proof.matched_tier is None:
        nearest = min(TIERS.values(),
                      key=lambda t: abs(t.price_usdt - proof.amount_usdt))
        raise TronPaymentVerifyError(
            f"amount {proof.amount_usdt} USDT does not match any tier. "
            f"Closest is {nearest.name} at {nearest.price_usdt} USDT. "
            f"Did fees get deducted from your transfer? Buyer must cover fees. "
            f"Contact dht.io.vn@gmail.com.")
    if expected_tier and proof.matched_tier != expected_tier:
        raise TronPaymentVerifyError(
            f"you requested {expected_tier} ({TIERS[expected_tier].price_usdt} USDT) "
            f"but the transaction sent {proof.amount_usdt} USDT which matches "
            f"the {proof.matched_tier} tier.")
    return proof
