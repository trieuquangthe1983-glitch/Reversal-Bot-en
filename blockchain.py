"""BSC USDT-BEP20 payment verification.

Same logic as the bot-side blockchain.py — but here the server is the
authoritative verifier. Customer's bot no longer talks to BSC; it just
trusts our signed token.
"""
from __future__ import annotations
import json
import os
from dataclasses import dataclass
from typing import Optional

import requests

from tiers import TIERS, Tier, match_tier_by_amount


USDT_BEP20_CONTRACT = "0x55d398326f99059fF775485246999027B3197955".lower()
USDT_DECIMALS = 18
TRANSFER_EVENT_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

PAYMENT_WALLET_ADDRESS = os.getenv(
    "LICENSE_PAYMENT_WALLET",
    "0xFdE5bE00bA5db63a93abf7922ee831dB62257550",
).lower()

DEFAULT_RPCS = [
    "https://bsc-dataseed.binance.org/",
    "https://bsc-dataseed1.defibit.io/",
    "https://bsc-dataseed1.ninicoin.io/",
]

MIN_CONFIRMATIONS = int(os.getenv("LICENSE_MIN_CONFIRMATIONS", "12"))


class PaymentVerifyError(RuntimeError):
    pass


@dataclass
class PaymentProof:
    tx_hash: str
    from_address: str
    to_address: str
    amount_usdt: float
    block_number: int
    confirmations: int
    matched_tier: Optional[str]
    raw_receipt: dict


def _rpc_call(method: str, params: list, rpcs: list[str] | None = None,
              timeout: float = 8.0) -> dict:
    rpcs = rpcs or DEFAULT_RPCS
    last_err: Exception | None = None
    for url in rpcs:
        try:
            r = requests.post(url, timeout=timeout, json={
                "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
            })
            if r.status_code != 200:
                last_err = RuntimeError(f"{url} returned {r.status_code}")
                continue
            j = r.json()
            if "error" in j:
                last_err = RuntimeError(f"{url} rpc error: {j['error']}")
                continue
            return j["result"]
        except (requests.RequestException, json.JSONDecodeError) as e:
            last_err = e
            continue
    raise PaymentVerifyError(f"all BSC RPCs failed: {last_err}")


def _hex_to_int(s: str) -> int:
    if not s or s == "0x":
        return 0
    return int(s, 16)


def _addr_pad(addr: str) -> str:
    return "0x" + addr.lower().replace("0x", "").rjust(64, "0")


def fetch_transaction_proof(tx_hash: str,
                            rpcs: list[str] | None = None,
                            now_block: Optional[int] = None) -> PaymentProof:
    if not tx_hash.startswith("0x") or len(tx_hash) != 66:
        raise PaymentVerifyError(f"invalid tx_hash format: {tx_hash!r}")

    receipt = _rpc_call("eth_getTransactionReceipt", [tx_hash], rpcs=rpcs)
    if receipt is None:
        raise PaymentVerifyError(
            "transaction not found on BSC (still pending? wait and retry)")
    if _hex_to_int(receipt.get("status", "0x0")) != 1:
        raise PaymentVerifyError("transaction failed on-chain (status=0)")

    block_no = _hex_to_int(receipt["blockNumber"])
    if now_block is None:
        now_block = _hex_to_int(_rpc_call("eth_blockNumber", [], rpcs=rpcs))
    confirmations = max(0, now_block - block_no)
    if confirmations < MIN_CONFIRMATIONS:
        raise PaymentVerifyError(
            f"only {confirmations} confirmations (need {MIN_CONFIRMATIONS}). "
            f"Wait ~{(MIN_CONFIRMATIONS - confirmations) * 3} seconds.")

    our_wallet_padded = _addr_pad(PAYMENT_WALLET_ADDRESS)
    transfer_log = None
    for log in receipt.get("logs", []):
        if log["address"].lower() != USDT_BEP20_CONTRACT:
            continue
        topics = log.get("topics", [])
        if not topics or topics[0].lower() != TRANSFER_EVENT_TOPIC:
            continue
        if len(topics) < 3:
            continue
        if topics[2].lower() != our_wallet_padded:
            continue
        transfer_log = log
        break

    if transfer_log is None:
        raise PaymentVerifyError(
            f"no USDT-BEP20 transfer to {PAYMENT_WALLET_ADDRESS} in this tx. "
            f"Did you send USDT (not BNB) and to the correct address?")

    raw_amount = _hex_to_int(transfer_log["data"])
    amount_usdt = raw_amount / (10 ** USDT_DECIMALS)
    from_addr = "0x" + transfer_log["topics"][1][-40:].lower()
    to_addr = "0x" + transfer_log["topics"][2][-40:].lower()

    matched = match_tier_by_amount(amount_usdt)
    matched_name = matched.name if matched else None

    return PaymentProof(
        tx_hash=tx_hash, from_address=from_addr, to_address=to_addr,
        amount_usdt=round(amount_usdt, 6), block_number=block_no,
        confirmations=confirmations, matched_tier=matched_name,
        raw_receipt=receipt,
    )


def verify_bsc_payment(tx_hash: str, expected_tier: Optional[str] = None,
                      rpcs: list[str] | None = None) -> PaymentProof:
    proof = fetch_transaction_proof(tx_hash, rpcs=rpcs)
    if proof.matched_tier is None:
        nearest = min(TIERS.values(),
                      key=lambda t: abs(t.price_usdt - proof.amount_usdt))
        raise PaymentVerifyError(
            f"amount {proof.amount_usdt} USDT does not match any tier. "
            f"Closest is {nearest.name} at {nearest.price_usdt} USDT. "
            f"Contact dht.io.vn@gmail.com.")
    if expected_tier and proof.matched_tier != expected_tier:
        raise PaymentVerifyError(
            f"you requested {expected_tier} ({TIERS[expected_tier].price_usdt} USDT) "
            f"but the transaction sent {proof.amount_usdt} USDT which matches "
            f"the {proof.matched_tier} tier.")
    return proof
