"""License tier definitions — single source of truth.

Same numbers as the bot's tiers.py so both sides stay in sync. The bot
fetches GET /tiers from this server at startup so customers always see
current pricing; this file is just the server's view.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Literal

TierName = Literal["trial", "monthly", "quarterly", "annual", "lifetime"]


@dataclass(frozen=True)
class Tier:
    name: TierName
    price_usdt: float
    duration_days: int | None   # None = lifetime
    discount_pct: float
    description: str
    is_trial: bool = False


TIERS: dict[TierName, Tier] = {
    "trial":     Tier("trial",     29.0,  30,   0.0, "30-day trial. One-shot per machine.", is_trial=True),
    "monthly":   Tier("monthly",   39.0,  30,   0.0, "Pay-as-you-go monthly subscription."),
    "quarterly": Tier("quarterly", 111.0, 90,   5.0, "3 months, 5% off."),
    "annual":    Tier("annual",    397.0, 365, 15.0, "12 months, 15% off."),
    "lifetime":  Tier("lifetime",  569.0, None, 0.0, "Lifetime + all updates included."),
}


def match_tier_by_amount(amount_usdt: float, tolerance: float = 0.5) -> Tier | None:
    for t in TIERS.values():
        if abs(amount_usdt - t.price_usdt) <= tolerance:
            return t
    return None
