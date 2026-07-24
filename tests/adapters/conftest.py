# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures for the rail-adapter tests."""

from datetime import datetime, timedelta, timezone

from secondsign.adapters import AlpacaCall, StripeCall
from secondsign.contracts import Currency, MarketSession, SourceTrust
from secondsign.intent import OrderType, PaymentTargetKind, SettlementPriority, TradeSide

FINGERPRINT_A = "fp:" + "a1" * 32
FINGERPRINT_B = "fp:" + "b2" * 32
_EPOCH = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def make_stripe_call(**overrides) -> StripeCall:
    """A valid, mappable Stripe payment call; override single fields per test."""
    base = {
        "counterparty_ref": FINGERPRINT_A,
        "source_account_ref": FINGERPRINT_B,
        "not_before": _EPOCH,
        "not_after": _EPOCH + timedelta(minutes=5),
        "declared_source_trust": SourceTrust.trusted_instruction,
        "scope_count": 1,
        "amount_minor": 125_000,
        "quote_currency": Currency.USD,
        "target_kind": PaymentTargetKind.bank_account,
        "new_beneficiary": False,
        "cross_border": False,
        "settlement_priority": SettlementPriority.standard,
    }
    base.update(overrides)
    return StripeCall(**base)


def make_alpaca_call(**overrides) -> AlpacaCall:
    """A valid, mappable Alpaca trade call (open market, fresh quote)."""
    base = {
        "counterparty_ref": FINGERPRINT_A,
        "source_account_ref": FINGERPRINT_B,
        "not_before": _EPOCH,
        "not_after": _EPOCH + timedelta(minutes=5),
        "declared_source_trust": SourceTrust.trusted_instruction,
        "scope_count": 1,
        "symbol": "AAPL",
        "quantity": 10,
        "side": TradeSide.buy,
        "order_type": OrderType.market,
        "limit_price_minor": None,
        "quote_currency": Currency.USD,
        "estimated_value_lower_minor": 1_800_00,
        "estimated_value_upper_minor": 1_850_00,
        "market_session": MarketSession.open,
        "quote_age_seconds": 2,
    }
    base.update(overrides)
    return AlpacaCall(**base)
