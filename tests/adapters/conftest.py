# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures for the rail-adapter tests."""

from datetime import datetime, timedelta, timezone

from secondsign.adapters import StripeCall
from secondsign.contracts import Currency, SourceTrust
from secondsign.intent import PaymentTargetKind, SettlementPriority

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
