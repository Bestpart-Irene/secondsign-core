# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures for the intent-layer tests."""

from datetime import datetime, timedelta, timezone

import pytest

from secondsign.contracts import Currency, RailClass, Reversibility, SourceTrust
from secondsign.intent import (
    DecisionDimensions,
    PaymentPayload,
    PaymentTargetKind,
    SettlementPriority,
)

#: A well-formed keyed fingerprint. A reference field accepts nothing else, so a
#: raw account number is unrepresentable rather than merely discouraged.
FINGERPRINT_A = "fp:" + "a1" * 32
FINGERPRINT_B = "fp:" + "b2" * 32


def make_dimensions(**overrides) -> DecisionDimensions:
    """A valid DecisionDimensions; override single fields per test."""
    now = datetime(2026, 7, 23, 12, 0, tzinfo=timezone.utc)
    base = {
        "value_lower_minor": 125_000,
        "value_upper_minor": 125_000,
        "quote_currency": Currency.USD,
        "counterparty_ref": FINGERPRINT_A,
        "source_account_ref": FINGERPRINT_B,
        "rail_class": RailClass.bank_transfer,
        "not_before": now,
        "not_after": now + timedelta(minutes=5),
        "reversibility": Reversibility.irreversible,
        "source_trust": SourceTrust.trusted_instruction,
        "scope_count": 1,
    }
    base.update(overrides)
    return DecisionDimensions(**base)


def make_payment(**overrides) -> PaymentPayload:
    """A valid PaymentPayload; override single fields per test."""
    base = {
        "target_kind": PaymentTargetKind.bank_account,
        "new_beneficiary": False,
        "cross_border": False,
        "settlement_priority": SettlementPriority.standard,
    }
    base.update(overrides)
    return PaymentPayload(**base)


@pytest.fixture
def dimensions() -> DecisionDimensions:
    return make_dimensions()


@pytest.fixture
def payment() -> PaymentPayload:
    return make_payment()
