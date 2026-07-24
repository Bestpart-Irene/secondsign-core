# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures for the plugin-contract tests."""

from datetime import datetime, timedelta, timezone

import pytest

from secondsign.contracts import (
    ActionClass,
    Currency,
    MarketSession,
    PolicyView,
    RailClass,
    Reversibility,
    RiskBand,
    SourceTrust,
)

#: A well-formed keyed fingerprint. The contract accepts nothing else in a
#: reference field, which is what makes a raw account number unrepresentable.
FINGERPRINT_A = "fp:" + "a1" * 32
FINGERPRINT_B = "fp:" + "b2" * 32


def make_view(**overrides) -> PolicyView:
    """A valid PolicyView; override single fields per test."""
    now = datetime(2026, 7, 23, 12, 0, tzinfo=timezone.utc)
    base = {
        "action_class": ActionClass.payment,
        "rail_class": RailClass.bank_transfer,
        "value_lower_minor": 125_000,
        "value_upper_minor": 125_000,
        "quote_currency": Currency.USD,
        "counterparty_ref": FINGERPRINT_A,
        "source_account_ref": FINGERPRINT_B,
        "not_before": now,
        "not_after": now + timedelta(minutes=5),
        "reversibility": Reversibility.irreversible,
        "source_trust": SourceTrust.trusted_instruction,
        "scope_count": 1,
        "recent_count_window": 2,
        "counterparty_risk_band": RiskBand.low,
        "new_counterparty": False,
        "cross_border": False,
        "market_session": MarketSession.not_applicable,
    }
    base.update(overrides)
    return PolicyView(**base)


@pytest.fixture
def view() -> PolicyView:
    return make_view()
