# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Algebraic properties of the intent value objects.

Two invariants are stated as properties rather than examples because they must
hold for *every* constructible value: a band is always ordered, and a value
object round-trips through its own serialization unchanged (a prerequisite for
the deterministic digest built on it in CORE-S007).
"""

from datetime import datetime, timedelta, timezone

from hypothesis import given
from hypothesis import strategies as st

from secondsign.contracts import Currency, RailClass, Reversibility, SourceTrust
from secondsign.intent import DecisionDimensions
from tests.intent.conftest import FINGERPRINT_A, FINGERPRINT_B

_EPOCH = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
_MAX_MINOR = 10**12


def _dimensions(lower: int, span: int, window_seconds: int) -> DecisionDimensions:
    return DecisionDimensions(
        value_lower_minor=lower,
        value_upper_minor=lower + span,
        quote_currency=Currency.USD,
        counterparty_ref=FINGERPRINT_A,
        source_account_ref=FINGERPRINT_B,
        rail_class=RailClass.bank_transfer,
        not_before=_EPOCH,
        not_after=_EPOCH + timedelta(seconds=window_seconds),
        reversibility=Reversibility.irreversible,
        source_trust=SourceTrust.trusted_instruction,
        scope_count=1,
    )


@given(
    lower=st.integers(min_value=0, max_value=_MAX_MINOR),
    span=st.integers(min_value=0, max_value=_MAX_MINOR),
    window_seconds=st.integers(min_value=1, max_value=86_400),
)
def test_band_is_always_ordered(lower, span, window_seconds):
    d = _dimensions(lower, span, window_seconds)
    assert d.value_lower_minor <= d.value_upper_minor


@given(
    lower=st.integers(min_value=0, max_value=_MAX_MINOR),
    span=st.integers(min_value=0, max_value=_MAX_MINOR),
    window_seconds=st.integers(min_value=1, max_value=86_400),
)
def test_round_trips_through_serialization(lower, span, window_seconds):
    d = _dimensions(lower, span, window_seconds)
    assert DecisionDimensions.model_validate(d.model_dump()) == d
    assert d.model_dump_json() == d.model_dump_json()
