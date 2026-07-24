# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the Stripe mapping — the mapping and its fail-closed rejects.

These cover what the generic conformance suite cannot: the specific shape of the
Stripe mapping (a settled amount becomes a degenerate value band, reversibility
defaults to irreversible) and the reject paths a valid-call corpus never
exercises.
"""

import pytest
from pydantic import ValidationError

from secondsign.adapters import RejectReason, StripeAdapter, StripeCall
from secondsign.adapters.contract import RejectCode
from secondsign.contracts import Currency, RailClass, Reversibility
from secondsign.intent import TransactionIntent, compute_digest
from tests.adapters.conftest import make_stripe_call

ADAPTER = StripeAdapter()


def test_a_call_maps_to_a_transaction_intent():
    result = ADAPTER.derive(make_stripe_call(amount_minor=125_000))
    assert isinstance(result, TransactionIntent)
    assert result.dimensions.rail_class is RailClass.card


def test_settled_amount_becomes_a_degenerate_band():
    intent = ADAPTER.derive(make_stripe_call(amount_minor=4_200))
    assert intent.dimensions.value_lower_minor == 4_200
    assert intent.dimensions.value_upper_minor == 4_200


def test_reversibility_defaults_to_the_strictest():
    intent = ADAPTER.derive(make_stripe_call())
    assert intent.dimensions.reversibility is Reversibility.irreversible


def test_zero_amount_is_rejected_not_mapped():
    result = ADAPTER.derive(make_stripe_call(amount_minor=0))
    assert result == RejectReason(code=RejectCode.malformed_call)


def test_unsupported_currency_is_rejected():
    result = ADAPTER.derive(make_stripe_call(quote_currency=Currency.JPY))
    assert result == RejectReason(code=RejectCode.unsupported_currency)


def test_idempotency_key_is_derived_from_content():
    a = ADAPTER.derive(make_stripe_call(amount_minor=100))
    b = ADAPTER.derive(make_stripe_call(amount_minor=100))
    c = ADAPTER.derive(make_stripe_call(amount_minor=101))
    assert a.idempotency_key == b.idempotency_key
    assert a.idempotency_key != c.idempotency_key
    assert a.idempotency_key.startswith("stripe-")


def test_the_call_has_no_idempotency_key_field():
    """Structurally, a caller cannot supply the key (B2)."""
    assert "idempotency_key" not in StripeCall.model_fields


def test_equal_calls_produce_an_identical_digest():
    """End-to-end determinism: the derived intent reduces to one stable digest."""
    a = ADAPTER.derive(make_stripe_call())
    b = ADAPTER.derive(make_stripe_call())
    assert compute_digest(a) == compute_digest(b)


def test_a_raw_account_number_cannot_be_placed_in_a_reference():
    """A5 — a reference field accepts only a keyed fingerprint."""
    with pytest.raises(ValidationError):
        make_stripe_call(counterparty_ref="4111111111111111")


def test_a_malformed_window_is_rejected_at_call_construction():
    with pytest.raises(ValidationError):
        make_stripe_call(not_after=make_stripe_call().not_before)
