# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the Alpaca mapping and its brokerage-specific rejects.

A trade maps to the same rail-agnostic dimensions as a payment, carrying its
symbol and side only in the payload. The two validities a payment never has —
an open market and a fresh quote — are enforced here, at the boundary, so the
decision layer only ever sees a tradeable trade.
"""

import pytest
from pydantic import ValidationError

from secondsign.adapters import AlpacaAdapter, AlpacaCall, RejectReason
from secondsign.adapters.contract import RejectCode
from secondsign.contracts import MarketSession, RailClass, Reversibility
from secondsign.intent import OrderType, TradePayload, TransactionIntent, compute_digest
from tests.adapters.conftest import make_alpaca_call

ADAPTER = AlpacaAdapter()


def test_a_trade_call_maps_to_an_intent_on_the_brokerage_rail():
    result = ADAPTER.derive(make_alpaca_call())
    assert isinstance(result, TransactionIntent)
    assert result.dimensions.rail_class is RailClass.brokerage
    assert isinstance(result.payload, TradePayload)
    assert result.payload.symbol == "AAPL"


def test_the_value_is_a_band_from_the_quote():
    intent = ADAPTER.derive(
        make_alpaca_call(estimated_value_lower_minor=100, estimated_value_upper_minor=200)
    )
    assert intent.dimensions.value_lower_minor == 100
    assert intent.dimensions.value_upper_minor == 200


def test_a_trade_is_irreversible_by_default():
    intent = ADAPTER.derive(make_alpaca_call())
    assert intent.dimensions.reversibility is Reversibility.irreversible


def test_a_closed_market_is_rejected():
    result = ADAPTER.derive(make_alpaca_call(market_session=MarketSession.closed))
    assert result == RejectReason(code=RejectCode.market_closed)


def test_a_halted_market_is_rejected():
    result = ADAPTER.derive(make_alpaca_call(market_session=MarketSession.halted))
    assert result == RejectReason(code=RejectCode.market_closed)


def test_an_extended_hours_session_is_rejected():
    result = ADAPTER.derive(make_alpaca_call(market_session=MarketSession.pre_market))
    assert result == RejectReason(code=RejectCode.market_closed)


def test_a_stale_quote_is_rejected():
    result = ADAPTER.derive(make_alpaca_call(quote_age_seconds=120))
    assert result == RejectReason(code=RejectCode.stale_quote)


def test_a_limit_order_without_a_price_is_malformed():
    result = ADAPTER.derive(make_alpaca_call(order_type=OrderType.limit, limit_price_minor=None))
    assert result == RejectReason(code=RejectCode.malformed_call)


def test_a_market_order_with_a_price_is_malformed():
    result = ADAPTER.derive(make_alpaca_call(order_type=OrderType.market, limit_price_minor=190_00))
    assert result == RejectReason(code=RejectCode.malformed_call)


def test_a_well_formed_limit_order_maps():
    intent = ADAPTER.derive(make_alpaca_call(order_type=OrderType.limit, limit_price_minor=190_00))
    assert isinstance(intent, TransactionIntent)
    assert intent.payload.order_type is OrderType.limit
    assert intent.payload.limit_price_minor == 190_00


def test_the_idempotency_key_is_derived_from_content():
    a = ADAPTER.derive(make_alpaca_call(quantity=10))
    b = ADAPTER.derive(make_alpaca_call(quantity=10))
    c = ADAPTER.derive(make_alpaca_call(quantity=11))
    assert a.idempotency_key == b.idempotency_key
    assert a.idempotency_key != c.idempotency_key
    assert a.idempotency_key.startswith("alpaca-")


def test_the_call_has_no_idempotency_key_field():
    assert "idempotency_key" not in AlpacaCall.model_fields


def test_a_raw_account_number_cannot_be_placed_in_a_reference():
    with pytest.raises(ValidationError):
        make_alpaca_call(counterparty_ref="not-a-fingerprint")


def test_an_inverted_value_band_is_rejected_at_call_construction():
    with pytest.raises(ValidationError):
        make_alpaca_call(estimated_value_lower_minor=500, estimated_value_upper_minor=100)


def test_equal_calls_produce_an_identical_digest():
    a = ADAPTER.derive(make_alpaca_call())
    b = ADAPTER.derive(make_alpaca_call())
    assert compute_digest(a) == compute_digest(b)
