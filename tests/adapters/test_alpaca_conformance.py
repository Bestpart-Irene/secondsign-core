# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The Alpaca adapter certified against the same rail-adapter conformance suite.

The point of the falsification: a brokerage rail proves its safety by inheriting
the *same* `RailAdapterConformance` a payment rail did — no trade-specific
conformance, no weakened checks. If the abstraction were wrong, this suite could
not be satisfied by both.
"""

from secondsign.adapters import AlpacaAdapter
from secondsign.conformance import RailAdapterConformance
from secondsign.contracts import Currency
from secondsign.intent import OrderType, TradeSide
from tests.adapters.conftest import make_alpaca_call


class TestAlpacaAdapterConformance(RailAdapterConformance):
    adapter = AlpacaAdapter()
    valid_calls = (
        make_alpaca_call(),
        make_alpaca_call(side=TradeSide.sell),
        make_alpaca_call(order_type=OrderType.limit, limit_price_minor=190_00),
        make_alpaca_call(quantity=1),
        make_alpaca_call(quantity=100_000),
        make_alpaca_call(quote_currency=Currency.EUR),
        make_alpaca_call(quote_age_seconds=0),
        make_alpaca_call(estimated_value_lower_minor=500, estimated_value_upper_minor=500),
    )
