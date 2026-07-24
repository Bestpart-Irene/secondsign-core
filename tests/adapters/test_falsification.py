# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The falsification result — adding a brokerage rail changed no decision code.

CORE-S015 exists to try to break the intent abstraction with a rail as unlike a
payment as possible. The test is whether a trade can be decided by the *same*
policy and engine a payment is, with nothing in `policy/` or `decision/` changed
to accommodate it. It can:

- a trade derived by the Alpaca adapter runs through the unchanged
  `AmountWindowPolicy` and `DecisionEngine` and gets a normal verdict;
- a payment and a trade with the same value band and key get the *same* verdict,
  because the engine judges dimensions, never the rail.

Combined with the scope gate — this slice may not touch `decision/**` or
`policy/**` — this is the evidence the abstraction held. Had it needed a
decision-layer change, that change would be outside scope and CI would reject
it, which is the "failed falsification" outcome the slice is a checkpoint for.
"""

from secondsign.adapters import AlpacaAdapter, StripeAdapter
from secondsign.contracts import Currency, ReasonCode
from secondsign.decision import DecisionEngine, DecisionVerdict
from secondsign.policy import (
    AggregateKey,
    AmountLimit,
    AmountWindowPolicy,
    PolicyContext,
    WindowAggregate,
)
from tests.adapters.conftest import make_alpaca_call, make_stripe_call

_WINDOW = 3_600


def _limit() -> AmountLimit:
    return AmountLimit(
        quote_currency=Currency.USD, window_seconds=_WINDOW, max_aggregate_minor=1_000_000
    )


def _context(intent) -> PolicyContext:
    return PolicyContext(
        window_aggregate=WindowAggregate(
            key=AggregateKey.from_intent(intent), window_seconds=_WINDOW, aggregate_minor=0, count=0
        )
    )


def _decide(intent):
    return DecisionEngine([AmountWindowPolicy(_limit())]).decide(intent, _context(intent))


def test_a_trade_is_judged_by_the_unchanged_amount_policy():
    intent = AlpacaAdapter().derive(
        make_alpaca_call(estimated_value_lower_minor=100, estimated_value_upper_minor=200)
    )
    assert _decide(intent).verdict is DecisionVerdict.ALLOW  # under cap, no trade-specific code


def test_a_trade_over_the_cap_denies_by_the_same_policy():
    intent = AlpacaAdapter().derive(
        make_alpaca_call(
            estimated_value_lower_minor=2_000_000, estimated_value_upper_minor=2_000_000
        )
    )
    decision = _decide(intent)
    assert decision.verdict is DecisionVerdict.DENY
    assert ReasonCode.value_band_exceeded in decision.reasons


def test_a_payment_and_a_trade_of_equal_value_get_the_same_verdict():
    """The engine judges dimensions, not the rail: same band + key, same answer."""
    trade = AlpacaAdapter().derive(
        make_alpaca_call(estimated_value_lower_minor=5_000, estimated_value_upper_minor=5_000)
    )
    payment = StripeAdapter().derive(make_stripe_call(amount_minor=5_000))
    assert _decide(trade).verdict == _decide(payment).verdict == DecisionVerdict.ALLOW
