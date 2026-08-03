# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the amount / sliding-window aggregate policy.

The load-bearing behaviours: a limit is judged on a rolling-window aggregate
(counterparty × source account × rail), a single transaction is the aggregate's
special case, and a missing or non-matching context takes the strictest path
rather than a laxer default (A4). The judgement is on the *upper* end of the
value band, so an unsettled market order is judged by what it could cost.
"""

from secondsign.contracts import Currency, PluginVerdict, ReasonCode
from secondsign.policy import AmountWindowPolicy, PolicyContext
from tests.policy.conftest import make_context, make_intent, make_limit


def _policy(cap: int = 1_000_000) -> AmountWindowPolicy:
    return AmountWindowPolicy(make_limit(cap=cap))


def test_a_single_transaction_within_the_cap_abstains():
    intent = make_intent(lower=500_000)
    result = _policy(cap=1_000_000).evaluate(intent, make_context(intent=intent))
    assert result.verdict is PluginVerdict.ABSTAIN


def test_a_single_transaction_over_the_cap_denies():
    intent = make_intent(lower=1_500_000)
    result = _policy(cap=1_000_000).evaluate(intent, make_context(intent=intent))
    assert result.verdict is PluginVerdict.DENY
    assert ReasonCode.value_band_exceeded in result.reasons


def test_the_aggregate_not_the_single_amount_is_judged():
    """Under the cap alone, but over it once the window's prior spend is added."""
    intent = make_intent(lower=600_000)
    context = make_context(intent=intent, recent_minor=600_000, count=1)
    result = _policy(cap=1_000_000).evaluate(intent, context)
    assert result.verdict is PluginVerdict.DENY
    assert ReasonCode.value_band_exceeded in result.reasons


def test_judgement_is_on_the_upper_band():
    intent = make_intent(lower=100_000, upper=2_000_000)
    result = _policy(cap=1_000_000).evaluate(intent, make_context(intent=intent))
    assert result.verdict is PluginVerdict.DENY


def test_missing_context_takes_the_strictest_path():
    """A4 — absent aggregate denies; it does not fall back to a laxer default."""
    intent = make_intent(lower=1)
    result = _policy(cap=1_000_000).evaluate(intent, PolicyContext(window_aggregate=None))
    assert result.verdict is PluginVerdict.DENY
    assert ReasonCode.velocity_limit in result.reasons


def test_context_for_a_different_key_is_treated_as_missing():
    """A context computed for another counterparty must not be reused."""
    intent = make_intent(counterparty="fp:" + "a1" * 32)
    other = make_intent(counterparty="fp:" + "cc" * 32)
    context = make_context(intent=other, recent_minor=0)  # aggregate keyed to `other`
    result = _policy(cap=1_000_000).evaluate(intent, context)
    assert result.verdict is PluginVerdict.DENY
    assert ReasonCode.velocity_limit in result.reasons


def test_context_for_a_different_window_is_treated_as_missing():
    intent = make_intent(lower=1)
    context = make_context(intent=intent, window=60)  # limit uses 3600
    result = _policy(cap=1_000_000).evaluate(intent, context)
    assert result.verdict is PluginVerdict.DENY


def test_a_different_currency_is_not_this_limits_concern():
    """A USD limit abstains on a EUR intent; coverage is the engine's job."""
    intent = make_intent(currency=Currency.EUR, lower=9_999_999)
    result = _policy(cap=1_000_000).evaluate(intent, make_context(intent=intent))
    assert result.verdict is PluginVerdict.ABSTAIN


def test_over_limit_finding_carries_the_prospective_total_and_cap():
    intent = make_intent(lower=700_000)
    context = make_context(intent=intent, recent_minor=800_000)
    result = _policy(cap=1_000_000).evaluate(intent, context)
    finding = next(f for f in result.findings if f.code is ReasonCode.value_band_exceeded)
    assert finding.observed == 1_500_000
    assert finding.limit == 1_000_000


def test_exactly_at_the_cap_abstains():
    """The cap is inclusive: spending exactly the limit is allowed."""
    intent = make_intent(lower=400_000)
    context = make_context(intent=intent, recent_minor=600_000)
    result = _policy(cap=1_000_000).evaluate(intent, context)
    assert result.verdict is PluginVerdict.ABSTAIN


class TestAnAbsurdAmountDoesNotMislabelTheDenial:
    """A prospective sum over MAX_DETAIL_MAGNITUDE must still deny with
    value_band_exceeded, not crash into a plugin_error: an agent naming an
    absurd amount cannot turn a limit breach into 'an extension failed', nor
    collapse a REVIEW into a DENY. The finding's quantity is clamped to the
    ceiling; the verdict is unchanged."""

    def test_an_over_magnitude_amount_denies_with_value_band_exceeded(self) -> None:
        from secondsign.contracts import MAX_DETAIL_MAGNITUDE

        policy = AmountWindowPolicy(make_limit(cap=1_000_00))
        intent = make_intent(lower=2 * MAX_DETAIL_MAGNITUDE)
        result = policy.evaluate(intent, make_context(intent=intent))
        assert result.verdict is PluginVerdict.DENY
        assert ReasonCode.value_band_exceeded in {f.code for f in result.findings}
        assert result.findings[0].observed == MAX_DETAIL_MAGNITUDE  # clamped, not raw

    def test_an_over_magnitude_amount_in_the_review_band_still_reviews(self) -> None:
        from secondsign.contracts import MAX_DETAIL_MAGNITUDE
        from secondsign.policy import AmountLimit

        # Cap far above the amount so the review band, not the cap, is crossed;
        # the amount is over the finding-magnitude ceiling either way.
        limit = AmountLimit(
            quote_currency=Currency.USD,
            window_seconds=3600,
            max_aggregate_minor=3 * MAX_DETAIL_MAGNITUDE,
            review_above_minor=MAX_DETAIL_MAGNITUDE // 2,
        )
        policy = AmountWindowPolicy(limit)
        intent = make_intent(lower=2 * MAX_DETAIL_MAGNITUDE)
        result = policy.evaluate(intent, make_context(intent=intent))
        assert result.verdict is PluginVerdict.REVIEW, (
            "an over-magnitude amount in the review band collapsed into a DENY"
        )
        assert result.findings[0].observed == MAX_DETAIL_MAGNITUDE
