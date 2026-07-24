# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Properties of the amount policy.

Stated as properties because they must hold for the whole input space: the
policy is monotone in spend (more never loosens), it is deterministic, and a
missing context always denies whatever the amount.
"""

from hypothesis import given
from hypothesis import strategies as st

from secondsign.contracts import PluginVerdict
from secondsign.policy import AmountWindowPolicy, PolicyContext
from tests.policy.conftest import make_context, make_intent, make_limit

_STRICTNESS = {PluginVerdict.ABSTAIN: 0, PluginVerdict.REVIEW: 1, PluginVerdict.DENY: 2}
_CAP = 1_000_000


def _policy() -> AmountWindowPolicy:
    return AmountWindowPolicy(make_limit(cap=_CAP))


@given(
    amount=st.integers(min_value=0, max_value=5_000_000),
    recent=st.integers(min_value=0, max_value=5_000_000),
)
def test_more_spend_never_loosens_the_verdict(amount, recent):
    policy = _policy()
    intent = make_intent(lower=amount)
    base = policy.evaluate(intent, make_context(intent=intent, recent_minor=recent))
    heavier = make_intent(lower=amount + 1)
    stricter = policy.evaluate(heavier, make_context(intent=heavier, recent_minor=recent))
    assert _STRICTNESS[stricter.verdict] >= _STRICTNESS[base.verdict]


@given(
    amount=st.integers(min_value=0, max_value=5_000_000),
    recent=st.integers(min_value=0, max_value=5_000_000),
)
def test_is_deterministic(amount, recent):
    policy = _policy()
    intent = make_intent(lower=amount)
    first = policy.evaluate(intent, make_context(intent=intent, recent_minor=recent))
    second = policy.evaluate(intent, make_context(intent=intent, recent_minor=recent))
    assert first == second


@given(amount=st.integers(min_value=0, max_value=10**12))
def test_missing_context_always_denies(amount):
    intent = make_intent(lower=amount)
    result = _policy().evaluate(intent, PolicyContext(window_aggregate=None))
    assert result.verdict is PluginVerdict.DENY


@given(
    amount=st.integers(min_value=0, max_value=_CAP),
    recent=st.integers(min_value=0, max_value=_CAP),
)
def test_within_the_cap_the_aggregate_always_abstains(amount, recent):
    if amount + recent > _CAP:
        return
    intent = make_intent(lower=amount)
    result = _policy().evaluate(intent, make_context(intent=intent, recent_minor=recent))
    assert result.verdict is PluginVerdict.ABSTAIN
