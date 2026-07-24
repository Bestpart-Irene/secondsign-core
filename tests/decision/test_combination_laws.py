# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The DecisionEngine's combination, tested as laws rather than examples.

Combination is the one place a decision could be weakened, so the engine's
composition is checked as an algebra: the verdict does not depend on the order
policies are registered (commutativity/associativity), a duplicate policy
changes nothing (idempotence), and adding any policy never loosens the verdict
(monotonicity). The last is the load-bearing one — installing a rule can only
tighten a decision, never open it.
"""

from hypothesis import given
from hypothesis import strategies as st

from secondsign.decision import DecisionEngine, DecisionVerdict
from tests.decision.conftest import (
    EMPTY_CONTEXT,
    AbstainPolicy,
    DenyPolicy,
    ExplodingPolicy,
    ReviewPolicy,
    make_intent,
)

_STRICTNESS = {
    DecisionVerdict.ALLOW: 0,
    DecisionVerdict.REVIEW: 1,
    DecisionVerdict.DENY: 2,
}

_POLICIES = [AbstainPolicy(), ReviewPolicy(), DenyPolicy(), ExplodingPolicy()]
_policy_lists = st.lists(st.sampled_from(_POLICIES), min_size=0, max_size=6)


def _verdict(policies):
    return DecisionEngine(policies).decide(make_intent(), EMPTY_CONTEXT).verdict


@given(policies=_policy_lists, order=st.randoms(use_true_random=False))
def test_registration_order_does_not_change_the_verdict(policies, order):
    shuffled = list(policies)
    order.shuffle(shuffled)
    assert _verdict(policies) == _verdict(shuffled)


@given(policies=_policy_lists, index=st.integers(min_value=0, max_value=5))
def test_duplicating_a_policy_changes_nothing(policies, index):
    if not policies:
        return
    duplicated = list(policies)
    duplicated.append(policies[index % len(policies)])
    assert _verdict(policies) == _verdict(duplicated)


@given(policies=_policy_lists, extra=st.sampled_from(_POLICIES))
def test_adding_a_policy_never_loosens_the_verdict(policies, extra):
    before = _verdict(policies)
    after = _verdict([*policies, extra])
    assert _STRICTNESS[after] >= _STRICTNESS[before]


@given(policies=_policy_lists)
def test_allow_iff_every_policy_abstains(policies):
    verdict = _verdict(policies)
    all_abstain = all(isinstance(p, AbstainPolicy) for p in policies)
    assert (verdict is DecisionVerdict.ALLOW) == all_abstain
