# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the DecisionEngine.

The engine turns a set of policy concerns into one verdict — ALLOW, REVIEW or
DENY — and it does so fail-closed: no concern means ALLOW, any DENY means DENY,
and a policy that raises resolves to DENY rather than being skipped. Every
non-ALLOW carries stable reason codes, and every decision carries the intent's
digest so the later steps bind to it (B1).
"""

from secondsign.contracts import ReasonCode
from secondsign.decision import DecisionEngine, DecisionVerdict
from secondsign.intent import compute_digest
from tests.decision.conftest import (
    EMPTY_CONTEXT,
    AbstainPolicy,
    DenyPolicy,
    ExplodingPolicy,
    ReviewPolicy,
    make_intent,
)


def _decide(policies):
    return DecisionEngine(policies).decide(make_intent(), EMPTY_CONTEXT)


def test_no_concern_allows():
    decision = _decide([AbstainPolicy(), AbstainPolicy()])
    assert decision.verdict is DecisionVerdict.ALLOW
    assert decision.reasons == ()


def test_an_empty_engine_allows():
    decision = _decide([])
    assert decision.verdict is DecisionVerdict.ALLOW


def test_a_review_concern_reviews():
    decision = _decide([AbstainPolicy(), ReviewPolicy()])
    assert decision.verdict is DecisionVerdict.REVIEW
    assert ReasonCode.new_counterparty in decision.reasons


def test_any_deny_denies():
    decision = _decide([ReviewPolicy(), DenyPolicy()])
    assert decision.verdict is DecisionVerdict.DENY
    assert ReasonCode.org_policy in decision.reasons


def test_a_failing_policy_resolves_to_deny():
    """A9 — evaluation failure is uncertainty, and uncertainty denies."""
    decision = _decide([AbstainPolicy(), ExplodingPolicy()])
    assert decision.verdict is DecisionVerdict.DENY
    assert ReasonCode.plugin_error in decision.reasons


def test_a_failing_policy_denies_even_beside_an_allow():
    decision = _decide([ExplodingPolicy()])
    assert decision.verdict is DecisionVerdict.DENY


def test_every_non_allow_carries_a_reason():
    for policies in ([ReviewPolicy()], [DenyPolicy()], [ExplodingPolicy()]):
        decision = _decide(policies)
        assert decision.verdict is not DecisionVerdict.ALLOW
        assert decision.reasons, "a non-ALLOW decision carried no reason code"


def test_decision_carries_the_intent_digest():
    intent = make_intent()
    decision = DecisionEngine([AbstainPolicy()]).decide(intent, EMPTY_CONTEXT)
    assert decision.digest == compute_digest(intent)


def test_decision_is_frozen():
    import pytest
    from pydantic import ValidationError

    decision = _decide([AbstainPolicy()])
    with pytest.raises(ValidationError):
        decision.verdict = DecisionVerdict.DENY


def test_reason_codes_are_deduplicated_in_order():
    decision = _decide(
        [DenyPolicy(ReasonCode.velocity_limit), DenyPolicy(ReasonCode.velocity_limit)]
    )
    assert decision.reasons == (ReasonCode.velocity_limit,)
