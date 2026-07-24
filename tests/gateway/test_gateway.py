# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the ExecutionGateway.

The gateway is the last line before money moves, so it re-checks rather than
trusts: it accepts only the decision-carried intent (no caller re-parameters),
recomputes and compares the digest immediately before dispatch (B1), re-verifies
the validity window (B5), reserves the idempotency key *before* executing so a
concurrent duplicate cannot double-spend (B2), and reports a three-state outcome
in which unknown is not failure (B8).
"""

import inspect
from datetime import timedelta

from secondsign.decision import DecisionVerdict
from secondsign.gateway import (
    ExecutionGateway,
    ExecutionOutcome,
    ExecutionStatus,
    GatewayRefusal,
    RefusalReason,
)
from tests.gateway.conftest import (
    NOT_AFTER,
    NOW,
    FixedExecutor,
    fresh_store,
    make_decision,
    make_grant,
    make_intent,
)


def _gateway(status: ExecutionStatus = ExecutionStatus.success):
    executor = FixedExecutor(status)
    return ExecutionGateway(executor, fresh_store()), executor


def test_an_allow_decision_executes():
    gateway, executor = _gateway()
    intent = make_intent()
    outcome = gateway.execute(intent, make_decision(intent, DecisionVerdict.ALLOW), now=NOW)
    assert isinstance(outcome, ExecutionOutcome)
    assert outcome.status is ExecutionStatus.success
    assert executor.dispatched == [intent.idempotency_key]


def test_a_denied_decision_never_dispatches():
    gateway, executor = _gateway()
    intent = make_intent()
    outcome = gateway.execute(intent, make_decision(intent, DecisionVerdict.DENY), now=NOW)
    assert outcome == GatewayRefusal(reason=RefusalReason.denied)
    assert executor.dispatched == []


def test_a_review_decision_needs_a_matching_grant():
    gateway, executor = _gateway()
    intent = make_intent()
    decision = make_decision(intent, DecisionVerdict.REVIEW)
    without = gateway.execute(intent, decision, now=NOW)
    assert without == GatewayRefusal(reason=RefusalReason.not_approved)
    assert executor.dispatched == []


def test_a_review_decision_with_a_grant_executes():
    gateway, executor = _gateway()
    intent = make_intent()
    decision = make_decision(intent, DecisionVerdict.REVIEW)
    outcome = gateway.execute(intent, decision, grant=make_grant(intent), now=NOW)
    assert isinstance(outcome, ExecutionOutcome)
    assert executor.dispatched == [intent.idempotency_key]


def test_a_tampered_intent_is_refused_before_dispatch():
    """B1 — the executed value must equal the decided value."""
    gateway, executor = _gateway()
    decided = make_intent(amount=100)
    decision = make_decision(decided, DecisionVerdict.ALLOW)
    tampered = make_intent(amount=999_999)  # same key, different amount => different digest
    outcome = gateway.execute(tampered, decision, now=NOW)
    assert outcome == GatewayRefusal(reason=RefusalReason.digest_mismatch)
    assert executor.dispatched == []


def test_a_grant_for_a_different_digest_is_refused():
    gateway, executor = _gateway()
    intent = make_intent()
    decision = make_decision(intent, DecisionVerdict.REVIEW)
    other_grant = make_grant(make_intent(amount=1))
    outcome = gateway.execute(intent, decision, grant=other_grant, now=NOW)
    assert outcome == GatewayRefusal(reason=RefusalReason.not_approved)
    assert executor.dispatched == []


def test_execution_outside_the_validity_window_is_refused():
    """B5 — over the window is re-decide, not dispatch."""
    gateway, executor = _gateway()
    intent = make_intent()
    decision = make_decision(intent, DecisionVerdict.ALLOW)
    too_late = NOT_AFTER + timedelta(seconds=1)
    outcome = gateway.execute(intent, decision, now=too_late)
    assert outcome == GatewayRefusal(reason=RefusalReason.window_expired)
    assert executor.dispatched == []


def test_a_duplicate_is_not_dispatched_twice():
    """B2 — the idempotency key is reserved before execution."""
    gateway, executor = _gateway()
    intent = make_intent()
    decision = make_decision(intent, DecisionVerdict.ALLOW)
    first = gateway.execute(intent, decision, now=NOW)
    second = gateway.execute(intent, decision, now=NOW)
    assert first == second
    assert executor.dispatched == [intent.idempotency_key]  # dispatched exactly once


def test_unknown_is_reported_and_is_not_failure():
    """B8 — an ambiguous outcome must not be collapsed to failure."""
    gateway, executor = _gateway(ExecutionStatus.unknown)
    intent = make_intent()
    outcome = gateway.execute(intent, make_decision(intent, DecisionVerdict.ALLOW), now=NOW)
    assert outcome.status is ExecutionStatus.unknown
    assert outcome.status is not ExecutionStatus.failure


def test_a_failure_is_reported_as_failure():
    gateway, executor = _gateway(ExecutionStatus.failure)
    intent = make_intent()
    outcome = gateway.execute(intent, make_decision(intent, DecisionVerdict.ALLOW), now=NOW)
    assert outcome.status is ExecutionStatus.failure


def test_a_duplicate_after_unknown_returns_unknown_without_redispatch():
    """B8 — retrying an unknown with the same key does not re-execute."""
    gateway, executor = _gateway(ExecutionStatus.unknown)
    intent = make_intent()
    decision = make_decision(intent, DecisionVerdict.ALLOW)
    gateway.execute(intent, decision, now=NOW)
    again = gateway.execute(intent, decision, now=NOW)
    assert again.status is ExecutionStatus.unknown
    assert executor.dispatched == [intent.idempotency_key]


def test_a_key_reserved_but_not_finalized_returns_unknown():
    """A crash (or a concurrent caller) between reserve and finalize leaves the
    key reserved with no recorded outcome; a retry must read unknown, never
    re-dispatch. B8."""
    executor = FixedExecutor(ExecutionStatus.success)
    store = fresh_store()
    intent = make_intent()
    store.reserve(intent.idempotency_key)  # reserved, never finalized
    gateway = ExecutionGateway(executor, store)
    outcome = gateway.execute(intent, make_decision(intent, DecisionVerdict.ALLOW), now=NOW)
    assert outcome.status is ExecutionStatus.unknown
    assert executor.dispatched == []


def test_gateway_takes_no_caller_transaction_parameters():
    """The gateway accepts the decided intent and its authorisation — never a
    fresh amount, target, or account a caller could substitute."""
    params = set(inspect.signature(ExecutionGateway.execute).parameters) - {"self"}
    assert params == {"intent", "decision", "grant", "now"}
