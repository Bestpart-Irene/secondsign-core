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

import pytest

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


class _RaisingExecutor:
    """An executor that breaks the protocol by raising instead of returning —
    the shape of a missing optional SDK, a non-HTTP answer the driver missed,
    or a third-party rail that throws."""

    def dispatch(self, intent):  # noqa: ANN001, ANN201 — a deliberately broken executor
        raise RuntimeError("the rail SDK is not installed")


class _ReturnsGarbageExecutor:
    """An executor that breaks the protocol by *returning* a non-RailResult
    rather than raising — the case a structural Protocol cannot prevent, and the
    one the raise-only guard missed: `None.status` and a bad `ExecutionOutcome`
    both blow up on the return, not on the call."""

    def __init__(self, value: object) -> None:
        self._value = value

    def dispatch(self, intent):  # noqa: ANN001, ANN201 — a deliberately broken executor
        return self._value


class _BadStatus:
    status = "definitely-succeeded"  # not an ExecutionStatus → ExecutionOutcome rejects it
    reference = 12345  # not a str


@pytest.mark.parametrize("value", [None, _BadStatus()])
def test_an_executor_that_returns_garbage_is_unknown_not_an_escape(value):
    """A `dispatch` that returns None or a non-RailResult object must not escape
    after the key is reserved and the rail ran — same INV-11 hole as a raise,
    reached on the return path instead of the call."""
    store = fresh_store()
    gateway = ExecutionGateway(_ReturnsGarbageExecutor(value), store)
    intent = make_intent()
    outcome = gateway.execute(intent, make_decision(intent, DecisionVerdict.ALLOW), now=NOW)
    assert isinstance(outcome, ExecutionOutcome)
    assert outcome.status is ExecutionStatus.unknown
    # And the key is finalized, not stuck reserved: a retry reads unknown back.
    retry = gateway.execute(intent, make_decision(intent, DecisionVerdict.ALLOW), now=NOW)
    assert retry.status is ExecutionStatus.unknown


def test_an_executor_that_raises_is_unknown_not_an_escape():
    """The money may have moved and the key is already reserved; the gateway
    must answer `unknown` rather than let the exception escape into a
    money-moving path that then writes no receipt (INV-11)."""
    gateway = ExecutionGateway(_RaisingExecutor(), fresh_store())
    intent = make_intent()
    outcome = gateway.execute(intent, make_decision(intent, DecisionVerdict.ALLOW), now=NOW)
    assert isinstance(outcome, ExecutionOutcome)
    assert outcome.status is ExecutionStatus.unknown
    # The reservation is finalized to unknown, so a retry reads that back rather
    # than re-dispatching a payment that may already have happened.
    retry = gateway.execute(intent, make_decision(intent, DecisionVerdict.ALLOW), now=NOW)
    assert retry.status is ExecutionStatus.unknown


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
