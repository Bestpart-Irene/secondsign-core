# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""End-to-end: a Stripe payment held, approved, and released — with a fake rail.

This exercises the whole path in one test, the way a real action flows through
it, but with the Stripe SDK faked so it runs in CI without a credential:

    tool call → adapter → policy → decision(REVIEW=held) → maker-checker(approved)
              → gateway(released via Stripe) → hash-chained receipt

The live version against real test-mode Stripe is `test_stripe_live.py`, run
only when a key is present.
"""

import stripe

from secondsign.approval import Grant
from secondsign.audit import AuditLog, InMemoryAuditSink, verify_chain
from secondsign.contracts import Currency
from secondsign.decision import Decision, DecisionEngine, DecisionVerdict
from secondsign.gateway import (
    ExecutionGateway,
    ExecutionOutcome,
    ExecutionStatus,
    InMemoryIdempotencyStore,
)
from secondsign.intent import compute_digest, compute_proposal_digest
from secondsign.policy import (
    AggregateKey,
    AmountLimit,
    AmountWindowPolicy,
    PolicyContext,
    WindowAggregate,
)
from secondsign.rails import StripePaymentExecutor
from tests.e2e.conftest import (
    MAKER,
    NOT_AFTER,
    NOW,
    FakeStripe,
    LargePaymentReviewPolicy,
    approve,
    derive_intent,
    make_stripe_call,
    new_maker_checker,
)

_WINDOW = 3_600


def _under_cap_context(intent) -> PolicyContext:
    return PolicyContext(
        window_aggregate=WindowAggregate(
            key=AggregateKey.from_intent(intent),
            window_seconds=_WINDOW,
            aggregate_minor=0,
            count=0,
        )
    )


def _review_engine() -> DecisionEngine:
    limit = AmountLimit(
        quote_currency=Currency.USD, window_seconds=_WINDOW, max_aggregate_minor=1_000_000
    )
    # Amount policy abstains (under cap); the review policy holds it for a human.
    return DecisionEngine([AmountWindowPolicy(limit), LargePaymentReviewPolicy(threshold_minor=1)])


def _executor(fake: FakeStripe) -> StripePaymentExecutor:
    return StripePaymentExecutor(api_key="rk_test_unused_by_fake", client=fake)


def _allow_decision(intent) -> Decision:
    return Decision(verdict=DecisionVerdict.ALLOW, digest=compute_digest(intent))


def test_a_payment_is_held_approved_and_released_with_a_linked_receipt():
    intent = derive_intent(make_stripe_call(amount_minor=5_000))

    # HELD: policy sends it to review.
    decision = _review_engine().decide(intent, _under_cap_context(intent))
    assert decision.verdict is DecisionVerdict.REVIEW

    # APPROVED: a distinct human checker consumes a one-shot, proposal-bound
    # approval — bound to every material field except the validity window, so a
    # human answering after the window closed still holds a usable answer.
    mc = new_maker_checker()
    pending = mc.request(
        decision,
        MAKER,
        approval_id="appr-e2e-1",
        proposal=compute_proposal_digest(intent),
        expires_at=NOT_AFTER,
    )
    grant = mc.consume(pending, approve(pending), now=NOW)
    assert isinstance(grant, Grant)

    # RELEASED: the gateway re-verifies and dispatches to Stripe exactly once.
    fake = FakeStripe(status="succeeded", pi_id="pi_fake_ok")
    gateway = ExecutionGateway(_executor(fake), InMemoryIdempotencyStore())
    outcome = gateway.execute(intent, decision, grant=grant, now=NOW)
    assert isinstance(outcome, ExecutionOutcome)
    assert outcome.status is ExecutionStatus.success
    assert outcome.reference == "pi_fake_ok"

    # The gateway called Stripe once, with OUR derived idempotency key — the
    # agent never chose it.
    assert len(fake.calls) == 1
    assert fake.calls[0]["idempotency_key"] == intent.idempotency_key
    assert fake.calls[0]["amount"] == 5_000
    assert fake.calls[0]["currency"] == "usd"

    # A single receipt links the decision, the approval, and the outcome.
    sink = InMemoryAuditSink()
    receipt = AuditLog(sink).record(
        digest=decision.digest,
        verdict=decision.verdict,
        reasons=decision.reasons,
        outcome_status=outcome.status,
        approval_id=grant.approval_id,
    )
    assert receipt.digest == decision.digest == outcome.digest  # decision ↔ outcome
    assert receipt.approval_id == grant.approval_id  # ↔ approval
    assert receipt.outcome_status is ExecutionStatus.success
    assert verify_chain(sink.entries()) is True

    # Redacted: no raw amount or fingerprint reaches the receipt.
    dumped = str(receipt.model_dump())
    assert "5000" not in dumped
    assert intent.dimensions.counterparty_ref not in dumped


def test_a_network_timeout_is_unknown_not_failure():
    """B8 — the money state is indeterminate, so it must not read as failure."""
    intent = derive_intent()
    fake = FakeStripe(raises=stripe.APIConnectionError("network unreachable"))
    gateway = ExecutionGateway(_executor(fake), InMemoryIdempotencyStore())
    outcome = gateway.execute(intent, _allow_decision(intent), now=NOW)
    assert outcome.status is ExecutionStatus.unknown
    assert outcome.status is not ExecutionStatus.failure


def test_a_card_decline_is_a_definite_failure():
    intent = derive_intent()
    fake = FakeStripe(
        raises=stripe.CardError("Your card was declined.", param=None, code="card_declined")
    )
    gateway = ExecutionGateway(_executor(fake), InMemoryIdempotencyStore())
    outcome = gateway.execute(intent, _allow_decision(intent), now=NOW)
    assert outcome.status is ExecutionStatus.failure


def test_a_bad_key_is_a_definite_failure_not_unknown():
    intent = derive_intent()
    fake = FakeStripe(raises=stripe.AuthenticationError("invalid api key"))
    gateway = ExecutionGateway(_executor(fake), InMemoryIdempotencyStore())
    outcome = gateway.execute(intent, _allow_decision(intent), now=NOW)
    assert outcome.status is ExecutionStatus.failure


def test_a_stripe_server_error_is_unknown():
    intent = derive_intent()
    fake = FakeStripe(raises=stripe.APIError("internal server error"))
    gateway = ExecutionGateway(_executor(fake), InMemoryIdempotencyStore())
    outcome = gateway.execute(intent, _allow_decision(intent), now=NOW)
    assert outcome.status is ExecutionStatus.unknown


def test_a_duplicate_release_hits_stripe_only_once():
    """B2 — the gateway reserves the idempotency key before dispatch."""
    intent = derive_intent()
    fake = FakeStripe(status="succeeded", pi_id="pi_fake_ok")
    gateway = ExecutionGateway(_executor(fake), InMemoryIdempotencyStore())
    decision = _allow_decision(intent)
    first = gateway.execute(intent, decision, now=NOW)
    second = gateway.execute(intent, decision, now=NOW)
    assert first == second
    assert len(fake.calls) == 1


def test_an_unclassified_stripe_error_is_fail_safe_unknown():
    """A StripeError we do not enumerate is unknown, never assumed-failed."""
    intent = derive_intent()
    fake = FakeStripe(raises=stripe.StripeError("something unforeseen"))
    gateway = ExecutionGateway(_executor(fake), InMemoryIdempotencyStore())
    outcome = gateway.execute(intent, _allow_decision(intent), now=NOW)
    assert outcome.status is ExecutionStatus.unknown


def test_a_canceled_payment_intent_is_a_failure():
    """A returned-but-terminal-non-success status means no money moved."""
    intent = derive_intent()
    fake = FakeStripe(status="canceled", pi_id="pi_fake_cx")
    gateway = ExecutionGateway(_executor(fake), InMemoryIdempotencyStore())
    outcome = gateway.execute(intent, _allow_decision(intent), now=NOW)
    assert outcome.status is ExecutionStatus.failure


def test_a_pending_payment_intent_status_is_unknown():
    """A non-terminal status (e.g. processing) is reconciled, not claimed."""
    intent = derive_intent()
    fake = FakeStripe(status="processing", pi_id="pi_fake_proc")
    gateway = ExecutionGateway(_executor(fake), InMemoryIdempotencyStore())
    outcome = gateway.execute(intent, _allow_decision(intent), now=NOW)
    assert outcome.status is ExecutionStatus.unknown
