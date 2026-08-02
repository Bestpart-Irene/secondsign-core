# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The live end-to-end against real test-mode Stripe.

Skipped unless STRIPE_TEST_KEY is set, so CI never needs a credential. Run it
yourself with your own test key, which stays in your environment and never
enters the repo:

    STRIPE_TEST_KEY=rk_test_... .venv/bin/pytest tests/e2e/test_stripe_live.py -v

It walks the same path as the faked test, but the gateway dispatches to a real
test-mode Stripe PaymentIntent — the first real outbound call, which is why this
slice is a human checkpoint.
"""

import os

import pytest

from secondsign.approval import Grant
from secondsign.audit import AuditLog, InMemoryAuditSink, verify_chain
from secondsign.contracts import Currency
from secondsign.decision import DecisionEngine, DecisionVerdict
from secondsign.gateway import (
    ExecutionGateway,
    ExecutionOutcome,
    ExecutionStatus,
    InMemoryIdempotencyStore,
)
from secondsign.intent import compute_proposal_digest
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
    LargePaymentReviewPolicy,
    approve,
    derive_intent,
    make_stripe_call,
    new_maker_checker,
)

_KEY = os.environ.get("STRIPE_TEST_KEY")
_WINDOW = 3_600


@pytest.mark.skipif(not _KEY, reason="STRIPE_TEST_KEY not set; live Stripe e2e skipped")
def test_live_test_mode_payment_is_held_approved_and_released():
    # Refuse to run against anything but a test-mode key — a live key here would
    # move real money.
    assert _KEY.startswith(("rk_test_", "sk_test_")), (
        "STRIPE_TEST_KEY is not a test-mode key (rk_test_/sk_test_); refusing to run"
    )

    intent = derive_intent(make_stripe_call(amount_minor=5_000, currency=Currency.USD))

    limit = AmountLimit(
        quote_currency=Currency.USD, window_seconds=_WINDOW, max_aggregate_minor=1_000_000
    )
    context = PolicyContext(
        window_aggregate=WindowAggregate(
            key=AggregateKey.from_intent(intent), window_seconds=_WINDOW, aggregate_minor=0, count=0
        )
    )
    decision = DecisionEngine(
        [AmountWindowPolicy(limit), LargePaymentReviewPolicy(threshold_minor=1)]
    ).decide(intent, context)
    assert decision.verdict is DecisionVerdict.REVIEW  # held

    mc = new_maker_checker()
    pending = mc.request(
        decision,
        MAKER,
        approval_id="appr-live-1",
        proposal=compute_proposal_digest(intent),
        expires_at=NOT_AFTER,
    )
    grant = mc.consume(pending, approve(pending), now=NOW)
    assert isinstance(grant, Grant)  # approved

    executor = StripePaymentExecutor(api_key=_KEY)  # real stripe, test mode
    gateway = ExecutionGateway(executor, InMemoryIdempotencyStore())
    outcome = gateway.execute(intent, decision, grant=grant, now=NOW)  # released
    assert isinstance(outcome, ExecutionOutcome)
    assert outcome.status is ExecutionStatus.success, f"unexpected outcome: {outcome}"
    assert outcome.reference is not None and outcome.reference.startswith("pi_")

    sink = InMemoryAuditSink()
    receipt = AuditLog(sink).record(
        digest=decision.digest,
        verdict=decision.verdict,
        reasons=decision.reasons,
        outcome_status=outcome.status,
        approval_id=grant.approval_id,
    )
    assert receipt.digest == outcome.digest
    assert receipt.approval_id == grant.approval_id
    assert verify_chain(sink.entries()) is True
    print(f"\nLive test-mode PaymentIntent released: {outcome.reference} ({outcome.status.value})")
