# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Red team: the approval-replay group (B2, B3, B6).

Every test mounts an attack that would succeed against a system without the
guard, and asserts SecondSign repels it. The attacks: replay a consumed approval
to move money twice, redirect an approval onto a different action, use an expired
or unexpired-but-missing approval, and approve one's own request.
"""

from datetime import timedelta

from secondsign.approval import CheckerIdentity, CheckerVerdict, Grant, Rejected, RejectionReason
from secondsign.gateway import ExecutionOutcome, GatewayRefusal, RefusalReason
from secondsign.intent import ProposalDigest, compute_digest
from tests.redteam.conftest import (
    CHECKER,
    MAKER,
    NOT_AFTER,
    NOW,
    CountingExecutor,
    fresh_gateway,
    grant_for,
    make_intent,
    new_maker_checker,
    pending_for,
    review_decision,
    verdict_for,
)


def test_a_consumed_approval_cannot_be_replayed_to_double_spend():
    """B2. Two executions of one approved intent must move money once."""
    intent = make_intent()
    decision = review_decision(intent)
    grant = grant_for(intent)
    executor = CountingExecutor()
    gateway = fresh_gateway(executor)

    first = gateway.execute(intent, decision, grant=grant, now=NOW)
    replay = gateway.execute(intent, decision, grant=grant, now=NOW)  # same grant, again

    assert isinstance(first, ExecutionOutcome)
    assert first == replay  # idempotent replay, not a second effect
    assert executor.dispatched == [intent.idempotency_key]  # dispatched exactly once


def test_consuming_a_maker_checker_approval_twice_grants_once():
    """B2. The one-shot approval itself cannot be consumed a second time."""
    intent = make_intent()
    mc = new_maker_checker()
    pending = pending_for(mc, intent, expires_at=NOT_AFTER)
    first = mc.consume(pending, verdict_for(pending), now=NOW)
    second = mc.consume(pending, verdict_for(pending), now=NOW)
    assert isinstance(first, Grant)
    assert second == Rejected(reason=RejectionReason.already_consumed)


def test_an_approval_for_one_action_cannot_be_redirected_to_another():
    """B3. A grant is bound to a digest; it cannot authorise a different intent."""
    approved = make_intent(amount=5_000, idempotency_key="k-approved")
    attacker = make_intent(amount=5_000_000, idempotency_key="k-attacker")
    grant = grant_for(approved)  # bound to the small, approved intent
    executor = CountingExecutor()
    gateway = fresh_gateway(executor)

    # Try to spend the big intent under the small intent's decision + grant.
    outcome = gateway.execute(attacker, review_decision(approved), grant=grant, now=NOW)
    assert outcome == GatewayRefusal(reason=RefusalReason.digest_mismatch)
    assert executor.dispatched == []


def test_a_grant_for_a_different_digest_is_refused():
    """B3. Even matching the decision, a grant naming another digest is refused."""
    intent = make_intent()
    other = make_intent(amount=999, idempotency_key="k-other")
    grant = grant_for(other)  # grant.digest != decision.digest
    executor = CountingExecutor()
    outcome = fresh_gateway(executor).execute(intent, review_decision(intent), grant=grant, now=NOW)
    assert outcome == GatewayRefusal(reason=RefusalReason.not_approved)
    assert executor.dispatched == []


def test_an_expired_approval_cannot_be_consumed():
    """B2. A late consume is refused; the TTL is not advisory."""
    intent = make_intent()
    mc = new_maker_checker()
    pending = pending_for(mc, intent, expires_at=NOT_AFTER)
    too_late = NOT_AFTER + timedelta(seconds=1)
    assert mc.consume(pending, verdict_for(pending), now=too_late) == Rejected(
        reason=RejectionReason.expired
    )


def test_a_missing_expiry_is_treated_as_expired():
    """B2. An approval with no expiry is dead, not permanent."""
    intent = make_intent()
    mc = new_maker_checker()
    pending = pending_for(mc, intent, expires_at=None)
    assert mc.consume(pending, verdict_for(pending), now=NOW) == Rejected(
        reason=RejectionReason.expired
    )


def test_the_maker_cannot_approve_their_own_request():
    """B6. Separation of duties: the checker's subject may not be the maker's."""
    intent = make_intent()
    mc = new_maker_checker()
    pending = pending_for(mc, intent, expires_at=NOT_AFTER)
    self_verdict = CheckerVerdict(
        checker=CheckerIdentity(subject=MAKER.subject),
        approval_id=pending.approval_id,
        proposal=pending.proposal,
        approved=True,
    )
    assert mc.consume(pending, self_verdict, now=NOW) == Rejected(
        reason=RejectionReason.self_approval
    )


def test_a_forged_grant_for_an_unapproved_review_is_refused():
    """B3. A fabricated grant whose proposal does not match is refused at dispatch."""
    intent = make_intent()
    forged = Grant(approval_id="forged", proposal=ProposalDigest(value="f" * 64), checker=CHECKER)
    executor = CountingExecutor()
    outcome = fresh_gateway(executor).execute(
        intent, review_decision(intent), grant=forged, now=NOW
    )
    assert outcome == GatewayRefusal(reason=RefusalReason.not_approved)
    assert executor.dispatched == []


def test_positive_control_a_valid_approval_does_execute():
    """The guards above reject; a genuine approval must still go through, or the
    tests would be vacuously green."""
    intent = make_intent()
    grant = grant_for(intent)
    outcome = fresh_gateway(CountingExecutor()).execute(
        intent, review_decision(intent), grant=grant, now=NOW
    )
    assert isinstance(outcome, ExecutionOutcome)
    assert compute_digest(intent) == outcome.digest
