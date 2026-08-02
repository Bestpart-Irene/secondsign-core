# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""System-level integrity: after a mixed workload, the books still agree.

The unit suites each check one component. This one runs the whole in-process
service through a realistic burst — allows, denies, an over-cap refusal, a
review approved and a review declined, and duplicate retries — and then asserts
the invariants that only hold *across* components:

- **The audit chain verifies.** Every non-ALLOW path and every dispatch writes
  a receipt, hash-chained; a gap or an edit anywhere fails `verify_chain`.
- **Nothing dispatched that should not have.** The rail's ledger holds only
  actions that were allowed or approved — never a denial, never a bare review.
- **The window never went over the cap.** Total recorded spend ≤ the limit,
  the same invariant the concurrency suite checks under threads, here under a
  sequence long enough to cross the cap if the bookkeeping leaked.
- **Every dispatch is on the audit chain.** The rail moved nothing the trail
  does not record.

No real money and no real API — the rail is an in-process recorder.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from secondsign.agent.surface import AuthorizationRequest
from secondsign.approval import CheckerIdentity, CheckerVerdict
from secondsign.audit import AuditLog, InMemoryAuditSink, verify_chain
from secondsign.contracts import Currency
from secondsign.controlplane.fingerprint import FingerprintKey
from secondsign.controlplane.window import WindowLedger
from secondsign.decision import DecisionEngine
from secondsign.gateway.authorization import AuthorizationService
from secondsign.gateway.execution import (
    ExecutionGateway,
    ExecutionStatus,
    InMemoryIdempotencyStore,
    RailResult,
)
from secondsign.policy import AmountLimit, AmountWindowPolicy

PRINCIPAL = "spiffe://secondsign.example/agent/integrity"
CAP = 1_000_00
REVIEW_ABOVE = 300_00


class RecordingRail:
    """Records the value of everything it dispatched. No network, no money."""

    def __init__(self) -> None:
        self.dispatched: list[int] = []

    def dispatch(self, intent) -> RailResult:  # noqa: ANN001 — protocol shape
        self.dispatched.append(intent.dimensions.value_upper_minor)
        return RailResult(status=ExecutionStatus.success, reference="ref")


@pytest.fixture()
def system():
    sink = InMemoryAuditSink()
    rail = RecordingRail()
    limit = AmountLimit(
        quote_currency=Currency.USD,
        window_seconds=3600,
        max_aggregate_minor=CAP,
        review_above_minor=REVIEW_ABOVE,
    )
    service = AuthorizationService(
        engine=DecisionEngine([AmountWindowPolicy(limit)]),
        gateway=ExecutionGateway(rail, InMemoryIdempotencyStore()),
        ledger=WindowLedger(window_seconds=limit.window_seconds),
        audit=AuditLog(sink),
        keys=FingerprintKey.generate(),
    )
    return service, sink, rail


def _request(ref_hex: str, amount: int) -> AuthorizationRequest:
    return AuthorizationRequest.model_validate(
        {
            "action": "payment",
            "rail": "card",
            "currency": "USD",
            "amount_minor": amount,
            "reversibility": "irreversible",
            "counterparty_ref": "fp:" + "cd" * 32,
            "source_account_ref": "fp:" + "ef" * 32,
            "request_ref": "fp:" + ref_hex,
        }
    )


def test_after_a_mixed_workload_the_books_agree(system) -> None:
    service, sink, rail = system
    start = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)

    def at(minute: int) -> datetime:
        # A monotonic clock, all within the one-hour window so nothing ages out.
        # The window is time-indexed, so a spend recorded at minute N is only
        # visible to a decision made at minute ≥ N. This sequential test feeds
        # the stamps in order; the *real* gateway does not guarantee that
        # (stamps are taken before a non-FIFO lock), which is exactly the leak
        # `test_the_cap_holds_when_stamp_order_inverts_lock_order` covers — the
        # service clamps its clock to a monotonic floor so an out-of-order stamp
        # still sees every prior spend.
        return start + timedelta(minutes=minute)

    # A small allow, dispatched.
    service.authorize(PRINCIPAL, _request("01" * 32, 100_00), now=at(0))
    # A duplicate of it, one minute later: a retry, not a second payment.
    service.authorize(PRINCIPAL, _request("01" * 32, 100_00), now=at(1))

    # A review, approved — records $400 at minute 3.
    held = service.authorize(PRINCIPAL, _request("02" * 32, 400_00), now=at(2))
    assert held.status.value == "awaiting_review"
    (review,) = service.open_reviews()
    service.resolve(
        review.approval_id,
        CheckerVerdict(
            checker=CheckerIdentity(subject="spiffe://secondsign.example/approver/a"),
            approval_id=review.approval_id,
            proposal=review.approval.proposal,
            approved=True,
        ),
        now=at(3),
    )

    # A review, declined — nothing moves.
    service.authorize(PRINCIPAL, _request("03" * 32, 350_00), now=at(4))
    (review2,) = service.open_reviews()
    service.resolve(
        review2.approval_id,
        CheckerVerdict(
            checker=CheckerIdentity(subject="spiffe://secondsign.example/approver/a"),
            approval_id=review2.approval_id,
            proposal=review2.approval.proposal,
            approved=False,
        ),
        now=at(5),
    )

    # $500 is now spent ($100 + $400). A $600 proposal crosses the $1,000 cap.
    over = service.authorize(PRINCIPAL, _request("04" * 32, 600_00), now=at(6))
    assert over.status.value == "refused"

    # --- the cross-component invariants ------------------------------------
    entries = sink.entries()
    assert verify_chain(entries), "the audit chain does not verify after the workload"

    # The rail moved exactly the two allowed/approved actions, once each.
    assert rail.dispatched == [100_00, 400_00], (
        f"the rail dispatched {rail.dispatched} — a denial, a decline or a duplicate reached it"
    )
    assert sum(rail.dispatched) <= CAP

    # Every dispatch is on the chain: a success receipt exists for each, and no
    # success receipt exists without a matching dispatch.
    successes = [e for e in entries if e.outcome_status is ExecutionStatus.success]
    assert len(successes) == len(rail.dispatched), (
        "the number of success receipts and rail dispatches disagree — the "
        "trail and the rail are not recording the same events"
    )


def test_the_audit_chain_is_unbroken_across_every_verdict_kind(system) -> None:
    """Each verdict class writes into the same chain, and the chain stays
    linked no matter which order the classes arrive in."""
    service, sink, _ = system
    now = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)

    service.authorize(PRINCIPAL, _request("aa" * 32, 50_00), now=now)  # allow
    service.authorize(PRINCIPAL, _request("bb" * 32, 400_00), now=now)  # review
    service.authorize(PRINCIPAL, _request("cc" * 32, 9_000_00), now=now)  # deny (over cap)

    entries = sink.entries()
    assert len(entries) >= 3
    assert verify_chain(entries)
    # Sequence is dense and zero-based — no receipt was dropped between kinds.
    assert [e.sequence for e in entries] == list(range(len(entries)))
