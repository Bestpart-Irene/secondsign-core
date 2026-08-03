# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""A REVIEW verdict, carried to a human and back.

Before this, `REVIEW` was a slower refusal: the service answered
`awaiting_review` and nothing carried that answer anywhere. The pieces all
existed — `MakerChecker`, the identities, an `ExecutionGateway` that requires a
grant — and none of them were connected across the seam.

What is asserted here is the seam, so the cases are the things only the assembly
can get wrong: that holding a review moves nothing and reserves nothing, that an
approval arriving hours later still executes, that it executes *what was
approved* and not a substitute, that a re-decision may still refuse, and that
the agent — which is holding one handle and re-sending one proposal — is told
the truth at every stage without learning anything about the human.

The clock in these tests is deliberately coarse. `INTENT_TTL` is five minutes
and every approval here lands well outside it, because an approval inside the
window would pass for the wrong reason and prove nothing about ADR 0005.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from secondsign.agent.surface import AgentOutcomeStatus, AuthorizationRequest
from secondsign.approval import (
    CheckerIdentity,
    CheckerVerdict,
    MakerIdentity,
    RejectionReason,
)
from secondsign.audit import AuditLog, InMemoryAuditSink, verify_chain
from secondsign.contracts import ActionClass, Currency, RailClass
from secondsign.controlplane.fingerprint import FingerprintKey
from secondsign.controlplane.pending import InMemoryPendingStore
from secondsign.controlplane.window import WindowLedger
from secondsign.decision import DecisionEngine, DecisionVerdict
from secondsign.gateway import ExecutionGateway, ExecutionStatus, InMemoryIdempotencyStore
from secondsign.gateway.authorization import (
    AuthorizationService,
    ReviewOutcomeStatus,
    complete_intent,
)
from secondsign.intent import ProposalDigest, compute_proposal_digest
from secondsign.policy import AmountLimit, AmountWindowPolicy
from tests.gateway.test_authorization_service import (
    ALICE,
    FP_A,
    FP_B,
    NOW,
    RecordingExecutor,
    make_request,
)

CHECKER = CheckerIdentity(subject="carol")
#: Long after the five-minute intent window has closed, and well inside any
#: sane review TTL. The whole flow has to survive this gap.
LATER = NOW + timedelta(hours=2)
#: Long after the intent window closed and still inside the trailing spend
#: window, which is what the re-decision cases need in order to see a limit
#: that has since filled up.
SOON = NOW + timedelta(minutes=30)

#: A band that puts the default 4,200 request in front of a human: above the
#: review threshold, under the cap.
REVIEW_ABOVE = 1_000
CAP = 100_000

#: Pinned here rather than imported from the code, so a change to the review TTL
#: has to be made twice — once where it is enforced and once in a test that
#: states the number out loud.
REVIEW_TTL_EXPECTED = timedelta(hours=4)


def build_service(
    *,
    executor: RecordingExecutor | None = None,
    sink: InMemoryAuditSink | None = None,
    review_above_minor: int | None = REVIEW_ABOVE,
    max_aggregate_minor: int = CAP,
    pending: InMemoryPendingStore | None = None,
) -> AuthorizationService:
    limit = AmountLimit(
        quote_currency=Currency.USD,
        window_seconds=3600,
        max_aggregate_minor=max_aggregate_minor,
        review_above_minor=review_above_minor,
    )
    return AuthorizationService(
        engine=DecisionEngine([AmountWindowPolicy(limit)]),
        gateway=ExecutionGateway(
            executor if executor is not None else RecordingExecutor(),
            InMemoryIdempotencyStore(),
        ),
        ledger=WindowLedger(window_seconds=limit.window_seconds),
        audit=AuditLog(sink if sink is not None else InMemoryAuditSink()),
        keys=FingerprintKey.generate(),
        pending=pending if pending is not None else InMemoryPendingStore(),
    )


def only_open_review(service: AuthorizationService):
    reviews = service.open_reviews()
    assert len(reviews) == 1, f"expected exactly one open review, found {len(reviews)}"
    return reviews[0]


def approve(pending, *, checker: CheckerIdentity = CHECKER, approved: bool = True):
    return CheckerVerdict(
        checker=checker,
        approval_id=pending.approval.approval_id,
        proposal=pending.approval.proposal,
        approved=approved,
    )


# --- holding a review --------------------------------------------------------


class TestHoldingAReview:
    def test_a_review_moves_nothing_and_reserves_nothing(self) -> None:
        executor = RecordingExecutor()
        service = build_service(executor=executor)

        outcome = service.authorize(ALICE, make_request(), now=NOW)

        assert outcome.status is AgentOutcomeStatus.awaiting_review
        assert executor.dispatched == []

    def test_a_held_review_does_not_consume_the_window(self) -> None:
        """Nothing has moved, so nothing has been spent.

        Consuming the window here would let a stream of proposals a human never
        answers exhaust an agent's limit — a denial of service an agent could
        inflict on itself, and one an attacker could inflict on it.
        """
        service = build_service(review_above_minor=1_000, max_aggregate_minor=9_000)

        service.authorize(ALICE, make_request(amount_minor=5_000), now=NOW)
        second = service.authorize(
            ALICE, make_request(amount_minor=5_000, request_ref=FP_A), now=NOW
        )

        assert second.status is AgentOutcomeStatus.awaiting_review, (
            "the first held review was counted against the window, so the second "
            "proposal read as over the cap"
        )

    def test_the_agent_is_told_nothing_about_the_human(self) -> None:
        service = build_service()

        outcome = service.authorize(ALICE, make_request(), now=NOW)
        review = only_open_review(service)

        body = outcome.model_dump_json()
        assert review.approval_id not in body
        assert "carol" not in body
        assert review.principal_ref not in body

    def test_the_review_carries_the_proposal_digest_not_the_intent_digest(self) -> None:
        service = build_service()

        service.authorize(ALICE, make_request(), now=NOW)
        review = only_open_review(service)

        assert review.approval.proposal.value != review.approval.decision.digest.value

    def test_one_workload_cannot_see_anothers_review(self) -> None:
        """Reviews are keyed by the reservation, which is namespaced by
        principal — the same property that keeps idempotency handles apart."""
        service = build_service()

        service.authorize(ALICE, make_request(), now=NOW)
        service.authorize("spiffe://secondsign.example/agent/mallory", make_request(), now=NOW)

        assert len({review.approval_id for review in service.open_reviews()}) == 2


# --- the approval, arriving long after the window closed ---------------------


class TestApprovalAfterTheWindowClosed:
    def test_an_approval_two_hours_later_still_executes(self) -> None:
        """ADR 0005, as a single case.

        The intent decided at NOW expired four minutes later. The approval binds
        to the proposal, so the service re-completes the intent with a fresh
        window, re-decides it, and dispatches what the human approved.
        """
        executor = RecordingExecutor()
        service = build_service(executor=executor)
        service.authorize(ALICE, make_request(), now=NOW)
        review = only_open_review(service)

        resolution = service.resolve(review.approval_id, approve(review), now=LATER)

        assert resolution.status is ReviewOutcomeStatus.executed
        assert len(executor.dispatched) == 1

    def test_what_is_dispatched_is_what_was_approved(self) -> None:
        executor = RecordingExecutor()
        service = build_service(executor=executor)
        service.authorize(ALICE, make_request(amount_minor=4_200), now=NOW)
        review = only_open_review(service)

        service.resolve(review.approval_id, approve(review), now=LATER)

        dispatched = executor.dispatched[0]
        assert dispatched.dimensions.value_upper_minor == 4_200
        assert dispatched.dimensions.counterparty_ref == FP_A
        assert compute_proposal_digest(dispatched) == review.approval.proposal

    def test_the_dispatched_intent_carries_a_fresh_window(self) -> None:
        """The one field the approval does not cover is the one that moves."""
        executor = RecordingExecutor()
        service = build_service(executor=executor)
        service.authorize(ALICE, make_request(), now=NOW)
        review = only_open_review(service)

        service.resolve(review.approval_id, approve(review), now=LATER)

        assert executor.dispatched[0].dimensions.not_before == LATER

    def test_the_agent_reads_completed_on_its_next_poll(self) -> None:
        service = build_service()
        request = make_request()
        service.authorize(ALICE, request, now=NOW)
        review = only_open_review(service)
        service.resolve(review.approval_id, approve(review), now=LATER)

        outcome = service.authorize(ALICE, request, now=LATER + timedelta(seconds=30))

        assert outcome.status is AgentOutcomeStatus.completed

    def test_a_resolved_review_leaves_the_queue(self) -> None:
        service = build_service()
        service.authorize(ALICE, make_request(), now=NOW)
        review = only_open_review(service)

        service.resolve(review.approval_id, approve(review), now=LATER)

        assert service.open_reviews() == ()


# --- what an approval may not do ---------------------------------------------


class TestWhatAnApprovalMayNotDo:
    def test_an_approval_cannot_execute_a_different_proposal(self) -> None:
        """B3, at the seam rather than at the provider.

        Two proposals are held. The verdict for the first is replayed against
        the second's approval id — the substitution a reviewer would never see,
        because the two look identical everywhere except the counterparty.
        """
        executor = RecordingExecutor()
        service = build_service(executor=executor)
        service.authorize(ALICE, make_request(counterparty_ref=FP_A), now=NOW)
        service.authorize(ALICE, make_request(counterparty_ref=FP_B, request_ref=FP_A), now=NOW)
        first, second = sorted(service.open_reviews(), key=lambda r: r.approval_id)

        resolution = service.resolve(second.approval_id, approve(first), now=LATER)

        assert resolution.status is ReviewOutcomeStatus.rejected
        assert resolution.reason is RejectionReason.wrong_approval
        assert executor.dispatched == []

    def test_an_answer_names_the_approval_it_answers(self) -> None:
        """Defence in depth behind the digest.

        The digest check would catch the substitution above on content alone.
        This is the case that does not depend on the two proposals differing:
        an answer is about one pending approval, and moving it to another is
        rejected for what it is rather than for what it happens to contain.
        """
        executor = RecordingExecutor()
        service = build_service(executor=executor)
        service.authorize(ALICE, make_request(amount_minor=4_200), now=NOW)
        service.authorize(ALICE, make_request(amount_minor=4_200, request_ref=FP_A), now=NOW)
        first, second = sorted(service.open_reviews(), key=lambda r: r.approval_id)
        answer = CheckerVerdict(
            checker=CHECKER,
            approval_id=first.approval_id,
            proposal=second.approval.proposal,
            approved=True,
        )

        resolution = service.resolve(second.approval_id, answer, now=LATER)

        assert resolution.status is ReviewOutcomeStatus.rejected
        assert resolution.reason is RejectionReason.wrong_approval
        assert executor.dispatched == []

    def test_a_replayed_approval_produces_no_second_dispatch(self) -> None:
        """B2 — one-shot, across the seam and not only inside MakerChecker."""
        executor = RecordingExecutor()
        service = build_service(executor=executor)
        service.authorize(ALICE, make_request(), now=NOW)
        review = only_open_review(service)
        verdict = approve(review)

        service.resolve(review.approval_id, verdict, now=LATER)
        replay = service.resolve(review.approval_id, verdict, now=LATER + timedelta(minutes=1))

        assert replay.status is ReviewOutcomeStatus.rejected
        assert len(executor.dispatched) == 1

    def test_a_checker_who_is_the_maker_is_rejected(self) -> None:
        """B6 — separation, checked where the maker identity is actually set."""
        executor = RecordingExecutor()
        service = build_service(executor=executor)
        service.authorize(ALICE, make_request(), now=NOW)
        review = only_open_review(service)
        self_approval = CheckerVerdict(
            checker=CheckerIdentity(subject=review.approval.maker.subject),
            approval_id=review.approval.approval_id,
            proposal=review.approval.proposal,
            approved=True,
        )

        resolution = service.resolve(review.approval_id, self_approval, now=LATER)

        assert resolution.status is ReviewOutcomeStatus.rejected
        assert resolution.reason is RejectionReason.self_approval
        assert executor.dispatched == []

    def test_the_maker_is_the_workload_and_not_a_person(self) -> None:
        """The agent proposed it, so the agent is the maker — which is what
        makes self-approval by that workload structurally impossible."""
        service = build_service()

        service.authorize(ALICE, make_request(), now=NOW)
        review = only_open_review(service)

        assert isinstance(review.approval.maker, MakerIdentity)
        assert ALICE not in review.approval.maker.subject, (
            "the raw principal is in the maker identity — fingerprints only"
        )

    def test_an_expired_approval_does_not_execute(self) -> None:
        executor = RecordingExecutor()
        service = build_service(executor=executor)
        service.authorize(ALICE, make_request(), now=NOW)
        review = only_open_review(service)

        resolution = service.resolve(
            review.approval_id, approve(review), now=NOW + timedelta(days=3)
        )

        assert resolution.status is ReviewOutcomeStatus.rejected
        assert resolution.reason is RejectionReason.expired
        assert executor.dispatched == []

    def test_an_unknown_approval_id_executes_nothing(self) -> None:
        executor = RecordingExecutor()
        service = build_service(executor=executor)
        service.authorize(ALICE, make_request(), now=NOW)
        review = only_open_review(service)

        resolution = service.resolve("appr-does-not-exist", approve(review), now=LATER)

        assert resolution.status is ReviewOutcomeStatus.rejected
        assert resolution.reason is RejectionReason.unknown_approval
        assert executor.dispatched == []

    def test_a_checker_saying_no_executes_nothing(self) -> None:
        executor = RecordingExecutor()
        service = build_service(executor=executor)
        service.authorize(ALICE, make_request(), now=NOW)
        review = only_open_review(service)

        resolution = service.resolve(review.approval_id, approve(review, approved=False), now=LATER)

        assert resolution.status is ReviewOutcomeStatus.rejected
        assert resolution.reason is RejectionReason.not_approved
        assert executor.dispatched == []

    def test_a_held_proposal_that_no_longer_re_completes_is_refused(self) -> None:
        """The belt-and-braces check, made to fire.

        Re-completion is deterministic in everything but the window, so this
        branch is unreachable unless the completion logic changes under a
        running deployment — a redeploy while a review is open. Standing in for
        that, the held record is replaced with one whose approval binds a
        proposal the re-completed intent cannot produce. The point is that the
        comparison is real: nothing dispatches on the strength of an approval id
        alone.
        """
        executor = RecordingExecutor()
        pending = InMemoryPendingStore()
        service = build_service(executor=executor, pending=pending)
        service.authorize(ALICE, make_request(), now=NOW)
        review = only_open_review(service)
        pending.hold(
            review.model_copy(
                update={
                    "approval": review.approval.model_copy(
                        update={"proposal": ProposalDigest(value="0" * 64)}
                    )
                }
            )
        )

        resolution = service.resolve(review.approval_id, approve(review), now=LATER)

        assert resolution.status is ReviewOutcomeStatus.rejected
        assert resolution.reason is RejectionReason.digest_mismatch
        assert executor.dispatched == []


# --- the re-decision is a real decision --------------------------------------


class TestTheReDecisionIsARealDecision:
    def test_a_re_decision_that_denies_dispatches_nothing(self) -> None:
        """Policy state moves while a human thinks.

        Between the review being raised and the approval arriving, another
        payment fills the window. The approved action is now over the cap, and
        an approval is not a permission slip that outranks the limit.
        """
        executor = RecordingExecutor()
        service = build_service(
            executor=executor, review_above_minor=4_000, max_aggregate_minor=8_000
        )
        service.authorize(ALICE, make_request(amount_minor=5_000), now=NOW)
        review = only_open_review(service)
        service.authorize(ALICE, make_request(amount_minor=3_500, request_ref=FP_A), now=NOW)

        resolution = service.resolve(review.approval_id, approve(review), now=SOON)

        assert resolution.status is ReviewOutcomeStatus.refused
        assert [intent.dimensions.value_upper_minor for intent in executor.dispatched] == [3_500], (
            "the approved 5,000 was dispatched over a cap it no longer fits under"
        )

    def test_a_denial_does_not_burn_the_human_s_answer(self) -> None:
        """The human said yes; the window said no. Only one of those changed.

        Once the window drains, the same verdict executes — otherwise a
        transient limit would silently require a second trip to a human, which
        is how approval fatigue starts.
        """
        executor = RecordingExecutor()
        service = build_service(
            executor=executor, review_above_minor=4_000, max_aggregate_minor=8_000
        )
        service.authorize(ALICE, make_request(amount_minor=5_000), now=NOW)
        review = only_open_review(service)
        service.authorize(ALICE, make_request(amount_minor=3_500, request_ref=FP_A), now=NOW)
        verdict = approve(review)

        refused = service.resolve(review.approval_id, verdict, now=SOON)
        drained = service.resolve(review.approval_id, verdict, now=LATER)

        assert refused.status is ReviewOutcomeStatus.refused
        assert drained.status is ReviewOutcomeStatus.executed
        assert [intent.dimensions.value_upper_minor for intent in executor.dispatched] == [
            3_500,
            5_000,
        ]

    def test_an_executed_review_consumes_the_window(self) -> None:
        executor = RecordingExecutor()
        service = build_service(
            executor=executor, review_above_minor=1_000, max_aggregate_minor=9_000
        )
        service.authorize(ALICE, make_request(amount_minor=5_000), now=NOW)
        review = only_open_review(service)
        service.resolve(review.approval_id, approve(review), now=LATER)

        later = service.authorize(
            ALICE, make_request(amount_minor=5_000, request_ref=FP_A), now=LATER
        )

        assert later.status is AgentOutcomeStatus.refused, (
            "5,000 was dispatched and not deducted, so a second 5,000 fitted under a 9,000 cap"
        )


# --- what the agent can learn, on one handle ---------------------------------


class TestThePollingAgent:
    def test_polling_a_held_review_repeats_awaiting_review(self) -> None:
        service = build_service()
        request = make_request()

        service.authorize(ALICE, request, now=NOW)
        again = service.authorize(ALICE, request, now=NOW + timedelta(minutes=30))

        assert again.status is AgentOutcomeStatus.awaiting_review
        assert len(service.open_reviews()) == 1, "polling raised a second review"

    def test_polling_returns_the_same_decision_reference(self) -> None:
        service = build_service()
        request = make_request()

        first = service.authorize(ALICE, request, now=NOW)
        again = service.authorize(ALICE, request, now=NOW + timedelta(minutes=30))

        assert again.decision_ref == first.decision_ref

    def test_polling_with_a_different_proposal_is_refused(self) -> None:
        service = build_service()

        service.authorize(ALICE, make_request(amount_minor=4_200), now=NOW)
        outcome = service.authorize(ALICE, make_request(amount_minor=4_300), now=NOW)

        assert outcome.status is AgentOutcomeStatus.refused
        assert len(service.open_reviews()) == 1


# --- the trail ---------------------------------------------------------------


class TestTheTrail:
    def test_every_stage_leaves_a_receipt_and_the_chain_verifies(self) -> None:
        sink = InMemoryAuditSink()
        service = build_service(sink=sink)
        service.authorize(ALICE, make_request(), now=NOW)
        review = only_open_review(service)

        service.resolve(review.approval_id, approve(review), now=LATER)

        verdicts = [entry.verdict for entry in sink.entries()]
        assert verdicts == [DecisionVerdict.REVIEW, DecisionVerdict.REVIEW], (
            "the executed receipt must still say REVIEW — the engine decided "
            "REVIEW and a receipt saying ALLOW would be false about it"
        )
        assert sink.entries()[0].approval_id is None
        assert sink.entries()[-1].approval_id == review.approval_id, (
            "nothing in the trail says the action was approved by a human"
        )
        assert sink.entries()[-1].outcome_status is ExecutionStatus.success
        assert verify_chain(sink.entries())

    def test_polling_does_not_write_a_second_receipt(self) -> None:
        """The trail holds decided actions, not every question about one."""
        sink = InMemoryAuditSink()
        service = build_service(sink=sink)
        request = make_request()

        service.authorize(ALICE, request, now=NOW)
        service.authorize(ALICE, request, now=NOW + timedelta(minutes=5))

        assert len(sink.entries()) == 1

    def test_a_receipt_records_the_principal_of_the_workload_that_proposed(self) -> None:
        sink = InMemoryAuditSink()
        service = build_service(sink=sink)
        service.authorize(ALICE, make_request(), now=NOW)
        review = only_open_review(service)

        service.resolve(review.approval_id, approve(review), now=LATER)

        assert sink.entries()[-1].principal_ref == review.principal_ref
        assert ALICE not in sink.entries()[-1].model_dump_json()


# --- the request an approver is shown ----------------------------------------


def test_the_request_held_for_review_is_the_one_the_agent_sent() -> None:
    """B3 — the human is shown the object that will execute, not a summary."""
    service = build_service()
    request = make_request(amount_minor=4_200)

    service.authorize(ALICE, request, now=NOW)
    review = only_open_review(service)

    assert review.request == request
    assert isinstance(review.request, AuthorizationRequest)


@pytest.mark.parametrize(
    "field",
    ["rail", "currency", "amount_minor", "counterparty_ref", "source_account_ref"],
)
def test_no_held_field_can_change_between_review_and_execution(field: str) -> None:
    """Every field of the request the *intent* carries is inside the digest.

    Stated as a parametrised case rather than as prose because "the human
    approved these fields" is only true field by field, and a field added to
    the wire later must be added here to stay true.

    `action` is deliberately absent from this list: the intent does not carry an
    action class at all, so two requests differing only in it are one proposal.
    `TestWhatAnApprovalMayNotDo` covers what keeps that from becoming a
    substitution.
    """
    alternatives = {
        "rail": RailClass.bank_transfer,
        "currency": Currency.EUR,
        "amount_minor": 9_999,
        "counterparty_ref": "fp:" + "e5" * 32,
        "source_account_ref": "fp:" + "f6" * 32,
    }
    service = build_service()
    service.authorize(ALICE, make_request(), now=NOW)
    review = only_open_review(service)

    substituted = compute_proposal_digest(
        complete_intent(
            make_request(**{field: alternatives[field]}),
            idempotency_key=review.reservation_key,
            now=NOW,
        )
    )

    assert substituted != review.approval.proposal, (
        f"{field} is outside the proposal digest, so a human approving one value "
        f"would have approved every other value of it"
    )


def test_the_action_class_is_not_carried_by_the_intent() -> None:
    """Pinning what is *not* true, so nobody assumes it is.

    `complete_intent` reads the wire's action class to decide whether the
    request is expressible and then drops it: `DecisionDimensions` has no such
    field. Two requests differing only in action produce one intent, so no
    policy can distinguish a payout from a refund and no reviewer display can
    either. It is not a substitution channel — the reservation key is inside the
    digest and is unique per review — and it is a real gap, tracked separately.

    This case exists so that closing the gap breaks a test that says what the
    old behaviour was, rather than passing silently either way.
    """
    payment = complete_intent(
        make_request(action=ActionClass.payment), idempotency_key="idem-x", now=NOW
    )
    refund = complete_intent(
        make_request(action=ActionClass.refund), idempotency_key="idem-x", now=NOW
    )

    assert compute_proposal_digest(payment) == compute_proposal_digest(refund)
    assert "action" not in str(payment.dimensions.model_fields_set)


def test_the_review_ttl_is_a_constant_and_not_a_setting(monkeypatch) -> None:
    """An operator who can extend a review TTL by editing an environment
    variable is an operator whose approval expiry is a suggestion."""
    monkeypatch.setenv("SECONDSIGN_REVIEW_TTL", "9999")
    service = build_service()

    service.authorize(ALICE, make_request(), now=NOW)
    review = only_open_review(service)

    assert review.approval.expires_at is not None
    assert review.approval.expires_at - NOW == REVIEW_TTL_EXPECTED


def test_a_review_needs_no_configuration_to_be_held() -> None:
    """The pending store defaults to a real one; a deployment that forgot to
    supply it must not silently drop reviews on the floor."""
    service = AuthorizationService(
        engine=DecisionEngine(
            [
                AmountWindowPolicy(
                    AmountLimit(
                        quote_currency=Currency.USD,
                        window_seconds=3600,
                        max_aggregate_minor=CAP,
                        review_above_minor=REVIEW_ABOVE,
                    )
                )
            ]
        ),
        gateway=ExecutionGateway(RecordingExecutor(), InMemoryIdempotencyStore()),
        ledger=WindowLedger(window_seconds=3600),
        audit=AuditLog(InMemoryAuditSink()),
        keys=FingerprintKey.generate(),
    )

    outcome = service.authorize(ALICE, make_request(), now=NOW)

    assert outcome.status is AgentOutcomeStatus.awaiting_review
    assert len(service.open_reviews()) == 1


def test_the_clock_the_service_is_given_is_the_clock_it_uses() -> None:
    """No `datetime.now()` inside the flow: a test that cannot control the clock
    cannot assert anything about expiry."""
    service = build_service()
    stamp = datetime(2027, 3, 1, 9, 30, tzinfo=timezone.utc)

    outcome = service.authorize(ALICE, make_request(), now=stamp)

    assert outcome.decided_at == stamp
    assert only_open_review(service).approval.expires_at == stamp + REVIEW_TTL_EXPECTED


class TestADeclineSettlesTheReview:
    """A checker's decline (or an expiry) takes the review off the queue and
    settles the agent's handle to refused — no approver shopping, and the
    agent's poll ends (H3)."""

    def test_a_declined_review_leaves_the_queue(self) -> None:
        service = build_service()
        service.authorize(ALICE, make_request(), now=NOW)
        review = only_open_review(service)

        resolution = service.resolve(review.approval_id, approve(review, approved=False), now=SOON)

        assert resolution.status is ReviewOutcomeStatus.rejected
        assert service.open_reviews() == (), "a declined review is still answerable"

    def test_a_second_checker_cannot_approve_a_declined_review(self) -> None:
        """The whole point: once one checker declines, another must not be able
        to approve the same review."""
        executor = RecordingExecutor()
        service = build_service(executor=executor)
        service.authorize(ALICE, make_request(), now=NOW)
        review = only_open_review(service)

        service.resolve(review.approval_id, approve(review, approved=False), now=SOON)
        second = service.resolve(review.approval_id, approve(review, approved=True), now=SOON)

        assert second.status is ReviewOutcomeStatus.rejected
        assert second.reason is RejectionReason.unknown_approval
        assert executor.dispatched == [], "a declined review was approved by a second checker"

    def test_the_agent_reads_refused_after_a_decline(self) -> None:
        """The agent re-sending its handle after a decline reads refused, not
        awaiting_review forever."""
        service = build_service()
        request = make_request()
        service.authorize(ALICE, request, now=NOW)
        review = only_open_review(service)

        service.resolve(review.approval_id, approve(review, approved=False), now=SOON)
        reread = service.authorize(ALICE, request, now=SOON)

        assert reread.status is AgentOutcomeStatus.refused

    def test_a_decline_is_recorded(self) -> None:
        sink = InMemoryAuditSink()
        service = build_service(sink=sink)
        service.authorize(ALICE, make_request(), now=NOW)
        review = only_open_review(service)
        before = len(sink.entries())

        service.resolve(review.approval_id, approve(review, approved=False), now=SOON)

        assert len(sink.entries()) > before, "a decline left no trace in the audit trail"

    def test_a_malformed_answer_does_not_cancel_the_review(self) -> None:
        """A digest mismatch is a wrong answer, not a decline: the review stays
        open for a correct one, so a malformed answer cannot cancel a pending
        review."""
        service = build_service()
        service.authorize(ALICE, make_request(), now=NOW)
        review = only_open_review(service)

        wrong = CheckerVerdict(
            checker=CHECKER,
            approval_id=review.approval_id,
            proposal=review.approval.proposal.model_copy(update={"value": "0" * 64}),
            approved=True,
        )
        resolution = service.resolve(review.approval_id, wrong, now=SOON)

        assert resolution.status is ReviewOutcomeStatus.rejected
        assert len(service.open_reviews()) == 1, "a malformed answer cancelled a pending review"
