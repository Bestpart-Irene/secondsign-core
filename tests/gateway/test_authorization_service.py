# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The assembly behind `/authorize`: a wire request becomes a decided action.

This is where the decision path stops being a library and starts being a
service. What is asserted here is the seam, not the components — each of those
has its own suite — so the cases are about the things only the assembly can get
wrong: what it fills in for facts the agent did not supply, what it refuses to
map at all, how one workload's idempotency handle is kept out of another's, and
what an agent is told versus what the ledger records.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from secondsign.agent.surface import AgentOutcomeStatus, AuthorizationRequest
from secondsign.audit import AuditLog, InMemoryAuditSink, verify_chain
from secondsign.contracts import (
    ActionClass,
    Currency,
    RailClass,
    ReasonCode,
    Reversibility,
    SourceTrust,
)
from secondsign.controlplane.fingerprint import FingerprintKey
from secondsign.controlplane.window import WindowLedger
from secondsign.decision import DecisionEngine, DecisionVerdict
from secondsign.gateway import (
    ExecutionGateway,
    ExecutionStatus,
    InMemoryIdempotencyStore,
    RailResult,
)
from secondsign.gateway.authorization import (
    AuthorizationService,
    UnmappableAction,
    complete_intent,
)
from secondsign.intent import PaymentTargetKind, SettlementPriority
from secondsign.policy import AmountLimit, AmountWindowPolicy

NOW = datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc)

ALICE = "spiffe://secondsign.example/agent/alice"
BOB = "spiffe://secondsign.example/agent/bob"

FP_A = "fp:" + "a1" * 32
FP_B = "fp:" + "b2" * 32
FP_REF = "fp:" + "c3" * 32


def make_request(**overrides) -> AuthorizationRequest:
    fields = {
        "action": ActionClass.payment,
        "rail": RailClass.card,
        "currency": Currency.USD,
        "amount_minor": 4_200,
        "reversibility": Reversibility.reversible,
        "counterparty_ref": FP_A,
        "source_account_ref": FP_B,
        "request_ref": FP_REF,
    }
    fields.update(overrides)
    return AuthorizationRequest(**fields)


class RecordingExecutor:
    """A rail executor that records what it was asked to dispatch."""

    def __init__(self, status: ExecutionStatus = ExecutionStatus.success) -> None:
        self.status = status
        self.dispatched: list[object] = []

    def dispatch(self, intent):
        self.dispatched.append(intent)
        return RailResult(status=self.status, reference="rail-ref-1")


def build_service(
    *,
    executor: RecordingExecutor | None = None,
    max_aggregate_minor: int = 100_000,
    sink: InMemoryAuditSink | None = None,
) -> AuthorizationService:
    limit = AmountLimit(
        quote_currency=Currency.USD,
        window_seconds=3600,
        max_aggregate_minor=max_aggregate_minor,
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
    )


# --- what the gateway fills in, and why it is the strictest value ------------


class TestTheGatewayCompletesWhatTheAgentDidNotSay:
    """The wire carries less than a decision needs. Every gap closes strictest."""

    def test_provenance_is_untrusted_because_the_wire_carries_none(self) -> None:
        intent = complete_intent(make_request(), idempotency_key="k", now=NOW)

        assert intent.dimensions.source_trust is SourceTrust.untrusted_data

    def test_the_agents_reversibility_claim_can_only_tighten(self) -> None:
        """A caller asserting `reversible` does not make an action reversible.

        The claim is combined toward strictness rather than ignored: an
        accepted-and-discarded field is one a later change can quietly start
        honouring, and the direction of that honouring must already be fixed.
        """
        claimed_loose = complete_intent(
            make_request(reversibility=Reversibility.reversible), idempotency_key="k", now=NOW
        )

        assert claimed_loose.dimensions.reversibility is Reversibility.irreversible

    def test_the_value_band_is_the_settled_amount(self) -> None:
        intent = complete_intent(make_request(amount_minor=4_200), idempotency_key="k", now=NOW)

        assert intent.dimensions.value_lower_minor == 4_200
        assert intent.dimensions.value_upper_minor == 4_200

    def test_the_window_opens_now_and_is_bounded(self) -> None:
        intent = complete_intent(make_request(), idempotency_key="k", now=NOW)

        assert intent.dimensions.not_before == NOW
        assert NOW < intent.dimensions.not_after <= NOW + timedelta(hours=1)

    def test_the_payment_payload_assumes_the_riskier_shape(self) -> None:
        intent = complete_intent(make_request(), idempotency_key="k", now=NOW)

        assert intent.payload.new_beneficiary is True
        assert intent.payload.cross_border is True
        assert intent.payload.settlement_priority is SettlementPriority.standard

    @pytest.mark.parametrize(
        ("rail", "target"),
        [
            (RailClass.card, PaymentTargetKind.card),
            (RailClass.bank_transfer, PaymentTargetKind.bank_account),
            (RailClass.wallet, PaymentTargetKind.wallet),
        ],
    )
    def test_the_target_kind_follows_the_rail_class(self, rail, target) -> None:
        intent = complete_intent(make_request(rail=rail), idempotency_key="k", now=NOW)

        assert intent.payload.target_kind is target

    def test_the_idempotency_key_is_carried_not_derived_here(self) -> None:
        """The key namespaces a principal, and this function never sees one."""
        intent = complete_intent(make_request(), idempotency_key="reservation-1", now=NOW)

        assert intent.idempotency_key == "reservation-1"


class TestWhatWireVersionOneCannotExpress:
    """Refused, never approximated. An intent nobody could execute faithfully is
    worse than an honest refusal."""

    def test_a_trade_needs_fields_the_wire_does_not_carry(self) -> None:
        with pytest.raises(UnmappableAction):
            complete_intent(
                make_request(action=ActionClass.trade, rail=RailClass.brokerage),
                idempotency_key="k",
                now=NOW,
            )

    def test_an_account_change_moves_no_value(self) -> None:
        with pytest.raises(UnmappableAction):
            complete_intent(
                make_request(action=ActionClass.account_change), idempotency_key="k", now=NOW
            )

    def test_an_unclassified_rail_has_no_payment_target(self) -> None:
        with pytest.raises(UnmappableAction):
            complete_intent(make_request(rail=RailClass.other), idempotency_key="k", now=NOW)

    def test_the_service_answers_refused_rather_than_raising(self) -> None:
        service = build_service()

        outcome = service.authorize(ALICE, make_request(action=ActionClass.account_change), now=NOW)

        assert outcome.status is AgentOutcomeStatus.refused
        assert ReasonCode.org_policy in outcome.reasons


# --- the three verdicts, end to end ------------------------------------------


class TestTheVerdictsReachTheAgent:
    def test_an_allowed_payment_is_dispatched_and_reads_completed(self) -> None:
        executor = RecordingExecutor()
        service = build_service(executor=executor)

        outcome = service.authorize(ALICE, make_request(), now=NOW)

        assert outcome.status is AgentOutcomeStatus.completed
        assert len(executor.dispatched) == 1
        assert executor.dispatched[0].dimensions.value_upper_minor == 4_200

    def test_a_denial_is_refused_and_nothing_is_dispatched(self) -> None:
        executor = RecordingExecutor()
        service = build_service(executor=executor, max_aggregate_minor=1_000)

        outcome = service.authorize(ALICE, make_request(amount_minor=5_000), now=NOW)

        assert outcome.status is AgentOutcomeStatus.refused
        assert ReasonCode.value_band_exceeded in outcome.reasons
        assert executor.dispatched == []

    def test_an_execution_failure_reads_refused(self) -> None:
        service = build_service(executor=RecordingExecutor(ExecutionStatus.failure))

        outcome = service.authorize(ALICE, make_request(), now=NOW)

        assert outcome.status is AgentOutcomeStatus.refused

    def test_an_unknown_execution_reads_refused_and_records_unknown(self) -> None:
        """The agent is told the least it can safely act on; the ledger keeps
        the distinction. `unknown` is not failure — money may have moved — but
        it is certainly not a completion an agent may build on."""
        sink = InMemoryAuditSink()
        service = build_service(executor=RecordingExecutor(ExecutionStatus.unknown), sink=sink)

        outcome = service.authorize(ALICE, make_request(), now=NOW)

        assert outcome.status is AgentOutcomeStatus.refused
        assert sink.entries()[-1].outcome_status is ExecutionStatus.unknown

    def test_the_outcome_carries_no_rail_reference(self) -> None:
        service = build_service()

        outcome = service.authorize(ALICE, make_request(), now=NOW)

        assert "rail-ref-1" not in outcome.model_dump_json()


# --- idempotency, namespaced by the authenticated principal ------------------


class TestTheIdempotencyNamespaceIsNotTheAgentsToChoose:
    def test_the_same_handle_from_one_principal_dispatches_once(self) -> None:
        executor = RecordingExecutor()
        service = build_service(executor=executor)
        request = make_request()

        first = service.authorize(ALICE, request, now=NOW)
        second = service.authorize(ALICE, request, now=NOW)

        assert first.status is AgentOutcomeStatus.completed
        assert second.status is AgentOutcomeStatus.completed
        assert len(executor.dispatched) == 1, "a retried proposal was executed twice"

    def test_a_retry_one_second_later_is_the_same_proposal(self) -> None:
        """The clock is not part of the proposal.

        The case above passes the same `now` twice, which is the one condition
        under which the intent digests match — `complete_intent` derives the
        validity window from `now`, so in a running process every retry lands on
        a different digest and is refused as a *different proposal*. A retry an
        agent actually makes is a second later, not in the same microsecond.
        """
        executor = RecordingExecutor()
        service = build_service(executor=executor)
        request = make_request()

        first = service.authorize(ALICE, request, now=NOW)
        second = service.authorize(ALICE, request, now=NOW + timedelta(seconds=1))

        assert first.status is AgentOutcomeStatus.completed
        assert second.status is AgentOutcomeStatus.completed, (
            "an identical proposal re-sent under the same handle was refused as a "
            "different one — the reservation binds a digest that contains the clock"
        )
        assert len(executor.dispatched) == 1

    def test_a_retry_does_not_consume_the_window_twice(self) -> None:
        """One dispatch, one deduction.

        The retry is de-duplicated at the idempotency store, which hands back
        the recorded outcome — and the service then records that outcome's value
        against the trailing window a second time. It fails closed, so it hides:
        the agent simply has less limit than it spent. The third request is what
        makes the difference observable, and it is sized so that it fits under
        one deduction and not under two.
        """
        executor = RecordingExecutor()
        service = build_service(executor=executor, max_aggregate_minor=8_500)
        request = make_request(amount_minor=4_200)

        service.authorize(ALICE, request, now=NOW)
        service.authorize(ALICE, request, now=NOW)
        outcome = service.authorize(
            ALICE, make_request(amount_minor=1_000, request_ref=FP_A), now=NOW
        )

        assert len(executor.dispatched) == 2
        assert outcome.status is AgentOutcomeStatus.completed, (
            "4,200 was deducted twice for one dispatch, so 4,200 + 1,000 read as "
            "9,400 against a limit of 8,500"
        )

    def test_a_retry_is_answered_from_the_record_rather_than_re_decided(self) -> None:
        """An agent asking "did that go through?" must not be told a new answer.

        Re-deciding a settled action asks the policy a question whose answer has
        already changed *because of that action*: the first dispatch is in the
        trailing window, so the second evaluation sees its own spend and denies.
        The agent is told `refused` for a payment that completed — the one
        answer that is neither true nor safe to act on.
        """
        executor = RecordingExecutor()
        service = build_service(executor=executor, max_aggregate_minor=5_000)
        request = make_request(amount_minor=4_200)

        first = service.authorize(ALICE, request, now=NOW)
        second = service.authorize(ALICE, request, now=NOW)

        assert first.status is AgentOutcomeStatus.completed
        assert second.status is AgentOutcomeStatus.completed, (
            "the retry was re-decided against a window its own dispatch had "
            "already filled, so a completed payment read as refused"
        )
        assert len(executor.dispatched) == 1

    def test_two_principals_choosing_the_same_handle_do_not_collide(self) -> None:
        """The red-team case the manifest names: one workload must not be able
        to consume or block another's reservation by choosing its request_ref."""
        executor = RecordingExecutor()
        service = build_service(executor=executor)
        request = make_request()

        service.authorize(ALICE, request, now=NOW)
        outcome = service.authorize(BOB, request, now=NOW)

        assert outcome.status is AgentOutcomeStatus.completed
        assert len(executor.dispatched) == 2, (
            "Bob's payment reused Alice's reservation — one workload silently "
            "consumed another's, which is a denial of service at best and a "
            "stolen outcome at worst"
        )

    def test_one_handle_cannot_be_reused_for_a_different_proposal(self) -> None:
        """The digest is bound to the reservation, so the same handle carrying a
        different amount is refused rather than answered with the first
        outcome — and certainly rather than executed."""
        executor = RecordingExecutor()
        service = build_service(executor=executor)

        service.authorize(ALICE, make_request(amount_minor=1_000), now=NOW)
        outcome = service.authorize(ALICE, make_request(amount_minor=9_000), now=NOW)

        assert outcome.status is AgentOutcomeStatus.refused
        assert len(executor.dispatched) == 1

    def test_the_reservation_key_does_not_contain_the_handle_the_agent_chose(self) -> None:
        executor = RecordingExecutor()
        service = build_service(executor=executor)

        service.authorize(ALICE, make_request(), now=NOW)

        key = executor.dispatched[0].idempotency_key
        assert FP_REF not in key
        assert ALICE not in key


# --- what the ledger records -------------------------------------------------


class TestTheAuditTrail:
    def test_every_decided_request_leaves_a_chained_receipt(self) -> None:
        sink = InMemoryAuditSink()
        service = build_service(sink=sink, max_aggregate_minor=5_000)

        service.authorize(ALICE, make_request(amount_minor=1_000), now=NOW)
        service.authorize(ALICE, make_request(amount_minor=9_000, request_ref=FP_A), now=NOW)

        assert len(sink.entries()) == 2
        assert verify_chain(sink.entries())
        assert sink.entries()[0].verdict is DecisionVerdict.ALLOW
        assert sink.entries()[1].verdict is DecisionVerdict.DENY

    def test_the_receipt_carries_a_keyed_fingerprint_of_the_principal(self) -> None:
        sink = InMemoryAuditSink()
        service = build_service(sink=sink)

        service.authorize(ALICE, make_request(), now=NOW)

        receipt = sink.entries()[-1]
        assert receipt.principal_ref is not None
        assert receipt.principal_ref.startswith("fp:")

    def test_the_raw_san_is_nowhere_in_the_trail(self) -> None:
        sink = InMemoryAuditSink()
        service = build_service(sink=sink)

        service.authorize(ALICE, make_request(), now=NOW)

        rendered = sink.entries()[-1].model_dump_json()
        assert ALICE not in rendered
        assert "alice" not in rendered

    def test_two_principals_fingerprint_differently(self) -> None:
        sink = InMemoryAuditSink()
        service = build_service(sink=sink)

        service.authorize(ALICE, make_request(), now=NOW)
        service.authorize(BOB, make_request(), now=NOW)

        first, second = sink.entries()
        assert first.principal_ref != second.principal_ref


# --- the windowed aggregate is what stops a split payment --------------------


class TestSpendAccumulates:
    def test_a_limit_cannot_be_evaded_by_splitting(self) -> None:
        executor = RecordingExecutor()
        service = build_service(executor=executor, max_aggregate_minor=10_000)

        for index in range(3):
            service.authorize(
                ALICE,
                make_request(amount_minor=4_000, request_ref=f"fp:{index:02d}" + "0" * 62),
                now=NOW,
            )

        assert len(executor.dispatched) == 2, (
            "three 4000-unit payments against a 10000 window limit: the third "
            "must be denied on the aggregate, not judged alone"
        )

    def test_spend_outside_the_window_no_longer_counts(self) -> None:
        executor = RecordingExecutor()
        service = build_service(executor=executor, max_aggregate_minor=10_000)

        service.authorize(ALICE, make_request(amount_minor=9_000), now=NOW)
        later = NOW + timedelta(hours=2)
        service.authorize(ALICE, make_request(amount_minor=9_000, request_ref=FP_A), now=later)

        assert len(executor.dispatched) == 2

    def test_an_indeterminate_dispatch_still_consumes_the_limit(self) -> None:
        """`unknown` means money may have moved. Not counting it would let an
        agent spend the window twice by arranging for the first answer to be
        ambiguous."""
        executor = RecordingExecutor(ExecutionStatus.unknown)
        service = build_service(executor=executor, max_aggregate_minor=10_000)

        service.authorize(ALICE, make_request(amount_minor=9_000), now=NOW)
        outcome = service.authorize(
            ALICE, make_request(amount_minor=9_000, request_ref=FP_A), now=NOW
        )

        assert outcome.status is AgentOutcomeStatus.refused
        assert ReasonCode.value_band_exceeded in outcome.reasons

    def test_a_denied_request_does_not_consume_the_limit(self) -> None:
        executor = RecordingExecutor()
        service = build_service(executor=executor, max_aggregate_minor=10_000)

        service.authorize(ALICE, make_request(amount_minor=99_000), now=NOW)
        outcome = service.authorize(
            ALICE, make_request(amount_minor=9_000, request_ref=FP_A), now=NOW
        )

        assert outcome.status is AgentOutcomeStatus.completed


class HoldsEverything:
    """A policy that raises a concern without denying — the shape a real
    compliance or counterparty rule takes."""

    def evaluate(self, intent, context):
        from secondsign.contracts import Finding, PluginJudgement, PluginVerdict

        return PluginJudgement(
            verdict=PluginVerdict.REVIEW,
            findings=(Finding(code=ReasonCode.new_counterparty),),
        )


class TestAReviewIsHeld:
    """`awaiting_review` is the one status where nothing has happened and
    nothing has been refused — and the one an agent must not read as either."""

    def _service(self, executor: RecordingExecutor, sink: InMemoryAuditSink):
        limit = AmountLimit(
            quote_currency=Currency.USD, window_seconds=3600, max_aggregate_minor=100_000
        )
        return AuthorizationService(
            engine=DecisionEngine([AmountWindowPolicy(limit), HoldsEverything()]),
            gateway=ExecutionGateway(executor, InMemoryIdempotencyStore()),
            ledger=WindowLedger(window_seconds=limit.window_seconds),
            audit=AuditLog(sink),
            keys=FingerprintKey.generate(),
        )

    def test_a_review_reaches_the_agent_as_awaiting_review(self) -> None:
        outcome = self._service(RecordingExecutor(), InMemoryAuditSink()).authorize(
            ALICE, make_request(), now=NOW
        )

        assert outcome.status is AgentOutcomeStatus.awaiting_review
        assert ReasonCode.new_counterparty in outcome.reasons

    def test_nothing_is_dispatched_while_a_human_has_not_decided(self) -> None:
        executor = RecordingExecutor()

        self._service(executor, InMemoryAuditSink()).authorize(ALICE, make_request(), now=NOW)

        assert executor.dispatched == []

    def test_a_held_action_consumes_no_limit(self) -> None:
        """Nothing moved, so nothing is spent. Counting a review against the
        window would let an agent exhaust its own limit by proposing actions it
        never intends to have approved — and would make the limit a measure of
        proposals rather than of money."""
        sink = InMemoryAuditSink()

        self._service(RecordingExecutor(), sink).authorize(ALICE, make_request(), now=NOW)

        receipt = sink.entries()[-1]
        assert receipt.verdict is DecisionVerdict.REVIEW
        assert receipt.outcome_status is None
