# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""What happens between an authenticated request and an answer.

Every component of the decision path already exists and each is tested on its
own. This module is the seam: it takes the workload identity the TLS session
produced and the proposal the wire carried, and it drives intent → decision →
execution → audit → outcome. Nothing here re-decides anything; what it does is
decide *what the pieces are given*, and that turns out to be where the security
properties of a service live.

**The wire carries less than a decision needs, and every gap closes strictest.**
An agent tells the gateway what it wants to move and to whom, as opaque
references. It does not tell it the provenance of the instruction, how many
entities the action touches, or whether the beneficiary is new — and it must not,
because those are exactly the facts an agent under prompt injection would like to
choose. So they are not read from the request: provenance is `untrusted_data`, the
beneficiary is new, the payment is cross-border. The agent's one factual claim
that does appear on the wire, `reversibility`, is combined *toward* strictness
rather than used, so a caller asserting `reversible` cannot make an action
reversible. That direction is fixed in code rather than in a comment, because a
field accepted and discarded is one a later change can quietly start honouring.

**What wire v1 cannot express is refused, not approximated.** A trade needs a
symbol, a side and a quantity; the wire carries none of them. An account change
moves no value and has no payment payload. An unclassified rail has no payment
target. Each is an :class:`UnmappableAction`, surfaced to the agent as a refusal.
Deriving a plausible-looking intent from a request that did not contain one would
put a decision behind a value nobody proposed.

**The idempotency namespace is not the agent's to choose.** The reservation key
is derived from the authenticated principal and the agent's `request_ref`
together, so two workloads that pick the same handle cannot collide — neither by
accident nor by an agent choosing a handle it has watched another workload use.
And the reservation is bound to the digest of the proposal it was made for: the
same handle carrying a *different* proposal is refused rather than answered with
the first one's outcome, because "here is my retry" and "here is something else
under the same name" are different statements and only one of them is a retry.

**The agent is told less than the ledger records.** An indeterminate dispatch —
money may or may not have moved — reads as `refused` at the boundary, because
there is no fourth status and `completed` would be a lie an agent could build on.
The receipt records `unknown`, which is the distinction that matters for
reconciliation, and it records it against a keyed fingerprint of the principal
rather than the raw SAN.

**An answer is given once and then repeated.** A reservation holds the answer it
produced, and a re-sent proposal reads it back rather than being decided again.
This is not a cache. Re-deciding a settled action asks the policy a question
whose answer has already changed *because of that action* — the first dispatch
is in the trailing window, so the second evaluation sees its own spend — and an
agent asking "did that go through?" would be told `refused` about a payment that
completed. What makes the repeat safe is that the reservation binds the
*proposal* digest: a retry a second later is the same proposal, and the same
handle carrying different material is still refused.

**A review is held, not answered.** `REVIEW` puts the proposal in the
control-plane pending store and moves nothing. When a checker approves, the
intent is re-completed from the stored proposal with a fresh window and
re-decided — because the human's answer is not a permission slip that outranks a
limit — and the grant, which binds the proposal rather than the intent, is what
lets the window have moved while nothing else did (ADR 0005).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict

from secondsign.agent.surface import (
    AgentOutcomeStatus,
    AuthorizationOutcome,
    AuthorizationRequest,
)
from secondsign.approval import (
    CheckerVerdict,
    Grant,
    MakerChecker,
    MakerIdentity,
    Rejected,
    RejectionReason,
)
from secondsign.audit import AuditLog
from secondsign.contracts import (
    ActionClass,
    Currency,
    RailClass,
    ReasonCode,
    Reversibility,
    SourceTrust,
)
from secondsign.controlplane.fingerprint import (
    APPROVAL_DOMAIN,
    DECISION_DOMAIN,
    MAKER_DOMAIN,
    PRINCIPAL_DOMAIN,
    FingerprintKey,
)
from secondsign.controlplane.pending import (
    InMemoryPendingStore,
    PendingReview,
    PendingStore,
)
from secondsign.controlplane.window import WindowLedger
from secondsign.decision import Decision, DecisionEngine, DecisionVerdict
from secondsign.gateway.execution import (
    ExecutionGateway,
    ExecutionOutcome,
    ExecutionStatus,
)
from secondsign.intent import (
    DecisionDimensions,
    IntentDigest,
    PaymentPayload,
    PaymentTargetKind,
    ProposalDigest,
    SettlementPriority,
    TransactionIntent,
    compute_digest,
    compute_proposal_digest,
)
from secondsign.policy import AggregateKey, PolicyContext

#: How long an authorization stays executable. Short, because the window is
#: re-verified at dispatch and a long one is a replay opportunity; non-zero,
#: because the decision and the dispatch are not the same instant.
INTENT_TTL: Final[timedelta] = timedelta(minutes=5)

#: How long a held review stays answerable. Long enough that a human in another
#: timezone can answer within a working day, short enough that an approval left
#: unanswered dies rather than accumulating.
#:
#: A constant, deliberately not a setting. An operator who can extend an
#: approval's life by editing the gateway's environment is an operator whose
#: expiry is a suggestion — the same reasoning that keeps the reference
#: deployment's limits out of the environment.
REVIEW_TTL: Final[timedelta] = timedelta(hours=4)


class ReviewOutcomeStatus(StrEnum):
    """What became of a checker's answer. Read by the approval channel, never
    by the agent — which learns only its own three states."""

    #: Approved, re-decided, and dispatched successfully.
    executed = "executed"
    #: Approved, and it did not run: the re-decision denied, the dispatch was
    #: refused, or the rail failed. The human's answer was not the problem.
    refused = "refused"
    #: The answer itself was not usable — expired, replayed, self-approved,
    #: bound to a different proposal, or a decline.
    rejected = "rejected"


class ReviewResolution(BaseModel):
    """The result of resolving one held review."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: ReviewOutcomeStatus
    #: Why the answer was not usable. Present only for `rejected`.
    reason: RejectionReason | None = None
    #: What the agent will read on its next poll, if the review settled.
    outcome: AuthorizationOutcome | None = None


#: Which rail class a payment lands on. Rails with no payment shape are absent
#: rather than mapped to a default: a missing entry is a refusal.
_TARGET_BY_RAIL: Final[dict[RailClass, PaymentTargetKind]] = {
    RailClass.card: PaymentTargetKind.card,
    RailClass.bank_transfer: PaymentTargetKind.bank_account,
    RailClass.wallet: PaymentTargetKind.wallet,
}

#: Actions that move value along a payment shape. `trade` needs a symbol and a
#: side; `account_change` moves nothing. Neither is expressible in wire v1.
_PAYMENT_ACTIONS: Final[frozenset[ActionClass]] = frozenset(
    {ActionClass.payment, ActionClass.refund, ActionClass.payout, ActionClass.transfer}
)

#: Strictness order for reversibility, strictest first — the enum's own
#: declaration order. Used only to check the direction a claim may move.
_REVERSIBILITY_ORDER: Final[tuple[Reversibility, ...]] = tuple(Reversibility)

#: What the gateway assumes when the wire says nothing. The strictest member of
#: the enum, taken from its declaration order rather than written out, so a
#: future member added below it is picked up here instead of being missed.
_STRICTEST_REVERSIBILITY: Final[Reversibility] = _REVERSIBILITY_ORDER[0]
_STRICTEST_TRUST: Final[SourceTrust] = tuple(SourceTrust)[0]


class UnmappableAction(Exception):
    """The proposal is well-formed and cannot become an intent.

    Not a validation error: the request parsed, the fields are in range, and the
    action it describes has no faithful representation in this contract version.
    An approximation would be a decision about something nobody proposed.
    """


def _strictest_reversibility(claimed: Reversibility) -> Reversibility:
    """The stricter of the gateway's default and what the agent claimed.

    Today the default is already the strictest member, so this always returns it.
    The function exists anyway, and is not inlined to a constant, because the
    invariant is *the claim may only tighten* — and when a later version derives
    a looser default from the rail, this is where that stays true.
    """
    return min(claimed, _STRICTEST_REVERSIBILITY, key=_REVERSIBILITY_ORDER.index)


def complete_intent(
    request: AuthorizationRequest, *, idempotency_key: str, now: datetime
) -> TransactionIntent:
    """Turn a wire proposal into the immutable intent a decision is made on.

    Raises :class:`UnmappableAction` for a proposal wire v1 cannot express. The
    idempotency key is passed in rather than derived here: it namespaces an
    authenticated principal, and this function is deliberately not given one.
    """
    if request.action not in _PAYMENT_ACTIONS:
        raise UnmappableAction(f"{request.action.value} is not a payment-shaped action")
    target_kind = _TARGET_BY_RAIL.get(request.rail)
    if target_kind is None:
        raise UnmappableAction(f"{request.rail.value} has no payment target kind")

    dimensions = DecisionDimensions(
        # A settled amount is a degenerate band. The band exists for rails that
        # do not settle at decision time; a payment is not one of them.
        value_lower_minor=request.amount_minor,
        value_upper_minor=request.amount_minor,
        quote_currency=Currency(request.currency.value),
        counterparty_ref=request.counterparty_ref,
        source_account_ref=request.source_account_ref,
        rail_class=RailClass(request.rail.value),
        not_before=now,
        not_after=now + INTENT_TTL,
        reversibility=_strictest_reversibility(Reversibility(request.reversibility.value)),
        # The wire has no provenance field, and that absence is not neutral: an
        # instruction whose origin nobody vouched for is untrusted (A4/B9).
        source_trust=_STRICTEST_TRUST,
        # One counterparty. A batch is not expressible on this wire, so claiming
        # a wider scope here would overstate what was proposed.
        scope_count=1,
    )
    payload = PaymentPayload(
        target_kind=target_kind,
        # Both assumed against the agent. A first payment to a counterparty and
        # a cross-border one are the two shapes a reviewer most wants to see, so
        # the gateway does not let silence turn them off.
        new_beneficiary=True,
        cross_border=True,
        settlement_priority=SettlementPriority.standard,
    )
    return TransactionIntent(
        dimensions=dimensions, payload=payload, idempotency_key=idempotency_key
    )


@dataclass(frozen=True)
class _Reservation:
    """What a handle was spent on, and what it was told.

    The digest held here is the **proposal** digest, not the intent digest. The
    intent digest contains the validity window, which is derived from the clock,
    so a retry one second later carries a different intent digest for a proposal
    that has not changed — binding the reservation to it would refuse every
    genuine retry as a different proposal and answer none of them.
    """

    proposal: ProposalDigest
    #: The answer this handle has already been given. Repeated verbatim on a
    #: re-send, so an agent's second question gets its first question's answer.
    answer: AuthorizationOutcome
    #: Set while a review is open under this handle; cleared when it resolves.
    approval_id: str | None = None


class AuthorizationService:
    """Drives one authorization from an authenticated principal to an outcome."""

    def __init__(
        self,
        *,
        engine: DecisionEngine,
        gateway: ExecutionGateway,
        ledger: WindowLedger,
        audit: AuditLog,
        keys: FingerprintKey,
        pending: PendingStore | None = None,
        maker_checker: MakerChecker | None = None,
    ) -> None:
        self._engine = engine
        self._gateway = gateway
        self._ledger = ledger
        self._audit = audit
        self._keys = keys
        # Defaulted rather than optional. A deployment that did not supply a
        # pending store still holds its reviews: the alternative is a REVIEW
        # verdict silently dropped, which reads to the agent exactly like a
        # review that no human will ever see — and is one.
        self._pending = pending if pending is not None else InMemoryPendingStore()
        self._maker_checker = maker_checker if maker_checker is not None else MakerChecker()
        self._reservations: dict[str, _Reservation] = {}
        # The gateway process serves on threads (`ThreadingHTTPServer`), so one
        # service answers many requests at once. Deciding reads the spend window
        # and dispatching records back to it, and between those two the window
        # must not move: two proposals that both read "nothing spent" and both
        # dispatch would each be within the cap while their sum is not. The
        # reservation guards a *repeat* of one handle; nothing but this guards
        # the window against *distinct* handles arriving together.
        #
        # It is held across dispatch on purpose, and that is a throughput
        # statement as much as a correctness one: every authorization in the
        # process serialises through here, including refusals that never touch
        # the rail, and a slow rail call holds the line for everyone behind it.
        # The reference stores are in-memory (INV-12 / CORE-S017), so this
        # process's memory is the only correct place to serialise them and the
        # trade is right; a distributed control plane enforces the same
        # invariant with a conditional write on the durable store instead, and
        # holds no process-local lock across rail I/O.
        #
        # A plain Lock, not an RLock, and not defensively: no path re-acquires
        # it — `authorize` and `resolve` do not call each other and no helper
        # takes it — and if a future change introduces re-entry, deadlocking
        # immediately is the alarm; an RLock would let the mistake in quietly.
        self._lock = threading.Lock()
        # The clock this service decides against, never allowed to run backwards.
        # `now` is stamped per request in the handler thread before the lock is
        # taken, and the lock is not FIFO-fair, so a request with an earlier
        # stamp can acquire the lock after a later-stamped one already recorded
        # its spend. The window aggregate is bounded at `now`, so the
        # earlier-stamped decision would be blind to that spend and could
        # overspend the cap. Clamping every decision's clock up to a monotonic
        # floor means each one sees every spend recorded before it, whatever
        # order the stamps arrived in. Updated only under the lock.
        self._now_floor = datetime.min.replace(tzinfo=timezone.utc)

    def authorize(
        self, principal: str, request: AuthorizationRequest, *, now: datetime
    ) -> AuthorizationOutcome:
        """The whole path, for one request from one authenticated workload."""
        principal_ref = self._keys.fingerprint(PRINCIPAL_DOMAIN, principal)
        reservation_key = self._keys.fingerprint(
            PRINCIPAL_DOMAIN, f"{principal}\x00{request.request_ref}"
        )

        try:
            intent = complete_intent(request, idempotency_key=reservation_key, now=now)
        except UnmappableAction:
            # No intent means no digest, so there is nothing to chain a receipt
            # to. The refusal is real and the ledger does not record it — worth
            # knowing when reading the trail: it holds decided actions, not
            # every message the process received.
            return self._refuse(reservation_key, now)

        proposal = compute_proposal_digest(intent)
        with self._lock:
            # The clock may not run backwards: a decision reads the window as of
            # `now`, so a `now` behind a spend already recorded would not see it.
            now = self._now_floor = max(now, self._now_floor)
            held = self._reservations.get(reservation_key)
            if held is not None:
                if held.proposal != proposal:
                    # The same handle, a different proposal. Answering with the
                    # first outcome would tell the agent something happened to
                    # *this* request that did not; executing would honour a
                    # handle that is already spent. Refusing is the only true
                    # statement.
                    return self._refuse(reservation_key, now, digest=compute_digest(intent))
                # The same proposal again. Repeat the answer rather than deciding
                # again: the state the policy would read now includes this
                # action's own effect, so a second decision answers a different
                # question.
                return held.answer

            decision = self._decide(intent, now=now)
            if decision.verdict is DecisionVerdict.REVIEW:
                return self._hold(
                    request,
                    intent,
                    decision,
                    proposal,
                    reservation_key=reservation_key,
                    principal_ref=principal_ref,
                    now=now,
                )
            if decision.verdict is not DecisionVerdict.ALLOW:
                return self._settle(
                    reservation_key, proposal, decision, principal_ref, now, outcome=None
                )

            result = self._dispatch(intent, decision, now=now)
            return self._settle(
                reservation_key, proposal, decision, principal_ref, now, outcome=result
            )

    def open_reviews(self) -> tuple[PendingReview, ...]:
        """Every review waiting for a human.

        Control-plane state, and the approval channel's window onto it. Nothing
        an agent can reach returns this — the managed agent's whole surface is
        one verb, and it is not this one.
        """
        return self._pending.open_reviews()

    def resolve(
        self, approval_id: str, verdict: CheckerVerdict, *, now: datetime
    ) -> ReviewResolution:
        """A checker's answer to a held review.

        The order of what follows is the design. The intent is re-completed from
        the *stored* proposal — never from anything the agent has sent since —
        and re-decided before the approval is consumed, so a limit that has
        filled up refuses the action without burning the human's answer. Only
        then is the one-shot spent, and only then does anything dispatch.
        """
        with self._lock:
            # Same window as `authorize`, and the same reason it is held across
            # dispatch: re-deciding reads the spend window, and two answers to
            # two reviews arriving together must not each see the other's spend
            # as absent. The one-shot consume also has to be atomic with the
            # get/release around it, or two calls answering one review could
            # both pass `get` before either releases.
            now = self._now_floor = max(now, self._now_floor)
            review = self._pending.get(approval_id)
            if review is None:
                return ReviewResolution(
                    status=ReviewOutcomeStatus.rejected,
                    reason=RejectionReason.unknown_approval,
                )

            intent = complete_intent(
                review.request, idempotency_key=review.reservation_key, now=now
            )
            proposal = compute_proposal_digest(intent)
            if proposal != review.approval.proposal:
                # Belt and braces: re-completion is deterministic in everything
                # but the window, so this cannot differ unless the completion
                # logic itself changed under a running deployment. It is checked
                # because it is the whole guarantee and it costs a comparison.
                return ReviewResolution(
                    status=ReviewOutcomeStatus.rejected,
                    reason=RejectionReason.digest_mismatch,
                )

            decision = self._decide(intent, now=now)
            if decision.verdict is DecisionVerdict.DENY:
                # Policy state moved while the human was thinking. An approval is
                # not a permission slip that outranks a limit — and the answer is
                # not spent, so it still executes once the window drains.
                self._audit.record(
                    digest=decision.digest,
                    verdict=decision.verdict,
                    reasons=decision.reasons,
                    outcome_status=None,
                    principal_ref=review.principal_ref,
                )
                return ReviewResolution(status=ReviewOutcomeStatus.refused)

            consumed = self._maker_checker.consume(review.approval, verdict, now=now)
            if isinstance(consumed, Rejected):
                return ReviewResolution(status=ReviewOutcomeStatus.rejected, reason=consumed.reason)

            result = self._dispatch(intent, decision, now=now, grant=consumed)
            outcome = self._settle(
                review.reservation_key,
                proposal,
                decision,
                review.principal_ref,
                now,
                outcome=result,
                approval_id=consumed.approval_id,
            )
            self._pending.release(approval_id)
            status = (
                ReviewOutcomeStatus.executed
                if outcome.status is AgentOutcomeStatus.completed
                else ReviewOutcomeStatus.refused
            )
            return ReviewResolution(status=status, outcome=outcome)

    def _decide(self, intent: TransactionIntent, *, now: datetime) -> Decision:
        aggregate = self._ledger.aggregate(AggregateKey.from_intent(intent), now=now)
        return self._engine.decide(intent, PolicyContext(window_aggregate=aggregate))

    def _dispatch(
        self,
        intent: TransactionIntent,
        decision: Decision,
        *,
        now: datetime,
        grant: Grant | None = None,
    ) -> object:
        result = self._gateway.execute(intent, decision, grant=grant, now=now)
        if isinstance(result, ExecutionOutcome) and result.status is not ExecutionStatus.failure:
            # Success, or an indeterminate dispatch that may have moved money.
            # Both consume the window: not counting `unknown` would let an agent
            # spend it twice by arranging for the first answer to be ambiguous.
            self._ledger.record(
                AggregateKey.from_intent(intent),
                amount_minor=intent.dimensions.value_upper_minor,
                at=now,
            )
        return result

    def _hold(
        self,
        request: AuthorizationRequest,
        intent: TransactionIntent,
        decision: Decision,
        proposal: ProposalDigest,
        *,
        reservation_key: str,
        principal_ref: str,
        now: datetime,
    ) -> AuthorizationOutcome:
        """Park a REVIEW where a human can reach it and an agent cannot.

        Nothing is dispatched and nothing is deducted. Counting a held review
        against the trailing window would let a stream of proposals no human
        ever answers exhaust an agent's limit.
        """
        approval_id = self._keys.fingerprint(APPROVAL_DOMAIN, reservation_key)
        approval = self._maker_checker.request(
            decision,
            # The workload that proposed the action is its maker. That is what
            # makes self-approval structurally impossible for it: a checker is a
            # different type, and this subject is a fingerprint of a machine.
            MakerIdentity(subject=self._keys.fingerprint(MAKER_DOMAIN, principal_ref)),
            approval_id=approval_id,
            proposal=proposal,
            expires_at=now + REVIEW_TTL,
        )
        self._pending.hold(
            PendingReview(
                approval_id=approval_id,
                reservation_key=reservation_key,
                principal_ref=principal_ref,
                request=request,
                approval=approval,
            )
        )
        answer = self._settle(reservation_key, proposal, decision, principal_ref, now, outcome=None)
        self._reservations[reservation_key] = _Reservation(
            proposal=proposal, answer=answer, approval_id=approval_id
        )
        return answer

    def _settle(
        self,
        reservation_key: str,
        proposal: ProposalDigest,
        decision: Decision,
        principal_ref: str,
        now: datetime,
        *,
        outcome: object,
        approval_id: str | None = None,
    ) -> AuthorizationOutcome:
        answer = self._record(
            decision, principal_ref, now, outcome=outcome, approval_id=approval_id
        )
        self._reservations[reservation_key] = _Reservation(proposal=proposal, answer=answer)
        return answer

    def _record(
        self,
        decision: Decision,
        principal_ref: str,
        now: datetime,
        *,
        outcome: object,
        approval_id: str | None = None,
    ) -> AuthorizationOutcome:
        status = outcome.status if isinstance(outcome, ExecutionOutcome) else None
        self._audit.record(
            digest=decision.digest,
            verdict=decision.verdict,
            reasons=decision.reasons,
            outcome_status=status,
            approval_id=approval_id,
            principal_ref=principal_ref,
        )
        return AuthorizationOutcome(
            status=_agent_status(decision.verdict, status, granted=approval_id is not None),
            # Opaque, and derived from the digest rather than from anything the
            # rail returned: a reference an agent can quote to a human must not
            # be a handle on the payment itself.
            decision_ref=self._keys.fingerprint(DECISION_DOMAIN, decision.digest.value),
            decided_at=now,
            reasons=decision.reasons,
        )

    def _refuse(
        self, reservation_key: str, now: datetime, *, digest: IntentDigest | None = None
    ) -> AuthorizationOutcome:
        """A refusal reached before any policy ran.

        `org_policy` because the reason vocabulary is frozen at CONTRACT_VERSION
        1 and holds no code for "this deployment cannot express your request".
        Inventing one is a contract change, and a refusal with a slightly broad
        reason is better than a contract that revs to explain itself.
        """
        material = digest.value if digest is not None else reservation_key
        return AuthorizationOutcome(
            status=AgentOutcomeStatus.refused,
            decision_ref=self._keys.fingerprint(DECISION_DOMAIN, material),
            decided_at=now,
            reasons=(ReasonCode.org_policy,),
        )


def _agent_status(
    verdict: DecisionVerdict,
    execution: ExecutionStatus | None,
    *,
    granted: bool = False,
) -> AgentOutcomeStatus:
    """What the agent is told, from what happened.

    `completed` has exactly one origin: a decision that permitted the action and
    a dispatch that is known to have succeeded. Everything else — a denial, a
    review, a refused dispatch, a failure, an indeterminate result — reads as
    one of the other two states, because there is no fourth status for
    uncertainty and an agent that could spot one would retry against it (INV-1).

    A `REVIEW` that has been granted is no longer awaiting one. The verdict on
    the receipt stays `REVIEW`, because that is what the engine decided and a
    receipt saying `ALLOW` would be false; what changes is that a human has
    since answered, and `granted` is that fact rather than a re-reading of the
    verdict.
    """
    if verdict is DecisionVerdict.REVIEW and not granted:
        return AgentOutcomeStatus.awaiting_review
    if execution is ExecutionStatus.success:
        return AgentOutcomeStatus.completed
    return AgentOutcomeStatus.refused
