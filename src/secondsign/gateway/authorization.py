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
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

from secondsign.agent.surface import (
    AgentOutcomeStatus,
    AuthorizationOutcome,
    AuthorizationRequest,
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
    DECISION_DOMAIN,
    PRINCIPAL_DOMAIN,
    FingerprintKey,
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
    SettlementPriority,
    TransactionIntent,
    compute_digest,
)
from secondsign.policy import AggregateKey, PolicyContext

#: How long an authorization stays executable. Short, because the window is
#: re-verified at dispatch and a long one is a replay opportunity; non-zero,
#: because the decision and the dispatch are not the same instant.
INTENT_TTL: Final[timedelta] = timedelta(minutes=5)

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
    """What a handle was spent on. Held so a reused handle can be told apart
    from a retry."""

    digest: IntentDigest


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
    ) -> None:
        self._engine = engine
        self._gateway = gateway
        self._ledger = ledger
        self._audit = audit
        self._keys = keys
        self._reservations: dict[str, _Reservation] = {}

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

        digest = compute_digest(intent)
        held = self._reservations.get(reservation_key)
        if held is not None and held.digest != digest:
            # The same handle, a different proposal. Answering with the first
            # outcome would tell the agent something happened to *this* request
            # that did not; executing would honour a handle that is already
            # spent. Refusing is the only statement that is true.
            return self._refuse(reservation_key, now, digest=digest)
        self._reservations[reservation_key] = _Reservation(digest=digest)

        aggregate_key = AggregateKey.from_intent(intent)
        decision = self._engine.decide(
            intent, PolicyContext(window_aggregate=self._ledger.aggregate(aggregate_key, now=now))
        )
        if decision.verdict is not DecisionVerdict.ALLOW:
            return self._record(decision, principal_ref, now, outcome=None)

        result = self._gateway.execute(intent, decision, now=now)
        if isinstance(result, ExecutionOutcome) and result.status is not ExecutionStatus.failure:
            # Success, or an indeterminate dispatch that may have moved money.
            # Both consume the window: not counting `unknown` would let an agent
            # spend it twice by arranging for the first answer to be ambiguous.
            self._ledger.record(
                aggregate_key, amount_minor=intent.dimensions.value_upper_minor, at=now
            )
        return self._record(decision, principal_ref, now, outcome=result)

    def _record(
        self,
        decision: Decision,
        principal_ref: str,
        now: datetime,
        *,
        outcome: object,
    ) -> AuthorizationOutcome:
        status = outcome.status if isinstance(outcome, ExecutionOutcome) else None
        self._audit.record(
            digest=decision.digest,
            verdict=decision.verdict,
            reasons=decision.reasons,
            outcome_status=status,
            principal_ref=principal_ref,
        )
        return AuthorizationOutcome(
            status=_agent_status(decision.verdict, status),
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
    verdict: DecisionVerdict, execution: ExecutionStatus | None
) -> AgentOutcomeStatus:
    """What the agent is told, from what happened.

    `completed` has exactly one origin: a decision that allowed and a dispatch
    that is known to have succeeded. Everything else — a denial, a review, a
    refused dispatch, a failure, an indeterminate result — reads as one of the
    other two states, because there is no fourth status for uncertainty and an
    agent that could spot one would retry against it (INV-1).
    """
    if verdict is DecisionVerdict.REVIEW:
        return AgentOutcomeStatus.awaiting_review
    if execution is ExecutionStatus.success:
        return AgentOutcomeStatus.completed
    return AgentOutcomeStatus.refused
