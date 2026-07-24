# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Fixtures for the red-team matrix — the attacker's toolkit.

These assemble the same path the e2e tests do, but the tests that use them try
to *defeat* it: replay an approval, structure a payment under a limit, reach the
control plane, self-approve. Each attack asserts the system fails closed.
"""

from datetime import datetime, timedelta, timezone

from secondsign.approval import (
    CheckerIdentity,
    CheckerVerdict,
    Grant,
    MakerChecker,
    MakerIdentity,
)
from secondsign.contracts import (
    Currency,
    Finding,
    RailClass,
    ReasonCode,
    Reversibility,
    SourceTrust,
)
from secondsign.decision import Decision, DecisionEngine, DecisionVerdict
from secondsign.gateway import (
    ExecutionGateway,
    ExecutionStatus,
    InMemoryIdempotencyStore,
    RailResult,
)
from secondsign.intent import (
    DecisionDimensions,
    PaymentPayload,
    PaymentTargetKind,
    SettlementPriority,
    TransactionIntent,
    compute_digest,
)
from secondsign.policy import (
    AggregateKey,
    AmountLimit,
    AmountWindowPolicy,
    PolicyContext,
    WindowAggregate,
)

_EPOCH = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
NOT_AFTER = _EPOCH + timedelta(minutes=5)
NOW = _EPOCH + timedelta(minutes=1)
FINGERPRINT_A = "fp:" + "a1" * 32
FINGERPRINT_B = "fp:" + "b2" * 32
WINDOW = 3_600

MAKER = MakerIdentity(subject="agent")
CHECKER = CheckerIdentity(subject="human")


def make_intent(amount: int = 5_000, idempotency_key: str = "idem-rt") -> TransactionIntent:
    dimensions = DecisionDimensions(
        value_lower_minor=amount,
        value_upper_minor=amount,
        quote_currency=Currency.USD,
        counterparty_ref=FINGERPRINT_A,
        source_account_ref=FINGERPRINT_B,
        rail_class=RailClass.card,
        not_before=_EPOCH,
        not_after=NOT_AFTER,
        reversibility=Reversibility.irreversible,
        source_trust=SourceTrust.trusted_instruction,
        scope_count=1,
    )
    payload = PaymentPayload(
        target_kind=PaymentTargetKind.bank_account,
        new_beneficiary=False,
        cross_border=False,
        settlement_priority=SettlementPriority.standard,
    )
    return TransactionIntent(
        dimensions=dimensions, payload=payload, idempotency_key=idempotency_key
    )


def review_decision(intent: TransactionIntent) -> Decision:
    return Decision(
        verdict=DecisionVerdict.REVIEW,
        digest=compute_digest(intent),
        findings=(Finding(code=ReasonCode.new_counterparty),),
    )


def allow_decision(intent: TransactionIntent) -> Decision:
    return Decision(verdict=DecisionVerdict.ALLOW, digest=compute_digest(intent))


def grant_for(intent: TransactionIntent, approval_id: str = "appr-rt") -> Grant:
    return Grant(approval_id=approval_id, digest=compute_digest(intent), checker=CHECKER)


def verdict_for(pending, checker: CheckerIdentity = CHECKER) -> CheckerVerdict:
    return CheckerVerdict(checker=checker, digest=pending.digest, approved=True)


class CountingExecutor:
    """Records every dispatch so a double-spend is visible as call count > 1."""

    rail_class = RailClass.card

    def __init__(self, status: ExecutionStatus = ExecutionStatus.success) -> None:
        self._status = status
        self.dispatched: list[str] = []

    def dispatch(self, intent: TransactionIntent) -> RailResult:
        self.dispatched.append(intent.idempotency_key)
        return RailResult(status=self._status, reference="rail-ref")


def fresh_gateway(executor: CountingExecutor) -> ExecutionGateway:
    return ExecutionGateway(executor, InMemoryIdempotencyStore())


def new_maker_checker() -> MakerChecker:
    return MakerChecker()


def amount_context(intent: TransactionIntent, recent_minor: int = 0) -> PolicyContext:
    return PolicyContext(
        window_aggregate=WindowAggregate(
            key=AggregateKey.from_intent(intent),
            window_seconds=WINDOW,
            aggregate_minor=recent_minor,
            count=0,
        )
    )


def amount_engine(cap: int = 1_000_000) -> DecisionEngine:
    return DecisionEngine(
        [
            AmountWindowPolicy(
                AmountLimit(
                    quote_currency=Currency.USD, window_seconds=WINDOW, max_aggregate_minor=cap
                )
            )
        ]
    )
