# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures for the execution-gateway tests."""

from datetime import datetime, timedelta, timezone

from secondsign.approval import CheckerIdentity, Grant
from secondsign.contracts import Currency, RailClass, Reversibility, SourceTrust
from secondsign.decision import Decision, DecisionVerdict
from secondsign.gateway import (
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
    compute_proposal_digest,
)

_EPOCH = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
NOT_BEFORE = _EPOCH
NOT_AFTER = _EPOCH + timedelta(minutes=5)
NOW = _EPOCH + timedelta(minutes=1)  # inside the window
FINGERPRINT_A = "fp:" + "a1" * 32
FINGERPRINT_B = "fp:" + "b2" * 32
CHECKER = CheckerIdentity(subject="bob")


def make_intent(amount: int = 125_000, idempotency_key: str = "idem-0001") -> TransactionIntent:
    dimensions = DecisionDimensions(
        value_lower_minor=amount,
        value_upper_minor=amount,
        quote_currency=Currency.USD,
        counterparty_ref=FINGERPRINT_A,
        source_account_ref=FINGERPRINT_B,
        rail_class=RailClass.card,
        not_before=NOT_BEFORE,
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


def make_decision(intent: TransactionIntent, verdict: DecisionVerdict) -> Decision:
    return Decision(verdict=verdict, digest=compute_digest(intent))


def make_grant(intent: TransactionIntent) -> Grant:
    return Grant(approval_id="appr-1", proposal=compute_proposal_digest(intent), checker=CHECKER)


class FixedExecutor:
    """A rail executor that reports a fixed outcome. Records what it dispatched
    so tests can assert single-dispatch."""

    def __init__(self, status: ExecutionStatus, reference: str | None = "rail-ref") -> None:
        self._status = status
        self._reference = reference
        self.dispatched: list[str] = []

    def dispatch(self, intent: TransactionIntent) -> RailResult:
        self.dispatched.append(intent.idempotency_key)
        return RailResult(status=self._status, reference=self._reference)


def fresh_store() -> InMemoryIdempotencyStore:
    return InMemoryIdempotencyStore()
