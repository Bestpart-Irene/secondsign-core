# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures for the maker-checker / approval tests."""

from datetime import datetime, timedelta, timezone

from secondsign.approval import (
    CheckerIdentity,
    CheckerVerdict,
    MakerChecker,
    MakerIdentity,
    PendingApproval,
)
from secondsign.contracts import (
    Currency,
    Finding,
    RailClass,
    ReasonCode,
    Reversibility,
    SourceTrust,
)
from secondsign.decision import Decision, DecisionVerdict
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
NOW = _EPOCH + timedelta(minutes=1)
EXPIRES_AT = _EPOCH + timedelta(minutes=10)
FINGERPRINT_A = "fp:" + "a1" * 32
FINGERPRINT_B = "fp:" + "b2" * 32

MAKER = MakerIdentity(subject="alice")
CHECKER = CheckerIdentity(subject="bob")


def make_intent(amount: int = 125_000) -> TransactionIntent:
    dimensions = DecisionDimensions(
        value_lower_minor=amount,
        value_upper_minor=amount,
        quote_currency=Currency.USD,
        counterparty_ref=FINGERPRINT_A,
        source_account_ref=FINGERPRINT_B,
        rail_class=RailClass.card,
        not_before=_EPOCH,
        not_after=_EPOCH + timedelta(minutes=5),
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
    return TransactionIntent(dimensions=dimensions, payload=payload, idempotency_key="idem-x")


def make_review_decision(intent: TransactionIntent | None = None) -> Decision:
    intent = intent if intent is not None else make_intent()
    return Decision(
        verdict=DecisionVerdict.REVIEW,
        digest=compute_digest(intent),
        findings=(Finding(code=ReasonCode.new_counterparty),),
    )


def make_pending(
    *,
    approval_id: str = "appr-0001",
    intent: TransactionIntent | None = None,
    decision: Decision | None = None,
    maker: MakerIdentity = MAKER,
    expires_at=EXPIRES_AT,
) -> PendingApproval:
    intent = intent if intent is not None else make_intent()
    return PendingApproval(
        approval_id=approval_id,
        decision=decision if decision is not None else make_review_decision(intent),
        proposal=compute_proposal_digest(intent),
        maker=maker,
        expires_at=expires_at,
    )


def approve(pending: PendingApproval, checker: CheckerIdentity = CHECKER) -> CheckerVerdict:
    return CheckerVerdict(
        checker=checker,
        approval_id=pending.approval_id,
        proposal=pending.proposal,
        approved=True,
    )


class AutoApproveProvider:
    """A deterministic provider that approves whatever it is shown, as the given
    checker. Real providers ask a human; this stands in for conformance."""

    def __init__(self, checker: CheckerIdentity = CHECKER) -> None:
        self._checker = checker

    def present(self, pending: PendingApproval) -> CheckerVerdict:
        return CheckerVerdict(
            checker=self._checker,
            approval_id=pending.approval_id,
            proposal=pending.proposal,
            approved=True,
        )


def fresh_maker_checker() -> MakerChecker:
    return MakerChecker()
