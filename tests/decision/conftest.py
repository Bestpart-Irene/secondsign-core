# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures for the decision-engine tests."""

from datetime import datetime, timedelta, timezone

from secondsign.contracts import (
    Currency,
    Finding,
    PluginJudgement,
    PluginVerdict,
    RailClass,
    ReasonCode,
    Reversibility,
    SourceTrust,
)
from secondsign.intent import (
    DecisionDimensions,
    PaymentPayload,
    PaymentTargetKind,
    SettlementPriority,
    TransactionIntent,
)
from secondsign.policy import PolicyContext

_EPOCH = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
FINGERPRINT_A = "fp:" + "a1" * 32
FINGERPRINT_B = "fp:" + "b2" * 32


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


EMPTY_CONTEXT = PolicyContext(window_aggregate=None)


class AbstainPolicy:
    def evaluate(self, intent, context) -> PluginJudgement:
        return PluginJudgement(verdict=PluginVerdict.ABSTAIN)


class ReviewPolicy:
    def __init__(self, code: ReasonCode = ReasonCode.new_counterparty) -> None:
        self.code = code

    def evaluate(self, intent, context) -> PluginJudgement:
        return PluginJudgement(verdict=PluginVerdict.REVIEW, findings=(Finding(code=self.code),))


class DenyPolicy:
    def __init__(self, code: ReasonCode = ReasonCode.org_policy) -> None:
        self.code = code

    def evaluate(self, intent, context) -> PluginJudgement:
        return PluginJudgement(verdict=PluginVerdict.DENY, findings=(Finding(code=self.code),))


class ExplodingPolicy:
    def evaluate(self, intent, context) -> PluginJudgement:
        raise RuntimeError("policy failure fixture")
