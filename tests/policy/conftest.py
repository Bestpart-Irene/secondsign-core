# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures for the amount-policy tests."""

from datetime import datetime, timedelta, timezone

from secondsign.contracts import Currency, RailClass, Reversibility, SourceTrust
from secondsign.intent import (
    DecisionDimensions,
    PaymentPayload,
    PaymentTargetKind,
    SettlementPriority,
    TransactionIntent,
)
from secondsign.policy import AggregateKey, AmountLimit, PolicyContext, WindowAggregate

FINGERPRINT_A = "fp:" + "a1" * 32
FINGERPRINT_B = "fp:" + "b2" * 32
_EPOCH = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)

WINDOW_SECONDS = 3_600


def make_intent(
    *,
    lower: int = 125_000,
    upper: int | None = None,
    currency: Currency = Currency.USD,
    counterparty: str = FINGERPRINT_A,
    source: str = FINGERPRINT_B,
    rail: RailClass = RailClass.card,
) -> TransactionIntent:
    dimensions = DecisionDimensions(
        value_lower_minor=lower,
        value_upper_minor=lower if upper is None else upper,
        quote_currency=currency,
        counterparty_ref=counterparty,
        source_account_ref=source,
        rail_class=rail,
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


def make_limit(
    *, currency: Currency = Currency.USD, cap: int = 1_000_000, window: int = WINDOW_SECONDS
) -> AmountLimit:
    return AmountLimit(quote_currency=currency, window_seconds=window, max_aggregate_minor=cap)


def make_context(
    *,
    intent: TransactionIntent | None = None,
    recent_minor: int = 0,
    count: int = 0,
    window: int = WINDOW_SECONDS,
    key: AggregateKey | None = None,
) -> PolicyContext:
    """A context whose window aggregate matches the given intent's key by default."""
    intent = intent if intent is not None else make_intent()
    aggregate = WindowAggregate(
        key=key if key is not None else AggregateKey.from_intent(intent),
        window_seconds=window,
        aggregate_minor=recent_minor,
        count=count,
    )
    return PolicyContext(window_aggregate=aggregate)
