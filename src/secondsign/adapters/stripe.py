# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""A Stripe payment mapping — the first concrete rail adapter.

This slice makes no network call: mapping a tool call to an intent is pure, and
must be, so it can be reasoned about and tested without a live account. The
adapter turns a redacted Stripe payment call into a :class:`TransactionIntent`,
deriving the idempotency key from the call's content and defaulting to the
strictest reversibility. It passes :class:`~secondsign.conformance.RailAdapterConformance`.
"""

import hashlib
import json

from pydantic import ConfigDict, Field

from secondsign.adapters.contract import RejectCode, RejectReason, ToolCall
from secondsign.contracts import Currency, RailClass, Reversibility
from secondsign.intent import (
    DecisionDimensions,
    PaymentPayload,
    PaymentTargetKind,
    SettlementPriority,
    TransactionIntent,
)

#: Currencies this mapping settles. A call in any other is rejected rather than
#: mapped to an intent nobody can execute.
_SUPPORTED_CURRENCIES: frozenset[Currency] = frozenset(
    {Currency.USD, Currency.EUR, Currency.GBP, Currency.CAD, Currency.AUD}
)


class StripeCall(ToolCall):
    """A redacted Stripe payment tool call.

    Note the absence of any idempotency-key field: a caller has no way to supply
    one, because the adapter derives it (B2). The amount is a settled scalar, so
    it maps to a degenerate value band.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    amount_minor: int = Field(ge=0)
    quote_currency: Currency
    target_kind: PaymentTargetKind
    new_beneficiary: bool
    cross_border: bool
    settlement_priority: SettlementPriority


class StripeAdapter:
    """Maps a :class:`StripeCall` to a TransactionIntent, or rejects it."""

    rail_class: RailClass = RailClass.card

    def derive(self, call: StripeCall) -> TransactionIntent | RejectReason:
        if call.amount_minor == 0:
            # A zero-value charge is not a payment; fail closed rather than
            # emit an intent the gateway would have to special-case.
            return RejectReason(code=RejectCode.malformed_call)
        if call.quote_currency not in _SUPPORTED_CURRENCIES:
            return RejectReason(code=RejectCode.unsupported_currency)

        dimensions = DecisionDimensions(
            value_lower_minor=call.amount_minor,
            value_upper_minor=call.amount_minor,
            quote_currency=call.quote_currency,
            counterparty_ref=call.counterparty_ref,
            source_account_ref=call.source_account_ref,
            rail_class=self.rail_class,
            not_before=call.not_before,
            not_after=call.not_after,
            # Strictest by default; a rail earns a weaker reversibility, it is
            # never assumed (B8).
            reversibility=Reversibility.irreversible,
            # Passed through unchanged — a downgrade of none. The adapter never
            # raises provenance (B9); the conformance suite enforces that.
            source_trust=call.declared_source_trust,
            scope_count=call.scope_count,
        )
        payload = PaymentPayload(
            target_kind=call.target_kind,
            new_beneficiary=call.new_beneficiary,
            cross_border=call.cross_border,
            settlement_priority=call.settlement_priority,
        )
        return TransactionIntent(
            dimensions=dimensions,
            payload=payload,
            idempotency_key=self._idempotency_key(call),
        )

    @staticmethod
    def _idempotency_key(call: StripeCall) -> str:
        """Derived from the call's content, so a caller cannot choose it (B2)."""
        material = json.dumps(
            call.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return "stripe-" + hashlib.sha256(material).hexdigest()
