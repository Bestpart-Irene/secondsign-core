# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""An Alpaca brokerage mapping — the second rail, and a falsification test.

This slice exists to try to break the intent abstraction. A brokerage trade is
as unlike a card payment as two money-moving actions get — a symbol and a side
instead of a beneficiary, a market that is open or closed, a quote that goes
stale — so if the decision layer had to change to accept it, the abstraction
would be wrong. It does not: a trade becomes a `TradePayload` variant and the
same rail-agnostic `DecisionDimensions`, and nothing in `decision/` or `policy/`
moves. The scope gate enforces that by excluding those packages.

Two brokerage-specific validities that a payment never has are enforced *here*,
at the adapter boundary, rather than pushed into the decision layer: a trade
against a closed market, or on a stale quote, is rejected and never becomes an
intent. The decision layer only ever sees a trade that was tradeable.

This mapping is pure — no network. The live Alpaca call is a separate,
credential-gated test.
"""

import hashlib
import json

from pydantic import ConfigDict, Field, model_validator

from secondsign.adapters.contract import RejectCode, RejectReason, ToolCall
from secondsign.contracts import Currency, MarketSession, RailClass, Reversibility
from secondsign.intent import (
    DecisionDimensions,
    OrderType,
    TradePayload,
    TradeSide,
    TransactionIntent,
)

#: A quote older than this is stale: the price it implies may no longer hold, so
#: the value band it produced can no longer be trusted for a decision.
_MAX_QUOTE_AGE_SECONDS = 30

#: The only session in which this mapping will place a trade. Extended-hours and
#: closed sessions are rejected rather than mapped — a conservative default a
#: deployment can widen deliberately.
_TRADEABLE_SESSION = MarketSession.open


class AlpacaCall(ToolCall):
    """A redacted Alpaca trade tool call.

    Like every rail call it has no idempotency-key field — the adapter derives
    it. The value band is supplied by the caller's quote (a market order has no
    settled price), and it is what policy judges; the symbol and side are
    rail-specific and travel only in the payload.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    symbol: str = Field(min_length=1)
    quantity: int = Field(gt=0)
    side: TradeSide
    order_type: OrderType
    limit_price_minor: int | None = Field(default=None, ge=0)
    quote_currency: Currency
    estimated_value_lower_minor: int = Field(ge=0)
    estimated_value_upper_minor: int = Field(ge=0)
    market_session: MarketSession
    quote_age_seconds: int = Field(ge=0)

    @model_validator(mode="after")
    def _value_band_is_ordered(self) -> "AlpacaCall":
        if self.estimated_value_upper_minor < self.estimated_value_lower_minor:
            raise ValueError("estimated_value_upper_minor cannot be below the lower bound")
        return self


class AlpacaAdapter:
    """Maps an :class:`AlpacaCall` to a TransactionIntent, or rejects it."""

    rail_class: RailClass = RailClass.brokerage

    def derive(self, call: AlpacaCall) -> TransactionIntent | RejectReason:
        if call.market_session is not _TRADEABLE_SESSION:
            # Never trade into a closed or extended-hours session.
            return RejectReason(code=RejectCode.market_closed)
        if call.quote_age_seconds > _MAX_QUOTE_AGE_SECONDS:
            return RejectReason(code=RejectCode.stale_quote)
        if (call.order_type is OrderType.limit) != (call.limit_price_minor is not None):
            # A limit order needs a limit price; a market order must not carry one.
            return RejectReason(code=RejectCode.malformed_call)

        dimensions = DecisionDimensions(
            value_lower_minor=call.estimated_value_lower_minor,
            value_upper_minor=call.estimated_value_upper_minor,
            quote_currency=call.quote_currency,
            counterparty_ref=call.counterparty_ref,
            source_account_ref=call.source_account_ref,
            rail_class=self.rail_class,
            not_before=call.not_before,
            not_after=call.not_after,
            # A filled trade cannot be undone; reversing it is a separate action.
            reversibility=Reversibility.irreversible,
            source_trust=call.declared_source_trust,
            scope_count=call.scope_count,
        )
        payload = TradePayload(
            symbol=call.symbol,
            quantity=call.quantity,
            side=call.side,
            order_type=call.order_type,
            limit_price_minor=call.limit_price_minor,
        )
        return TransactionIntent(
            dimensions=dimensions,
            payload=payload,
            idempotency_key=self._idempotency_key(call),
        )

    @staticmethod
    def _idempotency_key(call: AlpacaCall) -> str:
        material = json.dumps(
            call.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return "alpaca-" + hashlib.sha256(material).hexdigest()
