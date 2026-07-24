# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Rail payloads — a closed, tagged union.

A payment and a trade share the decision *dimensions* but not their fields: a
payment has a beneficiary and a settlement priority, a trade has a symbol and a
side. Rather than a single model with optional fields — which would be an open
mapping in disguise — each rail contributes a closed variant tagged by
``payload_kind``. A new rail adds a variant here and an adapter; the decision
layer never learns the vendor's field names (INV-8).

The closure is the point: it is impossible to attach arbitrary data to an
action, because there is no open shape to attach it to. Pydantic selects the
variant by ``payload_kind``.
"""

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


class PaymentTargetKind(StrEnum):
    """What a payment pays *to* — a class, never a raw destination."""

    card = "card"
    bank_account = "bank_account"
    wallet = "wallet"


class SettlementPriority(StrEnum):
    standard = "standard"
    express = "express"


class PaymentPayload(BaseModel):
    """A payment's rail-specific facts. No identifier, no free-form field."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    #: The union discriminator. A fixed literal, so this variant is unambiguous.
    payload_kind: Literal["payment"] = "payment"

    target_kind: PaymentTargetKind
    new_beneficiary: bool
    cross_border: bool
    settlement_priority: SettlementPriority


class TradeSide(StrEnum):
    buy = "buy"
    sell = "sell"


class OrderType(StrEnum):
    market = "market"
    limit = "limit"


class TradePayload(BaseModel):
    """A brokerage trade's rail-specific facts.

    A trade shares no fields with a payment, only the decision *dimensions* the
    intent carries. The quantity is whole shares (an integer, so no float sneaks
    onto an action); the price band lives in the intent's value dimensions, not
    here, which is precisely why value is a band rather than a scalar.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    #: The union discriminator. A fixed literal, so this variant is unambiguous.
    payload_kind: Literal["trade"] = "trade"

    symbol: str = Field(min_length=1)
    quantity: int = Field(gt=0)
    side: TradeSide
    order_type: OrderType
    #: Limit price in integer minor units; present for a limit order, absent for
    #: a market order.
    limit_price_minor: int | None = Field(default=None, ge=0)


#: The closed, tagged union of rail payloads. A new rail extends this with its
#: own variant and adds itself to :data:`RAIL_PAYLOAD_TYPES`; nothing else
#: changes, and in particular no decision-layer code changes (INV-8). Pydantic
#: selects the variant by ``payload_kind``.
RailPayload = Annotated[PaymentPayload | TradePayload, Field(discriminator="payload_kind")]

#: Every payload variant, in registration order. The tuple is what "closed"
#: means operationally: the set of rails is fixed at build time, not extended at
#: runtime by data.
RAIL_PAYLOAD_TYPES: tuple[type[BaseModel], ...] = (PaymentPayload, TradePayload)
