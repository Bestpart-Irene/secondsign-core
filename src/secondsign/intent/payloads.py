# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Rail payloads — a closed, tagged union.

A payment and a trade share the decision *dimensions* but not their fields: a
payment has a beneficiary and a settlement priority, a trade has a symbol and a
side. Rather than a single model with optional fields — which would be an open
mapping in disguise — each rail contributes a closed variant tagged by
``payload_kind``. A new rail adds a variant here and an adapter; the decision
layer never learns the vendor's field names (INV-8).

Today the union has one member. The closure is the point: it is impossible to
attach arbitrary data to an action, because there is no open shape to attach it
to.
"""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict


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


#: The closed union of rail payloads. A new rail extends this alias with its own
#: variant (e.g. ``PaymentPayload | TradePayload``) and adds itself to
#: :data:`RAIL_PAYLOAD_TYPES`; nothing else changes. Pydantic selects the
#: variant by ``payload_kind`` once there is more than one.
RailPayload = PaymentPayload

#: Every payload variant, in registration order. The tuple is what "closed"
#: means operationally: the set of rails is fixed at build time, not extended at
#: runtime by data.
RAIL_PAYLOAD_TYPES: tuple[type[BaseModel], ...] = (PaymentPayload,)
