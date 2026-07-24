# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The intent layer.

The decision dimensions and the closed rail-payload union (CORE-S006), the
immutable TransactionIntent that assembles them, and the versioned IntentDigest
that decision, approval and execution all bind to (CORE-S007).
"""

from secondsign.intent.digest import DIGEST_VERSION, IntentDigest, compute_digest
from secondsign.intent.dimensions import DecisionDimensions
from secondsign.intent.payloads import (
    RAIL_PAYLOAD_TYPES,
    OrderType,
    PaymentPayload,
    PaymentTargetKind,
    RailPayload,
    SettlementPriority,
    TradePayload,
    TradeSide,
)
from secondsign.intent.transaction import TransactionIntent

__all__ = [
    "DIGEST_VERSION",
    "RAIL_PAYLOAD_TYPES",
    "DecisionDimensions",
    "IntentDigest",
    "OrderType",
    "PaymentPayload",
    "PaymentTargetKind",
    "RailPayload",
    "SettlementPriority",
    "TradePayload",
    "TradeSide",
    "TransactionIntent",
    "compute_digest",
]
