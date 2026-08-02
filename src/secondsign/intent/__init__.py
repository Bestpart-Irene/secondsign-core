# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The intent layer.

The decision dimensions and the closed rail-payload union (CORE-S006), the
immutable TransactionIntent that assembles them, and the versioned IntentDigest
that decision, approval and execution all bind to (CORE-S007), plus the
ProposalDigest a human's approval binds to instead (CORE-S022, ADR 0005).
"""

from secondsign.intent.digest import (
    DIGEST_VERSION,
    PROPOSAL_DIGEST_VERSION,
    IntentDigest,
    ProposalDigest,
    compute_digest,
    compute_proposal_digest,
)
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
    "PROPOSAL_DIGEST_VERSION",
    "RAIL_PAYLOAD_TYPES",
    "DecisionDimensions",
    "IntentDigest",
    "OrderType",
    "PaymentPayload",
    "PaymentTargetKind",
    "ProposalDigest",
    "RailPayload",
    "SettlementPriority",
    "TradePayload",
    "TradeSide",
    "TransactionIntent",
    "compute_digest",
    "compute_proposal_digest",
]
