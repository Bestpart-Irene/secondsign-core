# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The intent layer's value objects.

The decision dimensions a rule reasons over, and the closed union of rail
payloads. Assembling these into an immutable, digest-bound TransactionIntent is
CORE-S007; here they are just the shapes, each closed and frozen.
"""

from secondsign.intent.dimensions import DecisionDimensions
from secondsign.intent.payloads import (
    RAIL_PAYLOAD_TYPES,
    PaymentPayload,
    PaymentTargetKind,
    RailPayload,
    SettlementPriority,
)

__all__ = [
    "RAIL_PAYLOAD_TYPES",
    "DecisionDimensions",
    "PaymentPayload",
    "PaymentTargetKind",
    "RailPayload",
    "SettlementPriority",
]
