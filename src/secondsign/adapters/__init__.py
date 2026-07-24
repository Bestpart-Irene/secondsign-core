# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Rail adapters — where a tool call becomes an intent.

The contract every adapter satisfies, and the first concrete mapping (Stripe
payments). A rail is a new call type and a new adapter; the decision layer does
not change to accept it (INV-8).
"""

from secondsign.adapters.contract import (
    RailAdapter,
    RejectCode,
    RejectReason,
    ToolCall,
    trust_rank,
)
from secondsign.adapters.stripe import StripeAdapter, StripeCall

__all__ = [
    "RailAdapter",
    "RejectCode",
    "RejectReason",
    "StripeAdapter",
    "StripeCall",
    "ToolCall",
    "trust_rank",
]
