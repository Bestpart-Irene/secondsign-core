# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Core policy.

Deterministic rules that judge an intent against redacted context and produce a
concern in the frozen decision vocabulary. The first is the amount limit, judged
on a sliding-window aggregate (CORE-S009).
"""

from secondsign.policy.amount import (
    AggregateKey,
    AmountLimit,
    AmountWindowPolicy,
    PolicyContext,
    WindowAggregate,
)
from secondsign.policy.coverage import CurrencyCoveragePolicy

__all__ = [
    "AggregateKey",
    "AmountLimit",
    "AmountWindowPolicy",
    "CurrencyCoveragePolicy",
    "PolicyContext",
    "WindowAggregate",
]
