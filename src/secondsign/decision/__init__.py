# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The decision layer.

The DecisionEngine combines core-policy concerns into one monotone, digest-bound
verdict — ALLOW, REVIEW or DENY (CORE-S010).
"""

from secondsign.decision.engine import (
    Decision,
    DecisionEngine,
    DecisionVerdict,
    Policy,
)

__all__ = [
    "Decision",
    "DecisionEngine",
    "DecisionVerdict",
    "Policy",
]
