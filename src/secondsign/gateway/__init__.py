# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The execution layer.

The gateway that re-verifies a decision and dispatches it exactly once, or
refuses — with a three-state outcome in which unknown is not failure
(CORE-S012).
"""

from secondsign.gateway.execution import (
    ExecutionGateway,
    ExecutionOutcome,
    ExecutionStatus,
    GatewayRefusal,
    IdempotencyStore,
    InMemoryIdempotencyStore,
    RailExecutor,
    RailResult,
    RefusalReason,
)

__all__ = [
    "ExecutionGateway",
    "ExecutionOutcome",
    "ExecutionStatus",
    "GatewayRefusal",
    "IdempotencyStore",
    "InMemoryIdempotencyStore",
    "RailExecutor",
    "RailResult",
    "RefusalReason",
]
