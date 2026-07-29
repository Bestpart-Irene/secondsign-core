# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""secondsign-client: the agent-side half of the SecondSign boundary.

Two things live here and nothing else: the wire contract
(:mod:`secondsign_client.wire`) and the transport that speaks it
(:mod:`secondsign_client.transport`). No gateway, no rail adapter, no policy,
no approval, no credential handling — by construction, and the core
repository's test suite asserts it against the built wheel.
"""

from secondsign_client import wire
from secondsign_client.transport import (
    GatewayClient,
    TransportRefusal,
    TransportRefusalReason,
)
from secondsign_client.wire import (
    WIRE_VERSION,
    AgentOutcomeStatus,
    AuthorizationOutcome,
    AuthorizationRequest,
)

__version__ = "0.1.0"

__all__ = [
    "WIRE_VERSION",
    "AgentOutcomeStatus",
    "AuthorizationOutcome",
    "AuthorizationRequest",
    "GatewayClient",
    "TransportRefusal",
    "TransportRefusalReason",
    "wire",
]
