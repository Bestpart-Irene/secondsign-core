# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""TransactionIntent — the immutable unit a decision is made on and bound to.

An intent is the decision dimensions, one closed rail payload, and the
adapter-derived idempotency key, assembled into one deeply immutable object.
Immutability is the point, not a convenience: the value a decision was made on
must be the value that is executed (B1), and that holds only if nothing between
decision and dispatch can rewrite the object. The idempotency key is carried
here so a replay can be recognised (B2); it is derived by the adapter, never
supplied by the calling agent — that derivation is CORE-S008.
"""

from pydantic import BaseModel, ConfigDict, Field

from secondsign.intent.dimensions import DecisionDimensions
from secondsign.intent.payloads import RailPayload


class TransactionIntent(BaseModel):
    """The immutable, digest-bound description of one action."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    dimensions: DecisionDimensions
    payload: RailPayload
    #: Derived by the adapter from the call, never accepted from the agent (B2).
    idempotency_key: str = Field(min_length=1)
