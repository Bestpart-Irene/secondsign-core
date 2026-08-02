# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Reviews waiting for a human, held where the agent cannot reach them.

A `REVIEW` verdict has to survive between two requests that may be hours apart:
the agent's proposal, and a checker's answer. What is held is not the decision
alone. It is the **proposal the agent sent**, so the intent can be re-completed
with a fresh window at approval time without asking the agent for anything
(ADR 0005) — and asking the agent again would be the whole vulnerability, since
the second answer would be the one that executed.

This is control-plane state by every measure INV-12 names. An agent that could
read this queue would learn which of its actions are under review and what a
reviewer is being shown; an agent that could write to it would be filing its own
approvals. The module lives under `secondsign.controlplane` so
:mod:`secondsign.isolation` classifies it on the protected side by prefix, the
moment the file exists, with no second edit anywhere to make that true.

The reference store is in memory. A deployment that restarts loses its open
reviews, which is the correct trade for a reference implementation and is
exactly what a durable control-plane store exists to fix — the same note the
fingerprint key and the idempotency store already carry.
"""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from secondsign.agent.surface import AuthorizationRequest
from secondsign.approval.maker_checker import PendingApproval


class PendingReview(BaseModel):
    """One held review: who proposed it, what they proposed, and what a checker
    is being asked."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    approval_id: str = Field(min_length=1)
    #: The reservation this review belongs to. Derived from the authenticated
    #: principal and the agent's handle together, so one workload's queue cannot
    #: be reached by another choosing the same `request_ref`.
    reservation_key: str = Field(min_length=1)
    #: A keyed fingerprint of the proposing workload, never the raw principal.
    principal_ref: str = Field(min_length=1)
    #: The agent's original proposal, kept verbatim. Re-completing the intent
    #: from this is what lets the window move while nothing else does.
    request: AuthorizationRequest
    #: What the checker is shown and answers about.
    approval: PendingApproval


class PendingStore(Protocol):
    """Control-plane state: which reviews are open, and what each one holds."""

    def hold(self, review: PendingReview) -> None: ...

    def get(self, approval_id: str) -> PendingReview | None:
        """The open review under ``approval_id``, or None if there is none.

        None covers both "never existed" and "already resolved". The caller
        distinguishes them no further, because both mean the same thing here:
        there is nothing to execute.
        """
        ...

    def release(self, approval_id: str) -> None:
        """Drop a review that has been resolved. Idempotent."""
        ...

    def open_reviews(self) -> tuple[PendingReview, ...]: ...


class InMemoryPendingStore:
    """A reference in-memory store. A production deployment uses the durable,
    control-plane-only store; this is enough for the flow and its tests."""

    def __init__(self) -> None:
        self._open: dict[str, PendingReview] = {}

    def hold(self, review: PendingReview) -> None:
        self._open[review.approval_id] = review

    def get(self, approval_id: str) -> PendingReview | None:
        return self._open.get(approval_id)

    def release(self, approval_id: str) -> None:
        self._open.pop(approval_id, None)

    def open_reviews(self) -> tuple[PendingReview, ...]:
        return tuple(self._open.values())
