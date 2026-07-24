# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The ExecutionGateway — the last check before money moves.

Everything upstream has produced a decision and, if needed, an approval. The
gateway does not trust them blindly: it re-checks, because it is the only place
that holds the rail's credentials and the only place a tampered value would
actually be spent.

- **Only the decided intent** (B1). ``execute`` takes the intent object the
  decision was made on, plus its authorisation — never a fresh amount, target,
  or account a caller could substitute. The digest is recomputed and compared
  immediately before dispatch; a mismatch is refused.
- **Still in its window** (B5). The validity window is re-verified against the
  clock at dispatch; past it, the action must be re-decided, not just re-run.
- **Reserved before executed** (B2). The idempotency key is reserved *before*
  dispatch, so a concurrent duplicate that arrives mid-flight sees the
  reservation and cannot double-spend. Recording only after execution would
  leave a crash window in which a retry re-executes.
- **Three-state outcome** (B8). Success, failure, or unknown — and unknown is
  not failure. A retry under unknown must reuse the same key so the downstream
  de-duplicates; the gateway never re-dispatches a reserved key.

The gateway holds no credential values: it drives a rail through an injected
executor that owns the opaque handle. Core never sees a secret (B11).
"""

from datetime import datetime
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from secondsign.decision import Decision, DecisionVerdict
from secondsign.intent import IntentDigest, TransactionIntent, compute_digest


class ExecutionStatus(StrEnum):
    """The three states a dispatch can end in. Unknown is not failure."""

    success = "success"
    failure = "failure"
    unknown = "unknown"


class RefusalReason(StrEnum):
    """Why the gateway declined to dispatch. A closed set."""

    digest_mismatch = "digest_mismatch"
    denied = "denied"
    not_approved = "not_approved"
    window_expired = "window_expired"


class RailResult(BaseModel):
    """What a rail executor reports back. The reference is an opaque handle, if
    the rail returned one; never a credential."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: ExecutionStatus
    reference: str | None = None


class ExecutionOutcome(BaseModel):
    """The result of an executed intent, bound to its digest."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: ExecutionStatus
    digest: IntentDigest
    reference: str | None = None


class GatewayRefusal(BaseModel):
    """A dispatch that did not happen, and why. Distinct from a failure: nothing
    was executed."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    reason: RefusalReason


class RailExecutor(Protocol):
    """Drives a specific rail. Owns the opaque credential handle; core does not."""

    def dispatch(self, intent: TransactionIntent) -> RailResult: ...


class IdempotencyStore(Protocol):
    """Control-plane state: which keys are reserved, and their recorded outcome."""

    def reserve(self, key: str) -> bool:
        """Reserve ``key``. True if newly reserved, False if already present."""
        ...

    def finalize(self, key: str, outcome: ExecutionOutcome) -> None: ...

    def outcome(self, key: str) -> ExecutionOutcome | None:
        """The recorded outcome for a reserved key, or None if still in flight."""
        ...


class InMemoryIdempotencyStore:
    """A reference in-memory store. A production deployment uses the durable,
    control-plane-only store; this is enough for the engine and its tests."""

    def __init__(self) -> None:
        self._outcomes: dict[str, ExecutionOutcome | None] = {}

    def reserve(self, key: str) -> bool:
        if key in self._outcomes:
            return False
        self._outcomes[key] = None
        return True

    def finalize(self, key: str, outcome: ExecutionOutcome) -> None:
        self._outcomes[key] = outcome

    def outcome(self, key: str) -> ExecutionOutcome | None:
        return self._outcomes.get(key)


class ExecutionGateway:
    """Re-verifies a decision and dispatches it, exactly once, or refuses."""

    def __init__(self, executor: RailExecutor, store: IdempotencyStore) -> None:
        self._executor = executor
        self._store = store

    def execute(
        self,
        intent: TransactionIntent,
        decision: Decision,
        *,
        grant: object = None,
        now: datetime,
    ) -> ExecutionOutcome | GatewayRefusal:
        # Integrity: the executed value must equal the decided value (B1).
        if compute_digest(intent) != decision.digest:
            return GatewayRefusal(reason=RefusalReason.digest_mismatch)

        # Authorisation by verdict. A DENY never runs; a REVIEW needs an approval
        # bound to this same digest.
        if decision.verdict is DecisionVerdict.DENY:
            return GatewayRefusal(reason=RefusalReason.denied)
        if decision.verdict is DecisionVerdict.REVIEW:
            grant_digest = getattr(grant, "digest", None)
            if grant_digest != decision.digest:
                return GatewayRefusal(reason=RefusalReason.not_approved)

        # Still within its window (B5): over it, the action is re-decided.
        if now < intent.dimensions.not_before or now >= intent.dimensions.not_after:
            return GatewayRefusal(reason=RefusalReason.window_expired)

        # Reserve before dispatch (B2). A duplicate that loses the race sees the
        # reservation and returns the recorded outcome, or unknown if in flight.
        key = intent.idempotency_key
        if not self._store.reserve(key):
            recorded = self._store.outcome(key)
            if recorded is not None:
                return recorded
            return ExecutionOutcome(
                status=ExecutionStatus.unknown, digest=decision.digest, reference=None
            )

        result = self._executor.dispatch(intent)
        outcome = ExecutionOutcome(
            status=result.status, digest=decision.digest, reference=result.reference
        )
        self._store.finalize(key, outcome)
        return outcome
