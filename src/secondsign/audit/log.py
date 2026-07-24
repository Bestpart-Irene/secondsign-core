# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The audit log and the sink contract.

The :class:`AuditLog` builds each receipt, links it to the last by hash, and
appends it to a sink. Two guarantees live here:

- **Fail-closed writes** (A7). A sink whose ``append`` raises is not swallowed —
  the exception propagates, so a caller that cannot record cannot proceed. An
  audit write that silently fails would leave money moved with no trail.
- **A sink may not drop.** :class:`~secondsign.conformance.AuditSinkConformance`
  certifies that every appended receipt is retrievable in order; a sink that
  discards writes fails it.

The sink is control-plane state (the append-only ledger), reached only through
this contract. Core ships an in-memory reference implementation; a deployment
supplies a durable one.
"""

from typing import Protocol

from secondsign.audit.receipt import (
    GENESIS_HASH,
    AuditReceipt,
    _content_hash,
)
from secondsign.contracts import ReasonCode
from secondsign.decision import DecisionVerdict
from secondsign.gateway import ExecutionStatus
from secondsign.intent import IntentDigest


class AuditSink(Protocol):
    """An append-only ledger of receipts. It must never silently drop a write."""

    def append(self, receipt: AuditReceipt) -> None: ...

    def entries(self) -> tuple[AuditReceipt, ...]: ...


class InMemoryAuditSink:
    """A reference append-only sink. A deployment uses a durable, control-plane
    store; this is enough for the engine and its tests."""

    def __init__(self) -> None:
        self._entries: list[AuditReceipt] = []

    def append(self, receipt: AuditReceipt) -> None:
        self._entries.append(receipt)

    def entries(self) -> tuple[AuditReceipt, ...]:
        return tuple(self._entries)


class AuditLog:
    """Records receipts into a sink, each chained to the last."""

    def __init__(self, sink: AuditSink) -> None:
        self._sink = sink

    def record(
        self,
        *,
        digest: IntentDigest,
        verdict: DecisionVerdict,
        reasons: tuple[ReasonCode, ...] = (),
        outcome_status: ExecutionStatus | None = None,
        approval_id: str | None = None,
    ) -> AuditReceipt:
        entries = self._sink.entries()
        sequence = len(entries)
        prev_hash = entries[-1].receipt_hash if entries else GENESIS_HASH
        reasons = tuple(reasons)

        receipt_hash = _content_hash(
            sequence=sequence,
            prev_hash=prev_hash,
            digest=digest,
            verdict=verdict,
            reasons=reasons,
            outcome_status=outcome_status,
            approval_id=approval_id,
        )
        receipt = AuditReceipt(
            sequence=sequence,
            prev_hash=prev_hash,
            digest=digest,
            verdict=verdict,
            reasons=reasons,
            outcome_status=outcome_status,
            approval_id=approval_id,
            receipt_hash=receipt_hash,
        )
        # Fail-closed: if the ledger cannot persist this, the error propagates
        # rather than being swallowed. The receipt is built before the append,
        # so a write failure never leaves a half-formed entry.
        self._sink.append(receipt)
        return receipt
