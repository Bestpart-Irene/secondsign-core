#!/usr/bin/env python3
# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""A one-second smoke test: is the decision path wired, end to end?

    python tools/smoke.py

Stands up the whole in-process service — engine, gateway, window ledger,
audit log, maker-checker — with an in-memory recording rail, and runs one of
every outcome:

    allow → completed        a small payment dispatches, ledger grows by one
    deny  → refused          an over-cap payment moves nothing
    review→ awaiting_review  a mid-band payment parks for a human
          → executed         and completes when the review is approved
    retry → completed        a re-sent handle reads the settled answer, once

Then it checks the books agree: the audit chain verifies, and the rail moved
exactly the actions that were allowed or approved. No Docker, no network, no
real credential, no real money — the rail is a counter. It exits non-zero on
the first thing that is not wired the way the guarantees say, so it is safe as
a pre-push or post-deploy sanity check where the full suite is too slow.

This is a smoke test, not the gate: it proves the path is connected, not that
every edge is defended. That is `pytest`, and `pytest tests/integrity` for the
concurrency and cross-component invariants specifically.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone

from secondsign.agent.surface import AuthorizationRequest
from secondsign.approval import CheckerIdentity, CheckerVerdict
from secondsign.audit import AuditLog, InMemoryAuditSink, verify_chain
from secondsign.contracts import Currency
from secondsign.controlplane.fingerprint import FingerprintKey
from secondsign.controlplane.window import WindowLedger
from secondsign.decision import DecisionEngine
from secondsign.gateway.authorization import AuthorizationService
from secondsign.gateway.execution import (
    ExecutionGateway,
    ExecutionStatus,
    InMemoryIdempotencyStore,
    RailResult,
)
from secondsign.policy import AmountLimit, AmountWindowPolicy

PRINCIPAL = "spiffe://secondsign.example/agent/smoke"
CHECKER = "spiffe://secondsign.example/approver/smoke"
CAP = 1_000_00
REVIEW_ABOVE = 300_00


class _RecordingRail:
    def __init__(self) -> None:
        self.dispatched: list[int] = []

    def dispatch(self, intent) -> RailResult:  # noqa: ANN001 — protocol shape
        self.dispatched.append(intent.dimensions.value_upper_minor)
        return RailResult(status=ExecutionStatus.success, reference="smoke-ref")


def _request(ref_hex: str, amount: int) -> AuthorizationRequest:
    return AuthorizationRequest.model_validate(
        {
            "action": "payment",
            "rail": "card",
            "currency": "USD",
            "amount_minor": amount,
            "reversibility": "irreversible",
            "counterparty_ref": "fp:" + "cd" * 32,
            "source_account_ref": "fp:" + "ef" * 32,
            "request_ref": "fp:" + ref_hex,
        }
    )


class _Smoke:
    """Accumulates pass/fail lines so the whole check runs and reports once."""

    def __init__(self) -> None:
        self._ok = True

    def check(self, label: str, condition: bool, detail: str = "") -> None:
        mark = "ok  " if condition else "FAIL"
        suffix = f"  — {detail}" if detail and not condition else ""
        print(f"  [{mark}] {label}{suffix}")
        self._ok = self._ok and condition

    @property
    def passed(self) -> bool:
        return self._ok


def main() -> int:
    smoke = _Smoke()
    sink = InMemoryAuditSink()
    rail = _RecordingRail()
    limit = AmountLimit(
        quote_currency=Currency.USD,
        window_seconds=3600,
        max_aggregate_minor=CAP,
        review_above_minor=REVIEW_ABOVE,
    )
    service = AuthorizationService(
        engine=DecisionEngine([AmountWindowPolicy(limit)]),
        gateway=ExecutionGateway(rail, InMemoryIdempotencyStore()),
        ledger=WindowLedger(window_seconds=limit.window_seconds),
        audit=AuditLog(sink),
        keys=FingerprintKey.generate(),
    )
    start = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)

    def at(minute: int) -> datetime:
        return start + timedelta(minutes=minute)

    print("SecondSign smoke test — the decision path, in process, no real money.\n")

    allow = service.authorize(PRINCIPAL, _request("01" * 32, 100_00), now=at(0))
    smoke.check(
        "a small payment is allowed and completes",
        allow.status.value == "completed",
        allow.status.value,
    )

    retry = service.authorize(PRINCIPAL, _request("01" * 32, 100_00), now=at(1))
    smoke.check(
        "a re-sent handle reads the settled answer",
        retry.status.value == "completed",
        retry.status.value,
    )

    deny = service.authorize(PRINCIPAL, _request("02" * 32, 9_000_00), now=at(2))
    smoke.check("an over-cap payment is refused", deny.status.value == "refused", deny.status.value)

    held = service.authorize(PRINCIPAL, _request("03" * 32, 400_00), now=at(3))
    smoke.check(
        "a mid-band payment parks for review",
        held.status.value == "awaiting_review",
        held.status.value,
    )

    reviews = service.open_reviews()
    smoke.check(
        "the parked review is visible to the control plane",
        len(reviews) == 1,
        f"{len(reviews)} open",
    )

    if reviews:
        review = reviews[0]
        resolution = service.resolve(
            review.approval_id,
            CheckerVerdict(
                checker=CheckerIdentity(subject=CHECKER),
                approval_id=review.approval_id,
                proposal=review.approval.proposal,
                approved=True,
            ),
            now=at(4),
        )
        smoke.check(
            "an approved review executes",
            resolution.status.value == "executed",
            resolution.status.value,
        )
        settled = service.authorize(PRINCIPAL, _request("03" * 32, 400_00), now=at(5))
        smoke.check(
            "the agent reads the review's outcome back",
            settled.status.value == "completed",
            settled.status.value,
        )

    # The books agree.
    smoke.check("the audit chain verifies", verify_chain(sink.entries()))
    smoke.check(
        "the rail moved only what was allowed or approved",
        rail.dispatched == [100_00, 400_00],
        str(rail.dispatched),
    )
    smoke.check(
        "total dispatched value is within the cap",
        sum(rail.dispatched) <= CAP,
        str(sum(rail.dispatched)),
    )
    successes = [e for e in sink.entries() if e.outcome_status is ExecutionStatus.success]
    smoke.check(
        "every dispatch is on the audit chain",
        len(successes) == len(rail.dispatched),
        f"{len(successes)} receipts vs {len(rail.dispatched)} dispatches",
    )

    print()
    if smoke.passed:
        print("SMOKE OK — the decision path is wired end to end.")
        return 0
    print("SMOKE FAILED — something on the decision path is not wired as the guarantees state.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
