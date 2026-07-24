# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures for the audit tests."""

from secondsign.audit import AuditLog, InMemoryAuditSink
from secondsign.contracts import ReasonCode
from secondsign.decision import DecisionVerdict
from secondsign.gateway import ExecutionStatus
from secondsign.intent import IntentDigest

DIGEST_A = IntentDigest(value="a" * 64)
DIGEST_B = IntentDigest(value="b" * 64)
DIGEST_C = IntentDigest(value="c" * 64)


def make_chain() -> InMemoryAuditSink:
    """A sink with three linked receipts across the non-ALLOW paths."""
    sink = InMemoryAuditSink()
    log = AuditLog(sink)
    log.record(digest=DIGEST_A, verdict=DecisionVerdict.DENY, reasons=(ReasonCode.org_policy,))
    log.record(
        digest=DIGEST_B,
        verdict=DecisionVerdict.REVIEW,
        reasons=(ReasonCode.new_counterparty,),
        approval_id="appr-1",
    )
    log.record(
        digest=DIGEST_C,
        verdict=DecisionVerdict.ALLOW,
        outcome_status=ExecutionStatus.unknown,
    )
    return sink


class DroppingSink:
    """A sink that silently discards writes — the forbidden behaviour."""

    def append(self, receipt) -> None:
        pass

    def entries(self):
        return ()


class FailingSink:
    """A sink whose write fails. Recording against it must fail closed."""

    def append(self, receipt) -> None:
        raise OSError("audit store unreachable")

    def entries(self):
        return ()
