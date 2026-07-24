# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The AuditLog records every non-ALLOW path, and fails closed on a write error.

A receipt is produced for a denial, a review, a degraded (unknown) execution and
an error path alike — the audit trail cannot have holes exactly where something
went wrong (A7). And if the sink cannot persist a receipt, that is itself a
fail-closed event: the write error propagates rather than being swallowed.
"""

import pytest

from secondsign.audit import AuditLog, AuditReceipt, InMemoryAuditSink, verify_chain
from secondsign.contracts import ReasonCode
from secondsign.decision import DecisionVerdict
from secondsign.gateway import ExecutionStatus
from tests.audit.conftest import DIGEST_A, FailingSink


def test_records_a_denial():
    log = AuditLog(InMemoryAuditSink())
    receipt = log.record(
        digest=DIGEST_A, verdict=DecisionVerdict.DENY, reasons=(ReasonCode.velocity_limit,)
    )
    assert isinstance(receipt, AuditReceipt)
    assert receipt.verdict is DecisionVerdict.DENY
    assert receipt.reasons == (ReasonCode.velocity_limit,)


def test_records_a_degraded_execution():
    """An unknown outcome is exactly the path that most needs a receipt."""
    log = AuditLog(InMemoryAuditSink())
    receipt = log.record(
        digest=DIGEST_A,
        verdict=DecisionVerdict.ALLOW,
        outcome_status=ExecutionStatus.unknown,
    )
    assert receipt.outcome_status is ExecutionStatus.unknown


def test_records_an_error_path_with_a_reason():
    log = AuditLog(InMemoryAuditSink())
    receipt = log.record(
        digest=DIGEST_A, verdict=DecisionVerdict.DENY, reasons=(ReasonCode.plugin_error,)
    )
    assert ReasonCode.plugin_error in receipt.reasons


def test_a_failing_sink_is_fail_closed():
    """A7 — a write that cannot be persisted is not a droppable side effect."""
    log = AuditLog(FailingSink())
    with pytest.raises(OSError, match="unreachable"):
        log.record(digest=DIGEST_A, verdict=DecisionVerdict.DENY, reasons=(ReasonCode.org_policy,))


def test_recorded_receipts_form_a_verifiable_chain():
    sink = InMemoryAuditSink()
    log = AuditLog(sink)
    for _ in range(5):
        log.record(digest=DIGEST_A, verdict=DecisionVerdict.DENY, reasons=(ReasonCode.org_policy,))
    assert verify_chain(sink.entries()) is True
    assert len(sink.entries()) == 5
