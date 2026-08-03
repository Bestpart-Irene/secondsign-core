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


class _SlowAppendSink:
    """A sink that yields inside `append`, after the sequence has been read but
    before the receipt lands — exactly the read-then-append window the lock
    exists to close. On CPython the GIL otherwise hides the fork, and a test
    that cannot fail is no guard. Wraps a real in-memory sink."""

    def __init__(self) -> None:
        import time

        self._inner = InMemoryAuditSink()
        self._sleep = time.sleep

    def entries(self):
        return self._inner.entries()

    def append(self, receipt) -> None:
        # The receipt's sequence and prev_hash are already fixed by the time
        # `record` calls this; sleeping here lets another writer read the same
        # (unchanged) tail and fix the same sequence — a fork, unless the log's
        # own lock made the read-and-append atomic.
        self._sleep(0.002)
        self._inner.append(receipt)


def test_concurrent_writers_do_not_fork_the_chain():
    """`record` reads the tail then appends; two threads that read the same
    tail would append two receipts with the same sequence and prev_hash — a
    fork `verify_chain` rejects. The log holds its own lock so the
    derive-and-append is atomic whatever the caller does. Verified with a sink
    that yields between the read and the append, so the race is real and not
    hidden by the GIL."""
    import threading

    sink = _SlowAppendSink()
    log = AuditLog(sink)
    writers = 12
    barrier = threading.Barrier(writers)

    def write() -> None:
        barrier.wait()
        log.record(digest=DIGEST_A, verdict=DecisionVerdict.DENY, reasons=(ReasonCode.org_policy,))

    threads = [threading.Thread(target=write) for _ in range(writers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    entries = sink.entries()
    assert len(entries) == writers, "a write was lost or the chain forked"
    assert [e.sequence for e in entries] == list(range(writers)), "sequences collided"
    assert verify_chain(entries), "the chain forked under concurrent writers"
