# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Certifying the example sink, and proving its two guarantees by test.

The one line that matters is the :class:`AuditSinkConformance` subclass — that
is the entire integration a third party performs. The inherited suite appends
a corpus and requires every receipt back, unchanged, in order.

The two extra cases here are the ones the README promises: a write failure
propagates instead of reading as success (INV-11), and a payload shaped like a
raw identifier is refused before it reaches disk.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from examples.audit_sink.jsonl_sink import JsonlAuditSink, _assert_redacted
from secondsign.audit import AuditLog, AuditReceipt, InMemoryAuditSink, verify_chain
from secondsign.conformance import AuditSinkConformance
from secondsign.contracts import ReasonCode
from secondsign.decision import DecisionVerdict
from secondsign.gateway import ExecutionStatus
from secondsign.intent import IntentDigest


def _corpus() -> tuple[AuditReceipt, ...]:
    """A short, properly chained corpus, built through the published surface."""
    staging = InMemoryAuditSink()
    log = AuditLog(staging)
    log.record(
        digest=IntentDigest(value="a1" * 32),
        verdict=DecisionVerdict.DENY,
        reasons=(ReasonCode.value_band_exceeded,),
    )
    log.record(
        digest=IntentDigest(value="b2" * 32),
        verdict=DecisionVerdict.ALLOW,
        outcome_status=ExecutionStatus.success,
        principal_ref="fp:" + "c3" * 32,
    )
    log.record(
        digest=IntentDigest(value="d4" * 32),
        verdict=DecisionVerdict.REVIEW,
        reasons=(ReasonCode.org_policy,),
        approval_id="rev-0001",
    )
    return staging.entries()


_CORPUS = _corpus()


def _fresh_sink() -> JsonlAuditSink:
    # The conformance suite demands a zero-argument factory returning an empty
    # sink, so each certification run writes its own file.
    directory = Path(tempfile.mkdtemp(prefix="secondsign-example-sink-"))
    return JsonlAuditSink(directory / "receipts.jsonl")


class TestJsonlAuditSinkConformance(AuditSinkConformance):
    sink_factory = staticmethod(_fresh_sink)
    receipt_corpus = _CORPUS


def test_what_lands_on_disk_is_still_a_verifiable_chain() -> None:
    sink = _fresh_sink()
    for receipt in _CORPUS:
        sink.append(receipt)
    assert verify_chain(sink.entries())


def test_a_write_failure_propagates_instead_of_reading_as_success() -> None:
    """INV-11: a sink that cannot persist a receipt must say so."""
    missing_parent = Path(tempfile.mkdtemp()) / "gone" / "receipts.jsonl"
    sink = JsonlAuditSink(missing_parent)
    with pytest.raises(OSError):
        sink.append(_CORPUS[0])


def test_a_raw_identifier_is_refused_before_it_reaches_disk() -> None:
    payload = _CORPUS[1].model_dump(mode="json")
    payload["principal_ref"] = "acct-0042-jane-doe"  # a raw identifier, not fp:…
    with pytest.raises(AssertionError, match="keyed fingerprint"):
        _assert_redacted(payload)


def test_an_unknown_field_is_refused_before_it_reaches_disk() -> None:
    payload = _CORPUS[0].model_dump(mode="json")
    payload["customer_name"] = "Jane Doe"
    with pytest.raises(AssertionError, match="unknown fields"):
        _assert_redacted(payload)
