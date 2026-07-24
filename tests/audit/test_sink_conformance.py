# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The audit-sink conformance suite, and proof it rejects a dropping sink.

A sink is where receipts are persisted. The one thing it may never do is
silently drop a write — that is a hole in the audit trail dressed as success.
The suite appends a corpus and checks every receipt is retrievable, in order;
the negative test proves a sink that discards writes fails it.
"""

from secondsign.conformance import AuditSinkConformance
from tests.audit.conftest import DroppingSink, make_chain

_CORPUS = make_chain().entries()


class TestInMemoryAuditSinkConformance(AuditSinkConformance):
    from secondsign.audit import InMemoryAuditSink

    sink_factory = InMemoryAuditSink
    receipt_corpus = _CORPUS


def _assert_raises(fn) -> None:
    try:
        fn()
    except AssertionError:
        return
    raise AssertionError("conformance check accepted a non-conformant sink")


def test_suite_rejects_a_dropping_sink():
    class Cert(AuditSinkConformance):
        sink_factory = DroppingSink
        receipt_corpus = _CORPUS

    _assert_raises(Cert().test_appends_are_retrievable_in_order)


def test_suite_refuses_a_subclass_with_no_factory():
    class Cert(AuditSinkConformance):
        receipt_corpus = _CORPUS

    _assert_raises(Cert().test_appends_are_retrievable_in_order)


def test_suite_refuses_a_subclass_with_an_empty_corpus():
    from secondsign.audit import InMemoryAuditSink

    class Cert(AuditSinkConformance):
        sink_factory = InMemoryAuditSink

    _assert_raises(Cert().test_appends_are_retrievable_in_order)
