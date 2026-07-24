# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Conformance suite for audit sinks.

A sink proves it is safe to install by inheriting from
:class:`AuditSinkConformance`, naming the subclass ``Test...``, and supplying a
factory for a fresh sink plus a corpus of receipts:

.. code-block:: python

    from secondsign.conformance import AuditSinkConformance
    from my_package import MySink


    class TestMySink(AuditSinkConformance):
        sink_factory = MySink
        receipt_corpus = (a_receipt, another_receipt)

The guarantee it certifies is the one a hole in the audit trail would exploit: a
sink may not silently drop a write. Every appended receipt must be retrievable,
in the order it was appended. Durability beyond process memory is a deployment
concern; not losing a write in the first place is the contract.

Like the other kits, this imports no test framework; the methods are plain
assertions pytest collects from the subclass.
"""

from collections.abc import Callable

from secondsign.audit import AuditReceipt


class AuditSinkConformance:
    """Inherit, set ``sink_factory`` and ``receipt_corpus``. Name it ``Test...``."""

    #: A zero-argument callable returning a fresh, empty sink. Subclasses set it.
    sink_factory: Callable[[], object] | None = None
    #: Receipts to append during the checks.
    receipt_corpus: tuple[AuditReceipt, ...] = ()

    def _fresh_sink(self) -> object:
        if self.sink_factory is None:
            raise AssertionError(
                f"{type(self).__name__} must set `sink_factory` to a callable "
                "returning a fresh sink"
            )
        return self.sink_factory()

    def _corpus(self) -> tuple[AuditReceipt, ...]:
        if not self.receipt_corpus:
            raise AssertionError(
                f"{type(self).__name__} must set `receipt_corpus` to a non-empty tuple of receipts"
            )
        return self.receipt_corpus

    def test_appends_are_retrievable_in_order(self):
        """The core guarantee: nothing is dropped, order is preserved."""
        sink = self._fresh_sink()
        corpus = self._corpus()
        for receipt in corpus:
            sink.append(receipt)
        assert sink.entries() == corpus, (
            "the sink did not return exactly what was appended, in order — a "
            "dropped or reordered write is a hole in the audit trail"
        )

    def test_a_fresh_sink_is_empty(self):
        assert self._fresh_sink().entries() == ()

    def test_appending_preserves_each_receipt_unchanged(self):
        sink = self._fresh_sink()
        for receipt in self._corpus():
            sink.append(receipt)
        for stored, original in zip(sink.entries(), self._corpus(), strict=True):
            assert stored == original, "the sink altered a receipt it stored"
