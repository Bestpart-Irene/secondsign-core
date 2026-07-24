# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Conformance suite for approval providers.

A provider proves it is safe to install by inheriting from
:class:`ApprovalProviderConformance`, naming the subclass ``Test...``, and
supplying a provider plus a corpus of pending approvals:

.. code-block:: python

    from secondsign.conformance import ApprovalProviderConformance
    from my_package import MyProvider, a_pending, another_pending


    class TestMyProvider(ApprovalProviderConformance):
        provider = MyProvider()
        pending_corpus = (a_pending, another_pending)

The guarantee it certifies is the one a substitution attack would break: the
verdict a provider returns binds to the digest of the pending approval it was
shown, and names a checker of the distinct checker type (B3, B6). A provider may
approve or reject as its human decides — what it may not do is approve a digest
it was never shown.

Like the other kits, this imports no test framework; the methods are plain
assertions pytest collects from the subclass.
"""

from secondsign.approval import CheckerIdentity, CheckerVerdict, PendingApproval


class ApprovalProviderConformance:
    """Inherit, set ``provider`` and ``pending_corpus``. Name the subclass ``Test...``."""

    #: The provider under test. Subclasses must set this.
    provider: object = None
    #: Pending approvals to present to it.
    pending_corpus: tuple[PendingApproval, ...] = ()

    def _provider(self) -> object:
        if self.provider is None:
            raise AssertionError(
                f"{type(self).__name__} must set a `provider` attribute to the "
                "provider instance being certified"
            )
        return self.provider

    def _corpus(self) -> tuple[PendingApproval, ...]:
        if not self.pending_corpus:
            raise AssertionError(
                f"{type(self).__name__} must set `pending_corpus` to a non-empty "
                "tuple of pending approvals"
            )
        return self.pending_corpus

    def _verdicts(self):
        provider = self._provider()
        for pending in self._corpus():
            verdict = provider.present(pending)
            assert isinstance(verdict, CheckerVerdict), (
                f"provider returned {type(verdict).__name__}, not a CheckerVerdict"
            )
            yield pending, verdict

    def test_returns_a_checker_verdict(self):
        for _pending, _verdict in self._verdicts():
            pass  # the assertion is inside _verdicts

    def test_verdict_binds_to_the_presented_digest(self):
        """B3 — a provider cannot approve a substitute for what it was shown."""
        for pending, verdict in self._verdicts():
            assert verdict.digest == pending.digest, (
                "provider returned a verdict bound to a different digest than the "
                "pending approval it was shown — a substitution channel"
            )

    def test_checker_is_the_distinct_checker_type(self):
        """B6 — the approver is a CheckerIdentity, never a maker."""
        for _pending, verdict in self._verdicts():
            assert isinstance(verdict.checker, CheckerIdentity), (
                f"provider named a {type(verdict.checker).__name__} as checker"
            )

    def test_does_not_mutate_the_pending(self):
        provider = self._provider()
        for pending in self._corpus():
            before = pending.model_dump()
            provider.present(pending)
            assert pending.model_dump() == before, "provider mutated the pending approval"
