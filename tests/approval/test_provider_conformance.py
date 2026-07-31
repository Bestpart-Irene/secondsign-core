# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The approval-provider conformance suite, and proof it rejects a bad provider.

A provider is the channel that shows a pending approval to a human checker and
returns their verdict. The one guarantee it cannot be allowed to break is that
the verdict binds to the proposal it was shown (B3) — approving a substitute must
be impossible. The suite checks that; the negative test proves it bites.
"""

from secondsign.approval import CheckerVerdict, PendingApproval
from secondsign.conformance import ApprovalProviderConformance
from secondsign.intent import ProposalDigest
from tests.approval.conftest import CHECKER, AutoApproveProvider, make_pending


class TestAutoApproveProviderConformance(ApprovalProviderConformance):
    provider = AutoApproveProvider()
    pending_corpus = (
        make_pending(approval_id="p1"),
        make_pending(approval_id="p2"),
    )


class _DigestSubstitutingProvider:
    """Approves, but against a proposal it was never shown — the B3 violation."""

    def present(self, pending: PendingApproval) -> CheckerVerdict:
        return CheckerVerdict(
            checker=CHECKER,
            approval_id=pending.approval_id,
            proposal=ProposalDigest(value="0" * 64),
            approved=True,
        )


def _assert_raises(fn) -> None:
    try:
        fn()
    except AssertionError:
        return
    raise AssertionError("conformance check accepted a non-conformant provider")


def test_suite_rejects_a_digest_substituting_provider():
    class Cert(ApprovalProviderConformance):
        provider = _DigestSubstitutingProvider()
        pending_corpus = (make_pending(),)

    _assert_raises(Cert().test_verdict_binds_to_the_presented_digest)


def test_suite_refuses_a_subclass_that_sets_no_provider():
    class Cert(ApprovalProviderConformance):
        pending_corpus = (make_pending(),)

    _assert_raises(Cert().test_verdict_binds_to_the_presented_digest)


def test_suite_refuses_a_subclass_with_an_empty_corpus():
    class Cert(ApprovalProviderConformance):
        provider = AutoApproveProvider()

    _assert_raises(Cert().test_verdict_binds_to_the_presented_digest)
