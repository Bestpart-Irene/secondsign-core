# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The approval-provider contract.

A provider is the channel that presents a pending approval to a human checker —
Slack, email, a console, an enterprise workflow — and returns their verdict. It
is pluggable, so the maker-checker flow does not know or care how a human is
reached. What every provider must guarantee, and what
:class:`~secondsign.conformance.ApprovalProviderConformance` certifies, is that
the verdict it returns binds to the digest it was shown: a provider must not be
able to return approval for a substitute intent (B3).
"""

from typing import Protocol

from secondsign.approval.maker_checker import CheckerVerdict, PendingApproval


class ApprovalProvider(Protocol):
    """Presents a pending approval to a checker and returns their verdict."""

    def present(self, pending: PendingApproval) -> CheckerVerdict: ...
