# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The approval layer.

The digest-bound maker-checker flow and the approval-provider contract
(CORE-S011). A REVIEW decision is held for a distinct second human; the approval
that results binds to one digest, is one-shot, and expires.
"""

from secondsign.approval.identities import CheckerIdentity, MakerIdentity
from secondsign.approval.maker_checker import (
    CheckerVerdict,
    Grant,
    MakerChecker,
    PendingApproval,
    Rejected,
    RejectionReason,
)
from secondsign.approval.provider import ApprovalProvider

__all__ = [
    "ApprovalProvider",
    "CheckerIdentity",
    "CheckerVerdict",
    "Grant",
    "MakerChecker",
    "MakerIdentity",
    "PendingApproval",
    "Rejected",
    "RejectionReason",
]
