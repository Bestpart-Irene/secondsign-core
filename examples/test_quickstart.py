# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The quickstart is a claim: three proposals, three fates. This keeps it true.

`examples/quickstart.py` is the first thing a new reader runs. If it ever stops
producing ALLOW / REVIEW→executed / DENY — because a default limit moved, a
verdict was renamed, or the resolve path changed — that reader's first
impression breaks silently. So the three outcomes are asserted here, and `main`
is run end to end so the narration cannot raise.
"""

from datetime import datetime, timezone

from examples.quickstart import build_service, main, proposal
from secondsign.approval import CheckerIdentity, CheckerVerdict


def _ref(n: int) -> str:
    return "fp:" + f"{n:064x}"


def test_the_three_proposals_have_the_three_fates() -> None:
    service, pending, rail = build_service()
    now = datetime.now(timezone.utc)
    principal = "agent-workload-7"

    # Under the review threshold: the machine's to allow, and it executed.
    small = service.authorize(principal, proposal(42, request_ref=_ref(1)), now=now)
    assert small.status.value == "completed"

    # Over the threshold, under the cap: held, nothing moved, nothing reserved.
    mid = service.authorize(principal, proposal(300, request_ref=_ref(2)), now=now)
    assert mid.status.value == "awaiting_review"

    # A second principal approves it — not a self-approval — and it executes.
    review = pending.open_reviews()[0]
    approved = CheckerVerdict(
        checker=CheckerIdentity(subject="approver@quickstart"),
        approval_id=review.approval_id,
        proposal=review.approval.proposal,
        approved=True,
    )
    resolution = service.resolve(review.approval_id, approved, now=now)
    assert resolution.status.value == "executed"

    # Over the cap: refused, and no approval was ever offered for it.
    big = service.authorize(principal, proposal(900, request_ref=_ref(3)), now=now)
    assert big.status.value == "refused"

    # The rail was reached only for the two that were authorised — never the $900.
    assert rail.calls == 2


def test_main_runs_and_narrates_all_three(capsys) -> None:
    main()
    out = capsys.readouterr().out
    assert "completed" in out
    assert "awaiting_review" in out
    assert "refused" in out
