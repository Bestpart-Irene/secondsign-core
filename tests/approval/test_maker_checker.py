# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the proposal-bound maker-checker flow.

The properties this enforces are the ones a replay or a self-approval would
break: an approval binds to exactly one proposal (B2), is one-shot, expires with a
mandatory TTL and treats a missing expiry as already expired, and the checker
cannot be the maker (B6) — a separation held at the type level and re-checked on
the subject.
"""

import pytest

from secondsign.approval import Grant, Rejected, RejectionReason
from secondsign.decision import Decision, DecisionVerdict
from secondsign.intent import ProposalDigest, compute_digest, compute_proposal_digest
from tests.approval.conftest import (
    CHECKER,
    EXPIRES_AT,
    MAKER,
    NOW,
    CheckerVerdict,
    approve,
    fresh_maker_checker,
    make_intent,
    make_pending,
    make_review_decision,
)


def test_request_produces_an_approval_bound_to_the_proposal():
    intent = make_intent()
    decision = make_review_decision(intent)
    proposal = compute_proposal_digest(intent)

    pending = fresh_maker_checker().request(
        decision, MAKER, approval_id="a1", proposal=proposal, expires_at=EXPIRES_AT
    )

    assert pending.decision == decision
    assert pending.proposal == proposal
    assert pending.maker is MAKER
    assert pending.proposal.value != decision.digest.value, (
        "the approval bound to the intent digest, which contains the window a "
        "human cannot answer inside (ADR 0005)"
    )


def test_only_a_review_decision_can_be_requested():
    """ALLOW needs no approval; a DENY cannot be approved into permission."""
    intent = make_intent()
    denied = Decision(verdict=DecisionVerdict.DENY, digest=compute_digest(intent))

    with pytest.raises(ValueError, match="REVIEW"):
        fresh_maker_checker().request(
            denied,
            MAKER,
            approval_id="a1",
            proposal=compute_proposal_digest(intent),
            expires_at=EXPIRES_AT,
        )


def test_a_valid_consume_grants():
    mc = fresh_maker_checker()
    pending = make_pending()
    grant = mc.consume(pending, approve(pending), now=NOW)
    assert isinstance(grant, Grant)
    assert grant.proposal == pending.proposal
    assert grant.checker is CHECKER


def test_consume_is_one_shot():
    mc = fresh_maker_checker()
    pending = make_pending()
    first = mc.consume(pending, approve(pending), now=NOW)
    second = mc.consume(pending, approve(pending), now=NOW)
    assert isinstance(first, Grant)
    assert second == Rejected(reason=RejectionReason.already_consumed)


def test_a_verdict_for_a_different_digest_is_rejected():
    """B2/B3 — an approval of some other intent cannot be redirected here."""
    mc = fresh_maker_checker()
    pending = make_pending()
    other = ProposalDigest(value="f" * 64)
    verdict = CheckerVerdict(
        checker=CHECKER, approval_id=pending.approval_id, proposal=other, approved=True
    )
    assert mc.consume(pending, verdict, now=NOW) == Rejected(reason=RejectionReason.digest_mismatch)


def test_the_maker_cannot_be_the_checker():
    """B6 — separation of duties, checked on the subject."""
    mc = fresh_maker_checker()
    pending = make_pending(maker=MAKER)
    from secondsign.approval import CheckerIdentity

    self_checker = CheckerIdentity(subject=MAKER.subject)
    verdict = CheckerVerdict(
        checker=self_checker,
        approval_id=pending.approval_id,
        proposal=pending.proposal,
        approved=True,
    )
    assert mc.consume(pending, verdict, now=NOW) == Rejected(reason=RejectionReason.self_approval)


def test_an_expired_approval_is_rejected():
    from datetime import timedelta

    mc = fresh_maker_checker()
    pending = make_pending(expires_at=EXPIRES_AT)
    too_late = EXPIRES_AT + timedelta(seconds=1)
    assert mc.consume(pending, approve(pending), now=too_late) == Rejected(
        reason=RejectionReason.expired
    )


def test_a_missing_expiry_is_treated_as_expired():
    mc = fresh_maker_checker()
    pending = make_pending(expires_at=None)
    assert mc.consume(pending, approve(pending), now=NOW) == Rejected(
        reason=RejectionReason.expired
    )


def test_a_rejected_verdict_does_not_grant():
    mc = fresh_maker_checker()
    pending = make_pending()
    verdict = CheckerVerdict(
        checker=CHECKER,
        approval_id=pending.approval_id,
        proposal=pending.proposal,
        approved=False,
    )
    assert mc.consume(pending, verdict, now=NOW) == Rejected(reason=RejectionReason.not_approved)


def test_a_failed_consume_does_not_burn_the_approval():
    """An expired attempt must not also consume a one-shot that could be
    re-requested; only a successful grant is one-shot."""
    mc = fresh_maker_checker()
    pending = make_pending()
    bad = CheckerVerdict(
        checker=CHECKER,
        approval_id=pending.approval_id,
        proposal=ProposalDigest(value="0" * 64),
        approved=True,
    )
    assert isinstance(mc.consume(pending, bad, now=NOW), Rejected)
    # a subsequent valid consume still grants
    assert isinstance(mc.consume(pending, approve(pending), now=NOW), Grant)


def test_approvals_are_not_bound_to_an_agent_or_action_type():
    """The forbidden coupling: a PendingApproval carries a proposal, a maker and a
    TTL — no agent id, session id, or action-type field to bind to."""
    from secondsign.approval import PendingApproval

    fields = set(PendingApproval.model_fields)
    assert not (
        fields & {"agent", "agent_id", "session", "session_id", "action_class", "action_type"}
    )
