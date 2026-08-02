# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Properties of the maker-checker flow — the ones a fuzzed attacker would probe.

For every subject, clock and digest: a one-shot approval grants at most once, an
expired or missing-expiry approval never grants, a self-approval never grants,
and a mismatched proposal never grants.
"""

from datetime import timedelta

from hypothesis import given
from hypothesis import strategies as st

from secondsign.approval import CheckerIdentity, CheckerVerdict, Grant, MakerIdentity
from secondsign.intent import ProposalDigest
from tests.approval.conftest import (
    EXPIRES_AT,
    NOW,
    approve,
    fresh_maker_checker,
    make_pending,
)

_subjects = st.text(alphabet="abcdefghijklmnop", min_size=1, max_size=6)


@given(attempts=st.integers(min_value=2, max_value=8))
def test_grants_at_most_once_however_many_attempts(attempts):
    mc = fresh_maker_checker()
    pending = make_pending()
    grants = sum(
        isinstance(mc.consume(pending, approve(pending), now=NOW), Grant) for _ in range(attempts)
    )
    assert grants == 1


@given(offset=st.integers(min_value=0, max_value=100_000))
def test_never_grants_at_or_after_expiry(offset):
    mc = fresh_maker_checker()
    pending = make_pending(expires_at=EXPIRES_AT)
    at_or_after = EXPIRES_AT + timedelta(seconds=offset)
    assert not isinstance(mc.consume(pending, approve(pending), now=at_or_after), Grant)


@given(maker_subject=_subjects)
def test_self_approval_never_grants(maker_subject):
    mc = fresh_maker_checker()
    pending = make_pending(maker=MakerIdentity(subject=maker_subject))
    verdict = CheckerVerdict(
        checker=CheckerIdentity(subject=maker_subject),
        approval_id=pending.approval_id,
        proposal=pending.proposal,
        approved=True,
    )
    assert not isinstance(mc.consume(pending, verdict, now=NOW), Grant)


@given(value=st.text(alphabet="0123456789abcdef", min_size=64, max_size=64))
def test_mismatched_digest_never_grants(value):
    mc = fresh_maker_checker()
    pending = make_pending()
    if value == pending.proposal.value:
        return
    verdict = CheckerVerdict(
        checker=CheckerIdentity(subject="bob"),
        approval_id=pending.approval_id,
        proposal=ProposalDigest(value=value),
        approved=True,
    )
    assert not isinstance(mc.consume(pending, verdict, now=NOW), Grant)
