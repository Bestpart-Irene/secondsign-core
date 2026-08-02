# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The band between "fine" and "no": send it to a human.

Until this existed, no policy in this repository could return REVIEW, so the
verdict was reachable only by a test constructing one by hand — the maker-checker
flow was wired to a branch that production could not enter.

A review threshold is not a second limit. It is the point above which the
decision stops being the machine's to make, and it lives on the same
`AmountLimit` as the deny cap for one reason: the two have to be checked against
each other. A threshold at or above the cap describes a band that cannot occur,
which is not a configuration to interpret carefully but one to refuse.

The three bands are pinned at their boundaries. An off-by-one here is an action
that silently skipped a human, and boundaries are where that happens.
"""

import pytest
from pydantic import ValidationError

from secondsign.contracts import Currency, PluginVerdict, ReasonCode
from secondsign.policy import AmountLimit, AmountWindowPolicy
from tests.policy.conftest import WINDOW_SECONDS, make_context, make_intent

CAP = 10_000
REVIEW_ABOVE = 5_000


def _policy() -> AmountWindowPolicy:
    return AmountWindowPolicy(
        AmountLimit(
            quote_currency=Currency.USD,
            window_seconds=WINDOW_SECONDS,
            max_aggregate_minor=CAP,
            review_above_minor=REVIEW_ABOVE,
        )
    )


def _verdict(prospective: int) -> PluginVerdict:
    intent = make_intent(lower=prospective)
    return _policy().evaluate(intent, make_context(intent=intent)).verdict


@pytest.mark.parametrize(
    ("prospective", "expected"),
    [
        (0, PluginVerdict.ABSTAIN),
        (REVIEW_ABOVE - 1, PluginVerdict.ABSTAIN),
        (REVIEW_ABOVE, PluginVerdict.ABSTAIN),
        (REVIEW_ABOVE + 1, PluginVerdict.REVIEW),
        (CAP - 1, PluginVerdict.REVIEW),
        (CAP, PluginVerdict.REVIEW),
        (CAP + 1, PluginVerdict.DENY),
    ],
)
def test_the_three_bands_are_pinned_at_their_boundaries(
    prospective: int, expected: PluginVerdict
) -> None:
    assert _verdict(prospective) is expected


def test_the_band_is_judged_on_the_aggregate_not_the_transaction() -> None:
    """Structuring does not get you under the review threshold either (B4)."""
    intent = make_intent(lower=1_000)
    context = make_context(intent=intent, recent_minor=4_500, count=3)

    result = _policy().evaluate(intent, context)

    assert result.verdict is PluginVerdict.REVIEW


def test_a_review_finding_states_what_was_observed_against_what() -> None:
    intent = make_intent(lower=REVIEW_ABOVE + 1)

    result = _policy().evaluate(intent, make_context(intent=intent))

    assert [f.code for f in result.findings] == [ReasonCode.value_band_exceeded]
    assert result.findings[0].observed == REVIEW_ABOVE + 1
    assert result.findings[0].limit == REVIEW_ABOVE


def test_no_threshold_means_no_review_band() -> None:
    """The field is optional, and absent means the policy behaves as before."""
    limit = AmountLimit(
        quote_currency=Currency.USD, window_seconds=WINDOW_SECONDS, max_aggregate_minor=CAP
    )
    intent = make_intent(lower=CAP - 1)

    result = AmountWindowPolicy(limit).evaluate(intent, make_context(intent=intent))

    assert result.verdict is PluginVerdict.ABSTAIN


def test_an_unverifiable_aggregate_still_denies_rather_than_reviewing() -> None:
    """A missing aggregate is not "ask a human"; it is the strictest path (A4).

    Routing it to review would look conservative and would not be: it converts a
    denial into a request that a human can answer yes to, on evidence nobody
    has.
    """
    intent = make_intent(lower=1)

    result = _policy().evaluate(intent, make_context(intent=intent, window=WINDOW_SECONDS * 2))

    assert result.verdict is PluginVerdict.DENY


@pytest.mark.parametrize("threshold", [CAP, CAP + 1])
def test_a_threshold_at_or_above_the_cap_is_refused_at_construction(threshold: int) -> None:
    """A band that cannot occur is a configuration mistake, not a strict policy."""
    with pytest.raises(ValidationError):
        AmountLimit(
            quote_currency=Currency.USD,
            window_seconds=WINDOW_SECONDS,
            max_aggregate_minor=CAP,
            review_above_minor=threshold,
        )
