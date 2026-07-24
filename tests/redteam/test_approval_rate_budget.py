# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Red team: the approval-rate budget (A8).

Availability is a security property: if a normal stream of actions sends too many
to human review, operators rubber-stamp under load and the control is defeated by
its own noise. So REVIEW must be a bounded fraction of representative traffic.
This measures that fraction against a fixed corpus and asserts it stays within
budget — the corrective for a breach is a more precise rule, never a laxer one.
"""

from secondsign.contracts import Finding, PluginJudgement, PluginVerdict, ReasonCode
from secondsign.decision import DecisionEngine, DecisionVerdict
from secondsign.policy import AmountLimit, AmountWindowPolicy
from tests.redteam.conftest import WINDOW, Currency, amount_context, make_intent

#: The share of representative traffic that may land in REVIEW.
_REVIEW_BUDGET = 0.25
_CAP = 3_000_000
_REVIEW_THRESHOLD = 500_000

# A representative corpus: mostly routine small payments, a few larger ones that
# warrant a look, and a couple that break the cap outright.
_CORPUS_AMOUNTS = (
    [50_000] * 14  # routine
    + [750_000, 900_000, 1_200_000]  # reviewable
    + [4_000_000]  # denied outright, not reviewed
)


class _ReviewOverThreshold:
    """A stand-in policy: large payments warrant a human look."""

    def __init__(self, threshold_minor: int) -> None:
        self._threshold = threshold_minor

    def evaluate(self, intent, context) -> PluginJudgement:
        if intent.dimensions.value_upper_minor >= self._threshold:
            return PluginJudgement(
                verdict=PluginVerdict.REVIEW, findings=(Finding(code=ReasonCode.new_counterparty),)
            )
        return PluginJudgement(verdict=PluginVerdict.ABSTAIN)


def _engine() -> DecisionEngine:
    return DecisionEngine(
        [
            AmountWindowPolicy(
                AmountLimit(
                    quote_currency=Currency.USD, window_seconds=WINDOW, max_aggregate_minor=_CAP
                )
            ),
            _ReviewOverThreshold(_REVIEW_THRESHOLD),
        ]
    )


def test_the_review_rate_is_within_budget():
    engine = _engine()
    verdicts = []
    for index, amount in enumerate(_CORPUS_AMOUNTS):
        intent = make_intent(amount=amount, idempotency_key=f"corpus-{index}")
        verdicts.append(engine.decide(intent, amount_context(intent)).verdict)

    reviewed = sum(1 for v in verdicts if v is DecisionVerdict.REVIEW)
    review_rate = reviewed / len(verdicts)
    assert review_rate <= _REVIEW_BUDGET, (
        f"review rate {review_rate:.0%} exceeds the {_REVIEW_BUDGET:.0%} budget — "
        "tighten the rule's precision, do not raise the threshold to pass more"
    )


def test_the_corpus_actually_exercises_all_three_verdicts():
    """A budget measured over traffic that never reviews or denies is vacuous."""
    engine = _engine()
    seen = {
        engine.decide(
            make_intent(amount=a, idempotency_key=f"c-{i}"), amount_context(make_intent(amount=a))
        ).verdict
        for i, a in enumerate(_CORPUS_AMOUNTS)
    }
    assert seen == {DecisionVerdict.ALLOW, DecisionVerdict.REVIEW, DecisionVerdict.DENY}
