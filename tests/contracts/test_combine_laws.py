"""Algebraic laws for combination.

Combination is the single place a plugin could weaken protection, so it is
tested as an algebra rather than by example: commutative, associative,
idempotent, monotone, with ABSTAIN as the identity element.
"""

from hypothesis import given
from hypothesis import strategies as st

from secondsign.contracts import PluginJudgement, PluginVerdict, ReasonCode, combine

STRICTNESS = {PluginVerdict.ABSTAIN: 0, PluginVerdict.REVIEW: 1, PluginVerdict.DENY: 2}


def _judgement(verdict: PluginVerdict, reasons: tuple[ReasonCode, ...]) -> PluginJudgement:
    if verdict is PluginVerdict.ABSTAIN:
        return PluginJudgement(verdict=verdict)
    reasons = reasons or (ReasonCode.org_policy,)
    return PluginJudgement(
        verdict=verdict,
        reasons=reasons,
        explanation="policy condition met",
    )


judgements = st.builds(
    _judgement,
    st.sampled_from(list(PluginVerdict)),
    st.lists(st.sampled_from(list(ReasonCode)), max_size=3).map(tuple),
)


@given(judgements, judgements)
def test_commutative_in_strictness_and_reasons(a, b):
    left, right = combine(a, b), combine(b, a)
    assert left.verdict is right.verdict
    assert set(left.reasons) == set(right.reasons)


@given(judgements, judgements, judgements)
def test_associative(a, b, c):
    assert combine(combine(a, b), c).verdict is combine(a, combine(b, c)).verdict


@given(judgements)
def test_idempotent(a):
    assert combine(a, a).verdict is a.verdict


@given(judgements, judgements)
def test_monotone_never_below_either_input(a, b):
    result = combine(a, b)
    assert STRICTNESS[result.verdict] >= STRICTNESS[a.verdict]
    assert STRICTNESS[result.verdict] >= STRICTNESS[b.verdict]


@given(judgements)
def test_abstain_is_the_identity_element(a):
    abstain = PluginJudgement(verdict=PluginVerdict.ABSTAIN)
    assert combine(a, abstain).verdict is a.verdict
    assert combine(abstain, a).verdict is a.verdict


@given(judgements, judgements)
def test_reasons_are_preserved_not_summarised(a, b):
    """Reason codes must survive combination — they are the audit trail."""
    result = combine(a, b)
    assert set(a.reasons) | set(b.reasons) <= set(result.reasons)


@given(judgements, judgements)
def test_reasons_are_deduplicated_and_ordered(a, b):
    result = combine(a, b)
    assert len(result.reasons) == len(set(result.reasons))
    assert isinstance(result.reasons, tuple)


@given(judgements, judgements)
def test_combination_never_produces_an_unexplained_non_abstain(a, b):
    result = combine(a, b)
    if result.verdict is not PluginVerdict.ABSTAIN:
        assert result.reasons
        assert result.explanation.strip()
