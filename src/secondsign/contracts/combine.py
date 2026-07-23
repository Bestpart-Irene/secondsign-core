# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Combination of plugin judgements — monotone by construction.

This is the only place a plugin's opinion meets another's, and therefore the
only place protection could be weakened. It is written so that no such path
exists rather than so that no such path is taken: the verdict is a maximum and
the reasons are a union, and there is no branch that returns anything else.
"""

from secondsign.contracts.types import (
    MAX_EXPLANATION_LENGTH,
    PluginJudgement,
    PluginVerdict,
    ReasonCode,
)


def _merge_reasons(
    left: tuple[ReasonCode, ...], right: tuple[ReasonCode, ...]
) -> tuple[ReasonCode, ...]:
    """Order-preserving union, left first. Deduplicated — a code repeated by
    two plugins is one finding, not two."""
    return tuple(dict.fromkeys((*left, *right)))


def _merge_explanations(left: str, right: str) -> str:
    parts = [part for part in (left.strip(), right.strip()) if part]
    merged = " ".join(dict.fromkeys(parts))
    if len(merged) > MAX_EXPLANATION_LENGTH:
        # Truncate rather than reject: a long chain of findings must not be
        # able to make combination fail, which would be a denial path.
        merged = merged[: MAX_EXPLANATION_LENGTH - 1].rstrip() + "…"
    return merged


def combine(left: PluginJudgement, right: PluginJudgement) -> PluginJudgement:
    """The stricter of two judgements, with both sets of reasons kept.

    Monotone: the result is never below either input on the strictness
    ordering. Commutative and associative in strictness, idempotent, with
    ABSTAIN as the identity element — all asserted as laws in the tests, not
    just by example.

    Reason codes are carried through rather than summarised: they are the audit
    trail, and a finding that disappears on combination cannot be reviewed.
    """
    verdict = left.verdict if left.verdict >= right.verdict else right.verdict
    return PluginJudgement(
        verdict=verdict,
        reasons=_merge_reasons(left.reasons, right.reasons),
        explanation=_merge_explanations(left.explanation, right.explanation),
    )


def neutral() -> PluginJudgement:
    """The identity element — the starting point before any plugin has spoken."""
    return PluginJudgement(verdict=PluginVerdict.ABSTAIN)
