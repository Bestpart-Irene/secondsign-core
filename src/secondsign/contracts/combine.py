# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Combination of plugin judgements — monotone and canonical by construction.

This is the only place a plugin's opinion meets another's, and therefore the
only place protection could be weakened. It is written so that no such path
exists rather than so that no such path is taken: the verdict is a maximum and
the findings are a union, and there is no branch that returns anything else.

The union is *canonically ordered*, not merely deduplicated. Two operators
running the same extensions in a different registration order must produce
byte-identical records, or reconciling their audit trails becomes a manual
exercise even when both denied the same transaction (INV-13).
"""

from secondsign.contracts.types import Finding, PluginJudgement, PluginVerdict


def _merge_findings(left: tuple[Finding, ...], right: tuple[Finding, ...]) -> tuple[Finding, ...]:
    """Deduplicated union in canonical order.

    Two findings are the same only if their code *and* their quantities match:
    "velocity 9" and "velocity 40" are two observations, and collapsing them
    would lose the larger one from the record.
    """
    unique = {finding.sort_key(): finding for finding in (*left, *right)}
    return tuple(unique[key] for key in sorted(unique))


def combine(left: PluginJudgement, right: PluginJudgement) -> PluginJudgement:
    """The stricter of two judgements, with both sets of findings kept.

    Monotone: the result is never below either input on the strictness
    ordering. Commutative, associative, idempotent, with ABSTAIN as the
    identity element — asserted as laws in the tests, not just by example.

    Findings are carried through rather than summarised: they are the audit
    trail, and a finding that disappears on combination cannot be reviewed.
    """
    verdict = left.verdict if left.verdict >= right.verdict else right.verdict
    return PluginJudgement(
        verdict=verdict,
        findings=_merge_findings(left.findings, right.findings),
    )


def neutral() -> PluginJudgement:
    """The identity element — the starting point before any plugin has spoken."""
    return PluginJudgement(verdict=PluginVerdict.ABSTAIN)
