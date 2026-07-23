# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Turning findings into a sentence.

Extensions report codes and quantities; the wording is written here. That
division is what keeps prose off the boundary (threat A5) and it has two
further benefits: the same condition always reads the same way in an audit
record regardless of which extension raised it, and the text can be translated
without asking every extension author to cooperate.

Every :class:`~secondsign.contracts.types.ReasonCode` must have a template. A
code without one would surface as a blank line in a receipt, so the test suite
requires the mapping to be total.
"""

from secondsign.contracts.types import Finding, PluginJudgement, PluginVerdict, ReasonCode

#: One sentence per reason code. ``{observed}`` and ``{limit}`` are filled when
#: the finding carries them; the fallback is used when it does not.
_TEMPLATES: dict[ReasonCode, tuple[str, str]] = {
    ReasonCode.velocity_limit: (
        "Recent activity reached {observed} against a limit of {limit}.",
        "Recent activity exceeded the configured limit.",
    ),
    ReasonCode.counterparty_risk: (
        "Counterparty risk is above the permitted band.",
        "Counterparty risk is above the permitted band.",
    ),
    ReasonCode.jurisdiction_restricted: (
        "The destination jurisdiction is restricted by policy.",
        "The destination jurisdiction is restricted by policy.",
    ),
    ReasonCode.market_session_closed: (
        "The market session does not permit this action.",
        "The market session does not permit this action.",
    ),
    ReasonCode.value_band_exceeded: (
        "Value reached {observed} minor units against a limit of {limit}.",
        "Value exceeded the configured limit.",
    ),
    ReasonCode.new_counterparty: (
        "This counterparty has not been paid before.",
        "This counterparty has not been paid before.",
    ),
    ReasonCode.org_policy: (
        "Organisation policy does not permit this action.",
        "Organisation policy does not permit this action.",
    ),
    ReasonCode.plugin_error: (
        "An extension failed during evaluation; denying.",
        "An extension failed during evaluation; denying.",
    ),
    ReasonCode.plugin_contract_mismatch: (
        "An extension declared an unrecognised contract version and was not consulted.",
        "An extension declared an unrecognised contract version and was not consulted.",
    ),
    ReasonCode.plugin_invalid_result: (
        "An extension returned a value that is not a judgement.",
        "An extension returned a value that is not a judgement.",
    ),
}

if set(_TEMPLATES) != set(ReasonCode):  # pragma: no cover — import-time guard
    missing = sorted(code.value for code in set(ReasonCode) - set(_TEMPLATES))
    raise RuntimeError(f"reason codes without a rendering template: {', '.join(missing)}")


def render_finding(finding: Finding) -> str:
    """One finding as a sentence."""
    quantified, plain = _TEMPLATES[finding.code]
    if finding.observed is None and finding.limit is None:
        return plain
    return quantified.format(
        observed="unspecified" if finding.observed is None else finding.observed,
        limit="unspecified" if finding.limit is None else finding.limit,
    )


def render(judgement: PluginJudgement) -> str:
    """A judgement as human-readable text.

    Empty for ABSTAIN: silence has nothing to explain. Deterministic, because
    findings arrive canonically ordered.
    """
    if judgement.verdict is PluginVerdict.ABSTAIN:
        return ""
    return " ".join(render_finding(finding) for finding in judgement.findings)
