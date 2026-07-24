# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""CORE-S004 — no free text crosses the boundary, and results are canonical.

Threat A5: a bounded, screened text field was still a text field. A plugin
author who wants to pass a customer name through will find a way to phrase it
under the length limit and without a digit run. The only durable answer is to
stop accepting prose: the plugin states *what* it found in closed vocabulary,
and core writes the sentence.

Threat A9: order-independence was previously asserted over the *set* of
reasons. Two operators with the same extensions in a different registration
order could still get byte-different records, which is a reconciliation
problem even when the verdict agrees.
"""

import pytest
from pydantic import ValidationError

from secondsign.contracts import (
    CONTRACT_VERSION,
    MAX_DETAIL_MAGNITUDE,
    Finding,
    PluginJudgement,
    PluginVerdict,
    ReasonCode,
    combine,
    render,
    run_plugins,
)


def _judgement(verdict, *findings):
    return PluginJudgement(verdict=verdict, findings=findings)


class _Fixed:
    contract_version = CONTRACT_VERSION

    def __init__(self, judgement):
        self._judgement = judgement

    def evaluate(self, view):
        return self._judgement


# --- no free text -------------------------------------------------------------


def test_judgement_has_no_text_field():
    """The acceptance criterion, asserted directly."""
    assert "explanation" not in PluginJudgement.model_fields
    assert set(PluginJudgement.model_fields) == {"contract_version", "verdict", "findings"}


def test_finding_has_no_text_field():
    assert set(Finding.model_fields) == {"code", "observed", "limit"}


@pytest.mark.parametrize("model", [PluginJudgement, Finding])
def test_no_boundary_field_accepts_free_text(model):
    """A str field is a payload channel regardless of how it is validated."""
    for name, field in model.model_fields.items():
        assert field.annotation is not str, f"{model.__name__}.{name} accepts free text"


def test_a_plugin_cannot_supply_prose():
    with pytest.raises(ValidationError):
        PluginJudgement(
            verdict=PluginVerdict.DENY,
            findings=(Finding(code=ReasonCode.org_policy),),
            explanation="Beneficiary Jane Roe looked wrong to me",
        )


# --- numeric detail is bounded ------------------------------------------------


def test_detail_magnitude_excludes_account_shaped_numbers():
    """A 15- or 16-digit identifier must not fit in a detail field."""
    assert MAX_DETAIL_MAGNITUDE < 10**14
    for oversized in (4111111111111111, 10**15, MAX_DETAIL_MAGNITUDE + 1):
        with pytest.raises(ValidationError):
            Finding(code=ReasonCode.velocity_limit, observed=oversized)


def test_detail_is_non_negative():
    with pytest.raises(ValidationError):
        Finding(code=ReasonCode.velocity_limit, observed=-1)


def test_detail_is_optional():
    finding = Finding(code=ReasonCode.org_policy)
    assert finding.observed is None
    assert finding.limit is None


def test_detail_is_integer_only():
    with pytest.raises(ValidationError):
        Finding(code=ReasonCode.velocity_limit, observed=1.5)


# --- core writes the sentence -------------------------------------------------


def test_core_renders_a_human_sentence_from_codes():
    text = render(
        _judgement(
            PluginVerdict.REVIEW,
            Finding(code=ReasonCode.velocity_limit, observed=9, limit=5),
        )
    )
    assert "9" in text
    assert "5" in text
    assert text.strip()


def test_every_reason_code_can_be_rendered():
    """A code with no template would surface as a blank audit record."""
    for code in ReasonCode:
        text = render(_judgement(PluginVerdict.DENY, Finding(code=code)))
        assert text.strip(), f"{code} renders empty"


def test_abstain_renders_empty():
    assert render(PluginJudgement(verdict=PluginVerdict.ABSTAIN)) == ""


def test_rendering_is_deterministic():
    judgement = _judgement(
        PluginVerdict.DENY,
        Finding(code=ReasonCode.counterparty_risk),
        Finding(code=ReasonCode.velocity_limit, observed=9, limit=5),
    )
    assert render(judgement) == render(judgement)


# --- canonical ordering -------------------------------------------------------


def test_combination_is_byte_identical_under_reordering():
    """A9 — stronger than set equality: the records must match exactly."""
    a = _judgement(PluginVerdict.REVIEW, Finding(code=ReasonCode.velocity_limit, observed=9))
    b = _judgement(PluginVerdict.DENY, Finding(code=ReasonCode.counterparty_risk))
    assert combine(a, b) == combine(b, a)
    assert combine(a, b).model_dump_json() == combine(b, a).model_dump_json()


def test_findings_are_canonically_ordered(view):
    late = _Fixed(_judgement(PluginVerdict.REVIEW, Finding(code=ReasonCode.velocity_limit)))
    early = _Fixed(_judgement(PluginVerdict.DENY, Finding(code=ReasonCode.counterparty_risk)))
    forward = run_plugins([late, early], view)
    reverse = run_plugins([early, late], view)
    assert forward == reverse
    assert forward.findings == tuple(sorted(forward.findings, key=lambda f: f.code.value))


def test_identical_findings_from_two_plugins_are_deduplicated(view):
    same = Finding(code=ReasonCode.org_policy, observed=3, limit=1)
    result = run_plugins(
        [
            _Fixed(_judgement(PluginVerdict.DENY, same)),
            _Fixed(_judgement(PluginVerdict.DENY, same)),
        ],
        view,
    )
    assert len(result.findings) == 1


def test_same_code_with_different_detail_is_kept_separately(view):
    result = run_plugins(
        [
            _Fixed(
                _judgement(
                    PluginVerdict.REVIEW, Finding(code=ReasonCode.velocity_limit, observed=9)
                )
            ),
            _Fixed(
                _judgement(
                    PluginVerdict.REVIEW, Finding(code=ReasonCode.velocity_limit, observed=40)
                )
            ),
        ],
        view,
    )
    assert len(result.findings) == 2, "different observations are different findings"


def test_findings_are_an_immutable_container():
    judgement = _judgement(PluginVerdict.DENY, Finding(code=ReasonCode.org_policy))
    assert isinstance(judgement.findings, tuple)
    with pytest.raises(TypeError):
        judgement.findings[0] = Finding(code=ReasonCode.velocity_limit)


def test_non_abstain_requires_at_least_one_finding():
    with pytest.raises(ValidationError):
        PluginJudgement(verdict=PluginVerdict.DENY, findings=())


def test_reasons_remains_available_as_a_derived_view():
    judgement = _judgement(
        PluginVerdict.DENY,
        Finding(code=ReasonCode.counterparty_risk),
        Finding(code=ReasonCode.velocity_limit),
    )
    assert judgement.reasons == (ReasonCode.counterparty_risk, ReasonCode.velocity_limit)
    assert "reasons" not in PluginJudgement.model_fields
