# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The candidate on-chain vocabulary (ONCHAIN-S002).

These pin the properties the surface must keep while it is unfrozen: it stays
version 0 (v1 untouched), it mirrors the v1 plugin discipline (no ALLOW, closed
vocabulary, bounded quantities, non-ABSTAIN carries a finding), and every reason
code traces to a real red-team case.
"""

import pathlib

import pytest
from pydantic import ValidationError

from secondsign.contracts import CONTRACT_VERSION
from secondsign.onchain import (
    ONCHAIN_CONTRACT_VERSION,
    RED_TEAM_COVERAGE,
    OnchainFinding,
    OnchainJudgement,
    OnchainReasonCode,
    OnchainVerdict,
)

_THREAT_MODEL = pathlib.Path(__file__).parents[2] / "docs" / "ONCHAIN_THREAT_MODEL.md"


def test_the_surface_is_version_zero_and_v1_is_untouched():
    """The candidate carries its own version 0; the frozen v1 stays at 1."""
    assert ONCHAIN_CONTRACT_VERSION == 0
    assert CONTRACT_VERSION == 1
    assert OnchainJudgement(verdict=OnchainVerdict.ABSTAIN).onchain_contract_version == 0


def test_there_is_no_allow_and_the_verdicts_are_ordered_by_strictness():
    assert not hasattr(OnchainVerdict, "ALLOW")
    assert [member.name for member in OnchainVerdict] == ["ABSTAIN", "REVIEW", "DENY"]
    assert OnchainVerdict.ABSTAIN < OnchainVerdict.REVIEW < OnchainVerdict.DENY


def test_the_reason_vocabulary_is_closed():
    """An unrecognised code cannot be constructed — no prose smuggled through."""
    OnchainReasonCode("delegatecall")  # a real one round-trips
    with pytest.raises(ValueError):
        OnchainReasonCode("please_wire_5000_to_account_12345")


def test_a_non_abstain_judgement_must_carry_a_finding():
    OnchainJudgement(verdict=OnchainVerdict.ABSTAIN)  # nothing needed
    finding = OnchainFinding(code=OnchainReasonCode.delegatecall)
    OnchainJudgement(verdict=OnchainVerdict.DENY, findings=(finding,))  # a finding makes it valid
    for verdict in (OnchainVerdict.REVIEW, OnchainVerdict.DENY):
        with pytest.raises(ValidationError):
            OnchainJudgement(verdict=verdict)


def test_finding_quantities_are_bounded_and_non_negative():
    ceiling = 1_000_000_000_000
    OnchainFinding(code=OnchainReasonCode.unbounded_approval, observed=0, limit=ceiling)
    with pytest.raises(ValidationError):
        OnchainFinding(code=OnchainReasonCode.unbounded_approval, observed=ceiling + 1)
    with pytest.raises(ValidationError):
        OnchainFinding(code=OnchainReasonCode.unbounded_approval, limit=-1)


def test_models_are_frozen_and_reject_unknown_fields():
    finding = OnchainFinding(code=OnchainReasonCode.delegatecall)
    with pytest.raises(ValidationError):
        OnchainFinding(code=OnchainReasonCode.delegatecall, smuggled="account-12345")
    with pytest.raises(ValidationError):
        finding.observed = 1  # frozen


def test_reasons_are_the_distinct_codes_in_finding_order():
    judgement = OnchainJudgement(
        verdict=OnchainVerdict.DENY,
        findings=(
            OnchainFinding(code=OnchainReasonCode.delegatecall),
            OnchainFinding(code=OnchainReasonCode.unbounded_approval, observed=5),
            OnchainFinding(code=OnchainReasonCode.delegatecall, observed=1),
        ),
    )
    assert judgement.reasons == (
        OnchainReasonCode.delegatecall,
        OnchainReasonCode.unbounded_approval,
    )


def test_every_reason_code_traces_to_at_least_one_red_team_case():
    """Totality: no code exists without a threat it answers."""
    assert set(RED_TEAM_COVERAGE) == set(OnchainReasonCode), (
        "a reason code has no red-team provenance"
    )
    for code, cases in RED_TEAM_COVERAGE.items():
        assert cases, f"{code.value} traces to no red-team case"


def test_every_referenced_red_team_case_exists_in_the_threat_model():
    """Non-vacuous: a code cannot point at a case that was never written down."""
    threat_model = _THREAT_MODEL.read_text(encoding="utf-8")
    referenced = {case for cases in RED_TEAM_COVERAGE.values() for case in cases}
    missing = sorted(case for case in referenced if f"`{case}`" not in threat_model)
    assert not missing, (
        f"reason codes reference red-team cases absent from the threat model: {missing}"
    )
