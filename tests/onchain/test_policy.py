# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The first-cut on-chain effect policy: what the co-signer refuses and allows."""

from secondsign.onchain import policy
from secondsign.onchain.effect import EffectKind, OnchainEffect
from secondsign.onchain.types import OnchainReasonCode, OnchainVerdict

_TOKEN = "0x" + "22" * 20
_SPENDER = "0x" + "33" * 20
_CAP = 1_000


def _effect(kind: EffectKind, amount: int | None = None) -> OnchainEffect:
    return OnchainEffect(kind=kind, target=_TOKEN, counterparty=_SPENDER, amount=amount)


def test_a_bounded_approval_raises_no_concern():
    judgement = policy.evaluate(_effect(EffectKind.erc20_approval, 100), approval_cap=_CAP)
    assert judgement.verdict is OnchainVerdict.ABSTAIN


def test_a_bounded_transfer_raises_no_concern():
    judgement = policy.evaluate(_effect(EffectKind.erc20_transfer, _CAP), approval_cap=_CAP)
    assert judgement.verdict is OnchainVerdict.ABSTAIN  # exactly the cap is allowed


def test_an_over_cap_approval_is_denied_with_a_clamped_finding():
    judgement = policy.evaluate(_effect(EffectKind.erc20_approval, 2**256 - 1), approval_cap=_CAP)
    assert judgement.verdict is OnchainVerdict.DENY
    (finding,) = judgement.findings
    assert finding.code is OnchainReasonCode.unbounded_approval
    assert finding.observed == 1_000_000_000_000  # clamped off the uint256 max
    assert finding.limit == _CAP


def test_an_over_cap_transfer_is_denied():
    judgement = policy.evaluate(_effect(EffectKind.erc20_transfer, _CAP + 1), approval_cap=_CAP)
    assert judgement.verdict is OnchainVerdict.DENY
    assert judgement.reasons == (OnchainReasonCode.unbounded_approval,)


def test_a_delegatecall_is_denied():
    judgement = policy.evaluate(_effect(EffectKind.delegatecall), approval_cap=_CAP)
    assert judgement.verdict is OnchainVerdict.DENY
    assert judgement.reasons == (OnchainReasonCode.delegatecall,)


def test_a_self_administration_is_denied():
    judgement = policy.evaluate(_effect(EffectKind.self_administration), approval_cap=_CAP)
    assert judgement.reasons == (OnchainReasonCode.structural_change,)


def test_an_unrecognised_call_is_denied():
    judgement = policy.evaluate(_effect(EffectKind.unrecognised), approval_cap=_CAP)
    assert judgement.reasons == (OnchainReasonCode.unknown_selector,)


def test_an_approval_with_no_amount_is_treated_as_zero_and_allowed():
    judgement = policy.evaluate(_effect(EffectKind.erc20_approval, None), approval_cap=_CAP)
    assert judgement.verdict is OnchainVerdict.ABSTAIN


def test_an_amount_in_the_review_band_is_held_for_a_human():
    judgement = policy.evaluate(
        _effect(EffectKind.erc20_approval, 500), approval_cap=_CAP, review_above=100
    )
    assert judgement.verdict is OnchainVerdict.REVIEW
    (finding,) = judgement.findings
    assert finding.observed == 500
    assert finding.limit == 100


def test_below_the_review_threshold_raises_no_concern():
    judgement = policy.evaluate(
        _effect(EffectKind.erc20_approval, 100), approval_cap=_CAP, review_above=100
    )
    assert judgement.verdict is OnchainVerdict.ABSTAIN  # exactly the threshold is not yet a review


def test_over_the_cap_denies_even_with_a_review_band():
    judgement = policy.evaluate(
        _effect(EffectKind.erc20_approval, _CAP + 1), approval_cap=_CAP, review_above=100
    )
    assert judgement.verdict is OnchainVerdict.DENY  # the cap is checked before the review band
