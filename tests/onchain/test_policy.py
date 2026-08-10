# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The first-cut on-chain effect policy: what the co-signer refuses and allows."""

from secondsign.onchain import policy
from secondsign.onchain.effect import EffectKind, OnchainEffect
from secondsign.onchain.types import OnchainReasonCode, OnchainVerdict

_TOKEN = "0x" + "22" * 20
_SPENDER = "0x" + "33" * 20
_ATTACKER = "0x" + "44" * 20
_CAP = 1_000
#: The spender the approval tests vouch for. An approval is fail-closed without it.
_ALLOWED = frozenset({_SPENDER})


def _effect(
    kind: EffectKind, amount: int | None = None, counterparty: str = _SPENDER
) -> OnchainEffect:
    return OnchainEffect(kind=kind, target=_TOKEN, counterparty=counterparty, amount=amount)


def test_a_bounded_approval_to_an_allowlisted_spender_raises_no_concern():
    judgement = policy.evaluate(
        _effect(EffectKind.erc20_approval, 100),
        approval_cap=_CAP,
        approve_spender_allowlist=_ALLOWED,
    )
    assert judgement.verdict is OnchainVerdict.ABSTAIN


def test_a_bounded_approval_to_an_unlisted_spender_is_denied():
    # The drain path: 999 < cap, so the amount alone raises no concern — but the
    # spender is not vouched for, and an allowance is a standing draw capability.
    judgement = policy.evaluate(
        _effect(EffectKind.erc20_approval, 999, counterparty=_ATTACKER),
        approval_cap=_CAP,
        approve_spender_allowlist=_ALLOWED,
    )
    assert judgement.verdict is OnchainVerdict.DENY
    assert judgement.reasons == (OnchainReasonCode.counterparty_not_allowlisted,)


def test_an_approval_is_fail_closed_when_no_spender_is_allowlisted():
    # The default: an empty allowlist denies every approval, vouched or not.
    judgement = policy.evaluate(_effect(EffectKind.erc20_approval, 100), approval_cap=_CAP)
    assert judgement.verdict is OnchainVerdict.DENY
    assert judgement.reasons == (OnchainReasonCode.counterparty_not_allowlisted,)


def test_a_bounded_transfer_is_not_gated_by_the_approval_allowlist():
    # A transfer is a one-time bounded outflow, not a standing capability, so the
    # spender allowlist does not apply — an arbitrary recipient under the cap is
    # allowed (the gateway's velocity window bounds repetition).
    judgement = policy.evaluate(
        _effect(EffectKind.erc20_transfer, 100, counterparty=_ATTACKER), approval_cap=_CAP
    )
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


def test_an_approval_with_an_undetermined_amount_is_denied():
    # amount=None is not zero — it is an amount the effect model could not
    # establish (fee-on-transfer, proxy indirection), and an unknown magnitude on
    # a value-moving call fails closed rather than passing as a harmless zero.
    judgement = policy.evaluate(
        _effect(EffectKind.erc20_approval, None),
        approval_cap=_CAP,
        approve_spender_allowlist=_ALLOWED,
    )
    assert judgement.verdict is OnchainVerdict.DENY
    assert judgement.reasons == (OnchainReasonCode.effect_outside_model,)


def test_a_transfer_with_an_undetermined_amount_is_denied():
    judgement = policy.evaluate(_effect(EffectKind.erc20_transfer, None), approval_cap=_CAP)
    assert judgement.verdict is OnchainVerdict.DENY
    assert judgement.reasons == (OnchainReasonCode.effect_outside_model,)


def test_native_value_alongside_a_bounded_call_is_denied():
    # The second drain: a bounded approve carrying huge native value. The calldata
    # alone is concern-free, but the value moving with it is outside the model.
    effect = OnchainEffect(
        kind=EffectKind.erc20_approval,
        target=_TOKEN,
        counterparty=_SPENDER,
        amount=100,
        native_value=10**21,
    )
    judgement = policy.evaluate(effect, approval_cap=_CAP, approve_spender_allowlist=_ALLOWED)
    assert judgement.verdict is OnchainVerdict.DENY
    assert judgement.reasons == (OnchainReasonCode.effect_outside_model,)


def test_an_amount_in_the_review_band_is_held_for_a_human():
    judgement = policy.evaluate(
        _effect(EffectKind.erc20_approval, 500),
        approval_cap=_CAP,
        review_above=100,
        approve_spender_allowlist=_ALLOWED,
    )
    assert judgement.verdict is OnchainVerdict.REVIEW
    (finding,) = judgement.findings
    assert finding.observed == 500
    assert finding.limit == 100


def test_below_the_review_threshold_raises_no_concern():
    judgement = policy.evaluate(
        _effect(EffectKind.erc20_approval, 100),
        approval_cap=_CAP,
        review_above=100,
        approve_spender_allowlist=_ALLOWED,
    )
    assert judgement.verdict is OnchainVerdict.ABSTAIN  # exactly the threshold is not yet a review


def test_over_the_cap_denies_even_with_a_review_band():
    judgement = policy.evaluate(
        _effect(EffectKind.erc20_approval, _CAP + 1), approval_cap=_CAP, review_above=100
    )
    assert judgement.verdict is OnchainVerdict.DENY  # the cap is checked before the review band
