# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""A first-cut on-chain effect policy — a decoded effect to a judgement.

This is the minimal decision the co-signer needs to withhold or grant its
signature. A ``delegatecall``, a self-administration, an unrecognised call, or a
token approval or transfer above the cap is refused; a bounded token operation
raises no concern. It reuses the ONCHAIN-S002 judgement vocabulary rather than a
second engine, and stays a single policy — the velocity window and maker-checker
of the fiat path are reused at the gateway, not reimplemented here.

An approval is judged more strictly than a transfer, because the two are not the
same shape of value. A transfer moves value *once*, so a per-transaction cap (and
the gateway's velocity window on top) bounds it. An approval grants a **standing
capability**: the spender may draw repeatedly within the allowance at a time when
SecondSign is not on the signing path, so a per-transaction cap cannot bound it
(threat model C1). The threat model's answer is an **explicit spender allowlist,
never a heuristic match** — an approval to a spender not on the allowlist is
refused, and the default allowlist is empty, so an approval is fail-closed until
a spender is deliberately vouched for.

Deliberately a first cut. The committed decision reuses the full engine over the
generalised algebra (ONCHAIN-S003); this classification is what lets the co-signer
ship its boundary first, and it is upgradeable behind the same ``OnchainJudgement``.
"""

from secondsign.onchain.effect import EffectKind, OnchainEffect
from secondsign.onchain.types import (
    OnchainFinding,
    OnchainJudgement,
    OnchainReasonCode,
    OnchainVerdict,
)

#: The finding-quantity ceiling (A5 anti-identifier bound), mirrored from the
#: on-chain finding fields. An approval of ``2**256-1`` far exceeds it, so a
#: reported quantity is clamped to it — enough to read "over the limit" without
#: carrying an identifier-magnitude number.
_MAX_DETAIL_MAGNITUDE = 1_000_000_000_000

_ABSTAIN = OnchainJudgement(verdict=OnchainVerdict.ABSTAIN)

#: The refusal reason for each non-token effect kind.
_REFUSALS = {
    EffectKind.delegatecall: OnchainReasonCode.delegatecall,
    EffectKind.self_administration: OnchainReasonCode.structural_change,
    EffectKind.unrecognised: OnchainReasonCode.unknown_selector,
}


def _bounded(value: int) -> int:
    return min(value, _MAX_DETAIL_MAGNITUDE)


def _judge(
    verdict: OnchainVerdict,
    code: OnchainReasonCode,
    *,
    observed: int | None = None,
    limit: int | None = None,
) -> OnchainJudgement:
    finding = OnchainFinding(
        code=code,
        observed=None if observed is None else _bounded(observed),
        limit=None if limit is None else _bounded(limit),
    )
    return OnchainJudgement(verdict=verdict, findings=(finding,))


def evaluate(
    effect: OnchainEffect,
    *,
    approval_cap: int,
    review_above: int | None = None,
    approve_spender_allowlist: frozenset[str] = frozenset(),
    token_allowlist: frozenset[str] = frozenset(),
) -> OnchainJudgement:
    """Judge a decoded effect against a per-transaction token cap.

    ABSTAIN means no concern — the on-chain "allow", since permission is the
    absence of a concern, not something a policy grants. Above ``review_above``
    (and up to the cap) an amount is held for a human (REVIEW); above the cap, or
    unmapped, it is denied (fail-closed). ``review_above`` is optional and, if
    given, must be below ``approval_cap`` for the band to be reachable.

    A token operation is judged only against a **pinned token**: a ``transfer`` or
    ``approve`` whose target is not in ``token_allowlist`` is denied, because an
    unitless cap says nothing about which asset it bounds (C1) and a look-alike or
    unknown token is not the one that was attested. The allowlist defaults empty,
    so token operations are fail-closed until an asset is pinned. Address is the
    static half of token identity; the co-signer re-verifies the pinned token's
    resolved implementation and code hash against chain before signing (C4).

    An approval carries the extra spender check: even a bounded approval to a
    spender not in ``approve_spender_allowlist`` is denied, because the allowance
    is a standing capability a per-transaction cap cannot bound (C1). The
    allowlist defaults empty, so approvals are fail-closed until a spender is
    deliberately vouched for. A transfer is not gated this way — it is a bounded,
    one-time outflow.
    """
    # Native value is judged before the calldata, on every kind: the first-cut
    # model has no native-value dimension, so any value riding alongside the call
    # is an effect outside the model and is refused rather than silently ignored
    # while the calldata alone is judged (a bounded approve carrying 1000 ETH).
    if effect.native_value > 0:
        return _judge(
            OnchainVerdict.DENY,
            OnchainReasonCode.effect_outside_model,
            observed=effect.native_value,
        )
    if effect.kind is EffectKind.erc20_transfer or effect.kind is EffectKind.erc20_approval:
        # The token identity gate, before amount or spender: an unpinned asset is
        # refused without needing the cap to say anything about it.
        pinned = {token.lower() for token in token_allowlist}
        if effect.target.lower() not in pinned:
            return _judge(OnchainVerdict.DENY, OnchainReasonCode.token_not_allowlisted)
    if effect.kind is EffectKind.erc20_transfer:
        return _judge_amount(effect, approval_cap, review_above)
    if effect.kind is EffectKind.erc20_approval:
        # An amount the effect model could not determine is not zero — it is
        # unknown, and an unknown magnitude on a value-moving call is refused
        # rather than treated as a harmless zero (fail-closed on undecidable).
        if effect.amount is None:
            return _judge(OnchainVerdict.DENY, OnchainReasonCode.effect_outside_model)
        amount = effect.amount
        # The cap is checked first, so an over-cap amount denies as such rather
        # than as a spender problem — the same ordering the fiat amount policy uses.
        if amount > approval_cap:
            return _judge(
                OnchainVerdict.DENY,
                OnchainReasonCode.unbounded_approval,
                observed=amount,
                limit=approval_cap,
            )
        allowlist = {spender.lower() for spender in approve_spender_allowlist}
        counterparty = effect.counterparty
        if counterparty is None or counterparty.lower() not in allowlist:
            # A standing draw capability granted to a party we cannot vouch for:
            # denied regardless of amount, because the spender — not the cap —
            # controls how much and how often the allowance is drawn.
            return _judge(OnchainVerdict.DENY, OnchainReasonCode.counterparty_not_allowlisted)
        return _judge_amount(effect, approval_cap, review_above)
    # Any kind not handled above is refused. `.get` with an explicit DENY default
    # keeps the docstring's fail-closed promise even if a future EffectKind lands
    # without a refusal reason — an unmapped kind denies, it does not raise.
    return _judge(
        OnchainVerdict.DENY,
        _REFUSALS.get(effect.kind, OnchainReasonCode.effect_outside_model),
    )


def _judge_amount(
    effect: OnchainEffect, approval_cap: int, review_above: int | None
) -> OnchainJudgement:
    """The shared amount posture: an undetermined amount denies, over the cap
    denies, the review band holds, the rest raises no concern."""
    if effect.amount is None:
        # Unknown magnitude on a value-moving call — fail closed, do not read as 0.
        return _judge(OnchainVerdict.DENY, OnchainReasonCode.effect_outside_model)
    amount = effect.amount
    if amount > approval_cap:
        return _judge(
            OnchainVerdict.DENY,
            OnchainReasonCode.unbounded_approval,
            observed=amount,
            limit=approval_cap,
        )
    if review_above is not None and amount > review_above:
        return _judge(
            OnchainVerdict.REVIEW,
            OnchainReasonCode.unbounded_approval,
            observed=amount,
            limit=review_above,
        )
    return _ABSTAIN
