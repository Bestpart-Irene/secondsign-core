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
) -> OnchainJudgement:
    """Judge a decoded effect against a per-transaction token cap.

    ABSTAIN means no concern — the on-chain "allow", since permission is the
    absence of a concern, not something a policy grants. Above ``review_above``
    (and up to the cap) an amount is held for a human (REVIEW); above the cap, or
    unmapped, it is denied (fail-closed). ``review_above`` is optional and, if
    given, must be below ``approval_cap`` for the band to be reachable.

    An approval carries the extra spender check: even a bounded approval to a
    spender not in ``approve_spender_allowlist`` is denied, because the allowance
    is a standing capability a per-transaction cap cannot bound (C1). The
    allowlist defaults empty, so approvals are fail-closed until a spender is
    deliberately vouched for. A transfer is not gated this way — it is a bounded,
    one-time outflow.
    """
    if effect.kind is EffectKind.erc20_transfer:
        return _judge_amount(effect, approval_cap, review_above)
    if effect.kind is EffectKind.erc20_approval:
        amount = effect.amount if effect.amount is not None else 0
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
    return _judge(OnchainVerdict.DENY, _REFUSALS[effect.kind])


def _judge_amount(
    effect: OnchainEffect, approval_cap: int, review_above: int | None
) -> OnchainJudgement:
    """The shared amount posture: over the cap denies, the review band holds, the
    rest raises no concern."""
    amount = effect.amount if effect.amount is not None else 0
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
