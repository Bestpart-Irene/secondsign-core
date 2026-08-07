# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""A first-cut on-chain effect policy — a decoded effect to a judgement.

This is the minimal decision the co-signer needs to withhold or grant its
signature. A ``delegatecall``, a self-administration, an unrecognised call, or a
token approval or transfer above the cap is refused; a bounded token operation
raises no concern. It reuses the ONCHAIN-S002 judgement vocabulary rather than a
second engine, and stays a single policy — the velocity window and maker-checker
of the fiat path are reused at the gateway, not reimplemented here.

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


def _deny(
    code: OnchainReasonCode, *, observed: int | None = None, limit: int | None = None
) -> OnchainJudgement:
    finding = OnchainFinding(
        code=code,
        observed=None if observed is None else _bounded(observed),
        limit=None if limit is None else _bounded(limit),
    )
    return OnchainJudgement(verdict=OnchainVerdict.DENY, findings=(finding,))


def evaluate(effect: OnchainEffect, *, approval_cap: int) -> OnchainJudgement:
    """Judge a decoded effect against a per-transaction token cap.

    ABSTAIN means no concern — the on-chain "allow", since permission is the
    absence of a concern, not something a policy grants. Everything unmapped or
    over the cap denies (fail-closed).
    """
    if effect.kind is EffectKind.erc20_approval or effect.kind is EffectKind.erc20_transfer:
        amount = effect.amount if effect.amount is not None else 0
        if amount > approval_cap:
            return _deny(OnchainReasonCode.unbounded_approval, observed=amount, limit=approval_cap)
        return _ABSTAIN
    return _deny(_REFUSALS[effect.kind])
