# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Experimental on-chain decision vocabulary — UNFROZEN, contract version 0.

This is the candidate type surface for on-chain decisions (ONCHAIN-S002). It is
deliberately kept **out** of the frozen v1 contract surface: v1
(:mod:`secondsign.contracts`, ``CONTRACT_VERSION`` 1) does not change, this
package carries its own version constant set to ``0``, and no v1 module imports
it. Nothing here is a compatibility promise until a later freeze slice raises the
version to 1 — until then a field, a code or a verdict may be added, removed or
renamed.

The verdict and finding *shapes* mirror the v1 plugin surface — ``ABSTAIN`` /
``REVIEW`` / ``DENY`` with no ``ALLOW``, a closed reason vocabulary, and bounded
quantities — so the combination algebra and the anti-identifier bound carry over
unchanged. What is genuinely new is the reason vocabulary: every on-chain code
names a specific red-team case from ``docs/ONCHAIN_THREAT_MODEL.md``, so a code
cannot exist without a threat it answers.
"""

from enum import IntEnum, StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

#: This surface is a candidate, not a promise. It reaches ``1`` only when a
#: freeze slice deliberately makes it one; until then it is ``0`` and unfrozen.
ONCHAIN_CONTRACT_VERSION = 0

#: The anti-identifier ceiling, mirrored from v1 so an on-chain quantity cannot
#: carry an account number. Kept as its own constant rather than imported from
#: the frozen surface: a candidate surface owns its constants until it freezes.
_MAX_DETAIL_MAGNITUDE = 1_000_000_000_000


class OnchainVerdict(IntEnum):
    """What an on-chain policy may say.

    Mirrors :class:`~secondsign.contracts.PluginVerdict`: there is no ``ALLOW``,
    and the members are ordered by strictness so that combining two judgements is
    a maximum — permission remains the absence of concern, not something a policy
    grants.
    """

    ABSTAIN = 0
    REVIEW = 1
    DENY = 2


class OnchainReasonCode(StrEnum):
    """Closed, stable codes for on-chain concerns.

    Each code names at least one red-team case in the on-chain threat model (see
    :data:`RED_TEAM_COVERAGE`). The vocabulary is closed: an unrecognised string
    cannot be constructed, so a policy cannot smuggle prose through a code.
    """

    unbounded_approval = "unbounded_approval"
    counterparty_not_allowlisted = "counterparty_not_allowlisted"
    token_not_allowlisted = "token_not_allowlisted"  # noqa: S105 — a reason code, not a secret
    unrecognised_authorisation = "unrecognised_authorisation"
    structural_change = "structural_change"
    delegatecall = "delegatecall"
    implementation_moved = "implementation_moved"
    unknown_selector = "unknown_selector"
    effect_outside_model = "effect_outside_model"
    unbounded_slippage = "unbounded_slippage"
    replayed_signature = "replayed_signature"
    calldata_diverged = "calldata_diverged"


#: The provenance of every on-chain reason code: the red-team case(s) it answers.
#: A test asserts this direction is **total** — every code is covered — and that
#: every referenced ``C-RT-NNN`` actually exists in the threat model, so a code
#: cannot point at a case that was never written down.
RED_TEAM_COVERAGE: dict[OnchainReasonCode, frozenset[str]] = {
    OnchainReasonCode.unbounded_approval: frozenset(
        {"C-RT-001", "C-RT-002", "C-RT-003", "C-RT-004"}
    ),
    # An approval hands a *standing* draw capability to a counterparty: the spender
    # can pull repeatedly within the allowance at a time when SecondSign is not on
    # the path, so a per-transaction cap cannot bound it (C1). The threat model's
    # answer is an explicit spender allowlist, never a heuristic match — an
    # approval to an un-vouched party is the arbitrary/multi-spender exposure of
    # C-RT-001/003/004, not merely an over-cap amount.
    OnchainReasonCode.counterparty_not_allowlisted: frozenset({"C-RT-001", "C-RT-003", "C-RT-004"}),
    # A token that is not the pinned asset — an unknown or look-alike contract, or
    # a proxy whose identity cannot be vouched for. Treated as an unknown contract
    # (C-RT-011) and an asset-identity failure (C-RT-024), both DENY.
    OnchainReasonCode.token_not_allowlisted: frozenset({"C-RT-011", "C-RT-024"}),
    OnchainReasonCode.unrecognised_authorisation: frozenset({"C-RT-006"}),
    OnchainReasonCode.structural_change: frozenset({"C-RT-007", "C-RT-008", "C-RT-016"}),
    OnchainReasonCode.delegatecall: frozenset({"C-RT-009"}),
    OnchainReasonCode.implementation_moved: frozenset({"C-RT-010", "C-RT-011"}),
    OnchainReasonCode.unknown_selector: frozenset({"C-RT-012"}),
    OnchainReasonCode.effect_outside_model: frozenset({"C-RT-013"}),
    OnchainReasonCode.unbounded_slippage: frozenset({"C-RT-018"}),
    OnchainReasonCode.replayed_signature: frozenset({"C-RT-019"}),
    OnchainReasonCode.calldata_diverged: frozenset({"C-RT-026"}),
}


class OnchainFinding(BaseModel):
    """One on-chain observation, in closed vocabulary.

    Mirrors :class:`~secondsign.contracts.Finding`: no prose, and the optional
    quantities are bounded so they cannot carry an identifier.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: OnchainReasonCode
    observed: int | None = Field(default=None, ge=0, le=_MAX_DETAIL_MAGNITUDE)
    limit: int | None = Field(default=None, ge=0, le=_MAX_DETAIL_MAGNITUDE)


class OnchainJudgement(BaseModel):
    """What an on-chain policy returns.

    Mirrors :class:`~secondsign.contracts.PluginJudgement`: an ``ABSTAIN`` needs
    nothing, and anything stronger must carry at least one finding — a concern
    nobody can act on is not a concern.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    onchain_contract_version: int = ONCHAIN_CONTRACT_VERSION
    verdict: OnchainVerdict
    findings: tuple[OnchainFinding, ...] = ()

    @property
    def reasons(self) -> tuple[OnchainReasonCode, ...]:
        """The distinct reason codes, in finding order. Derived, not stored."""
        return tuple(dict.fromkeys(finding.code for finding in self.findings))

    @model_validator(mode="after")
    def _non_abstain_carries_a_finding(self) -> "OnchainJudgement":
        if self.verdict is not OnchainVerdict.ABSTAIN and not self.findings:
            raise ValueError("a non-ABSTAIN judgement must carry at least one finding")
        return self
