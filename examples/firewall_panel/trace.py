# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""One judgement, reconstructed as the seven stations a proposal passes through.

**This module is an observer, and that is a deliberate constraint.** The
co-signer returns a verdict, not a narrative: ``CosignOutcome`` carries the
status, the judgement, the signature and the approval id, and says nothing about
what the decode produced or what the re-verification read. To show the reasoning,
the panel recomputes each station through the *same public API* the co-signer
uses — ``SafeAdapter.decode``, ``ExpectedSafeConfig.mismatches``,
``policy.evaluate`` — rather than instrumenting the signing boundary, which is
the most security-sensitive file in the repository and must not grow display
concerns.

The honest risk is drift: a recomputation can disagree with what the co-signer
actually did if the co-signer's ordering changes later, and a panel that
confidently shows the wrong reasoning is worse than one that shows none. The
control is :func:`implied_status` plus the test that pins it to the real
``CosignOutcome.status`` across the whole scenario-by-knob matrix. Every station
also carries its :attr:`Station.provenance`, so the UI can say which conclusions
are authoritative and which are reconstructed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from secondsign.gateway.onchain_cosigner import CosignOutcome, CosignStatus
from secondsign.onchain import policy
from secondsign.onchain.chain_state import ChainStateReader, ExpectedSafeConfig
from secondsign.onchain.effect import SafeAdapter, SafeCall
from secondsign.onchain.types import OnchainVerdict

#: A station's conclusion, for styling and for :func:`implied_status`.
PASS = "pass"  # noqa: S105 — a CSS class name, not a credential
REFUSE = "refuse"
HOLD = "hold"
#: Never reached, because an earlier station already ended the proposal.
SKIPPED = "skipped"
#: Real, but not executed by this panel — station ⑦ only.
INERT = "inert"

#: Where a station's conclusion came from.
OBSERVED = "observed"
COSIGNER = "cosigner"


@dataclass(frozen=True)
class Station:
    """One step of the decision, as the panel renders it."""

    key: str
    ordinal: str
    title: str
    state: str
    summary: str
    #: Label/value rows — the internal state that is otherwise invisible.
    facts: tuple[tuple[str, str], ...] = ()
    provenance: str = OBSERVED


@dataclass(frozen=True)
class Trace:
    stations: tuple[Station, ...]
    #: The verdict the reconstruction implies. Compared against the real
    #: ``CosignOutcome.status`` by the consistency test — never shown as the
    #: answer, which always comes from the co-signer.
    implied: str
    findings: tuple[str, ...] = field(default_factory=tuple)


#: The four constitutional invariants the Solidity double guard enforces at
#: execution. Rendered so the last line of defence is visible, and marked inert
#: because this panel runs no EVM — see the panel's stated boundary.
GUARD_INVARIANTS: tuple[str, ...] = (
    "the agent reconfigures nothing (owners, threshold, guards, modules)",
    "the second signature cannot be removed from the signing path",
    "the module path reaches swapOwner and nothing else",
    "a refusal is an executed refusal, not an unenforced opinion",
)


def reverify_station(
    safe_address: str,
    reader: ChainStateReader | None,
    expected: ExpectedSafeConfig | None,
) -> tuple[Station, tuple[str, ...]]:
    """Station ① on its own, with the drift it found.

    Shared by :func:`observe` and :func:`observe_resolution` because the
    co-signer itself re-verifies in both places — on ``cosign`` and again on
    ``resolve``. One function here keeps the panel from implying the second
    read is a different, weaker check than the first.
    """
    if reader is None or expected is None:
        return (
            Station(
                key="reverify",
                ordinal="①",
                title="Chain re-verification",
                state=REFUSE,
                summary="Not wired to read the chain — so nothing can be confirmed, so nothing is signed.",
                facts=(
                    ("reader", "absent" if reader is None else "present"),
                    ("attested config", "absent" if expected is None else "present"),
                    ("posture", "absence is refusal, not a fallback to trusting the caller"),
                ),
            ),
            (),
        )
    state = reader.read_safe(safe_address)
    token = reader.token_identity(expected.token)
    drift = expected.mismatches(state, token)
    if drift:
        return (
            Station(
                key="reverify",
                ordinal="①",
                title="Chain re-verification",
                state=REFUSE,
                summary="The live account no longer matches what was attested. Refused before the call is even judged.",
                facts=(
                    ("drift", ", ".join(reason.value for reason in drift)),
                    *_account_facts(state, expected, token),
                ),
            ),
            tuple(reason.value for reason in drift),
        )
    return (
        Station(
            key="reverify",
            ordinal="①",
            title="Chain re-verification",
            state=PASS,
            summary="The live account and the pinned token match the attestation. Nonce read from chain, never from the caller.",
            facts=(
                ("nonce (from chain)", str(state.nonce)),
                *_account_facts(state, expected, token),
            ),
        ),
        (),
    )


def observe_resolution(
    outcome: CosignOutcome,
    *,
    safe_address: str,
    reader: ChainStateReader | None,
    expected: ExpectedSafeConfig | None,
    checker: str,
    approved: bool,
) -> Trace:
    """The stations a *checker's answer* passes through — not a full proposal.

    ``resolve`` re-verifies the chain and then consumes the one-shot answer, so
    only stations ①, ⑤ and ⑥ are live. Rendering the full seven here would
    leave a stale ``PASS`` from the original proposal sitting under a refusal
    the second read produced — the panel would contradict itself on screen.
    """
    station, drift = reverify_station(safe_address, reader, expected)
    signed = outcome.status is CosignStatus.signed
    answer = Station(
        key="review",
        ordinal="⑤",
        title="Human review",
        state=PASS if signed else REFUSE,
        summary=(
            f"Answered by {checker}. "
            + (
                "A different principal than the maker, so the one-shot approval was spent and the signature produced."
                if signed
                else "No signature: the answer was declined, came from the proposer, or the chain moved while the human was deciding."
            )
        ),
        facts=(
            ("answered as", checker),
            ("answer", "approve" if approved else "decline"),
            ("result", outcome.status.value),
            ("signature", outcome.signature or "none"),
        ),
        provenance=COSIGNER,
    )
    receipt = Station(
        key="audit",
        ordinal="⑥",
        title="Audit receipt",
        state=PASS,
        summary="The answer is recorded too — an approval that led nowhere is still evidence.",
        facts=(("outcome", outcome.status.value),),
        provenance=COSIGNER,
    )
    return Trace(stations=(station, answer, receipt), implied=outcome.status.value, findings=drift)


def observe(
    call: SafeCall,
    outcome: CosignOutcome,
    *,
    safe_address: str,
    reader: ChainStateReader | None,
    expected: ExpectedSafeConfig | None,
    approval_cap: int,
    review_above: int | None,
    approve_spender_allowlist: frozenset[str],
    token_allowlist: frozenset[str],
) -> Trace:
    """Rebuild the seven stations for one proposal.

    ``outcome`` is the authoritative answer and is used for the stations that
    only the co-signer can report (the hold, the receipt). The earlier stations
    are recomputed.
    """
    stations: list[Station] = []

    # ① Chain re-verification.
    station, drift = reverify_station(safe_address, reader, expected)
    stations.append(station)
    if station.state == REFUSE or reader is None or expected is None:
        # ``implied`` is a CosignStatus value ("refused"), not a station state
        # ("refuse"). The two vocabularies are one letter apart and mean
        # different things; conflating them is what the consistency test caught.
        return _finish(stations, CosignStatus.refused.value, outcome, skip_from=1, findings=drift)

    # ② Decode.
    effect = SafeAdapter(safe_address).decode(call)
    stations.append(
        Station(
            key="decode",
            ordinal="②",
            title="Decode",
            state=PASS,
            summary=f"The proposal is a {effect.kind.value.replace('_', ' ')}.",
            facts=(
                ("kind", effect.kind.value),
                ("target", effect.target),
                ("selector", effect.selector or "—"),
                ("counterparty", effect.counterparty or "—"),
                ("amount", "—" if effect.amount is None else _amount(effect.amount)),
                ("native value", _wei(effect.native_value)),
            ),
        )
    )

    # ③ Policy.
    judgement = policy.evaluate(
        effect,
        approval_cap=approval_cap,
        review_above=review_above,
        approve_spender_allowlist=approve_spender_allowlist,
        token_allowlist=token_allowlist,
    )
    reasons = tuple(finding.code.value for finding in judgement.findings)
    verdict = judgement.verdict
    stations.append(
        Station(
            key="policy",
            ordinal="③",
            title="Policy",
            state={OnchainVerdict.ABSTAIN: PASS, OnchainVerdict.REVIEW: HOLD}.get(verdict, REFUSE),
            summary=_policy_summary(verdict, reasons),
            facts=(
                # ``OnchainVerdict`` is an IntEnum ordered by strictness, so
                # ``.value`` is 0/1/2 — the name is the word a reader needs.
                ("verdict", verdict.name),
                ("reason", ", ".join(reasons) or "no concern raised"),
                *_band_facts(judgement),
                ("per-transaction cap", _amount(approval_cap)),
                ("review above", "—" if review_above is None else _amount(review_above)),
                ("pinned tokens", ", ".join(sorted(token_allowlist)) or "none (fail-closed)"),
                (
                    "vouched spenders",
                    ", ".join(sorted(approve_spender_allowlist)) or "none (fail-closed)",
                ),
            ),
        )
    )

    # ④ Signing boundary.
    if verdict is OnchainVerdict.ABSTAIN:
        boundary_state, boundary = (
            PASS,
            "ABSTAIN — the absence of any concern. This is the only state that signs.",
        )
        implied = CosignStatus.signed.value
    elif verdict is OnchainVerdict.REVIEW:
        boundary_state, boundary = HOLD, "REVIEW — held for a human. No signature yet."
        implied = CosignStatus.held.value
    else:
        boundary_state, boundary = REFUSE, f"{verdict.name} — no signature. Silence is not consent."
        implied = CosignStatus.refused.value
    stations.append(
        Station(
            key="boundary",
            ordinal="④",
            title="Signing boundary",
            state=boundary_state,
            summary=boundary,
            facts=(
                ("rule", "only ABSTAIN signs; REVIEW holds; everything else refuses"),
                ("signature", outcome.signature or "none"),
            ),
            provenance=COSIGNER,
        )
    )
    return _finish(stations, implied, outcome, skip_from=4, findings=reasons)


def _finish(
    stations: list[Station],
    implied: str,
    outcome: CosignOutcome,
    *,
    skip_from: int,
    findings: tuple[str, ...] = (),
) -> Trace:
    """Append stations ⑤–⑦, marking as skipped whatever the proposal never reached."""
    reached_review = outcome.status is CosignStatus.held
    if skip_from <= 3:
        for key, ordinal, title in (
            ("decode", "②", "Decode"),
            ("policy", "③", "Policy"),
            ("boundary", "④", "Signing boundary"),
        ):
            stations.append(
                Station(
                    key=key,
                    ordinal=ordinal,
                    title=title,
                    state=SKIPPED,
                    summary="Never reached — the account could not be confirmed.",
                )
            )
    stations.append(
        Station(
            key="review",
            ordinal="⑤",
            title="Human review",
            state=HOLD if reached_review else SKIPPED,
            summary=(
                "Held for a checker. The chain is re-verified again when the answer arrives, "
                "and the proposer cannot approve their own proposal."
            )
            if reached_review
            else "Not reached — no review was held.",
            facts=(("approval id", outcome.approval_id or "—"),),
            provenance=COSIGNER,
        )
    )
    stations.append(
        Station(
            key="audit",
            ordinal="⑥",
            title="Audit receipt",
            state=PASS,
            summary="One record, whatever the outcome. The digest is the Safe transaction hash, so the trail names the exact transaction.",
            facts=(("outcome", outcome.status.value),),
            provenance=COSIGNER,
        )
    )
    stations.append(
        Station(
            key="guard",
            ordinal="⑦",
            title="On-chain double guard",
            state=INERT,
            summary="The last line, enforced in Solidity at execution. This panel runs no EVM, so these are shown, not executed.",
            facts=tuple((f"invariant {i}", text) for i, text in enumerate(GUARD_INVARIANTS, 1)),
        )
    )
    return Trace(stations=tuple(stations), implied=implied, findings=findings)


def implied_status(trace: Trace) -> str:
    """The status the reconstruction implies — pinned to the real one by test."""
    return trace.implied


def _policy_summary(verdict: OnchainVerdict, reasons: tuple[str, ...]) -> str:
    if verdict is OnchainVerdict.ABSTAIN:
        return "No concern raised. Permission is the absence of a concern, not something a policy grants."
    joined = ", ".join(reasons) or verdict.name
    return f"Concern raised: {joined}."


def _band_facts(judgement) -> tuple[tuple[str, str], ...]:  # noqa: ANN001 — local shape
    finding = judgement.findings[0] if judgement.findings else None
    if finding is None or (finding.observed is None and finding.limit is None):
        return ()
    return (
        ("observed", "—" if finding.observed is None else _amount(finding.observed)),
        ("limit", "—" if finding.limit is None else _amount(finding.limit)),
    )


def _account_facts(state, expected, token) -> tuple[tuple[str, str], ...]:  # noqa: ANN001
    return (
        ("chain", f"{state.chain_id} (attested {expected.chain_id})"),
        ("Safe version", state.safe_version),
        (
            "owners · threshold",
            f"{len(state.owners)} owners · {state.threshold}-of-{len(state.owners)}",
        ),
        ("transaction guard", state.transaction_guard),
        ("module guard", state.module_guard),
        ("token implementation", token.implementation),
        ("token code hash", token.code_hash[:18] + "…"),
    )


def _amount(minor: int) -> str:
    """USDC minor units, rendered readably. Huge values are named, not printed —
    ``2**256-1`` as digits tells a reader nothing."""
    if minor >= 2**255:
        return "unlimited (2²⁵⁶−1)"
    if minor >= 10**12:
        return f"{minor / 10**6:,.0f} USDC"
    return f"{minor / 10**6:,.2f} USDC"


def _wei(value: int) -> str:
    if value == 0:
        return "0"
    return f"{value / 10**18:g} ETH"
