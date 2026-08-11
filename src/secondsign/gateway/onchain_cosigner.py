# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The on-chain co-signer — SecondSign's decision as a Safe co-signature.

Control-plane. It holds the SecondSign signing *capability* — a ``SignerProvider``
(ADR 0007), never a raw key — which the managed agent never reaches (the on-chain
analogue of the rail credential; INV-12, enforced by this module living on the
control-plane side of the boundary). Given a proposed Safe
transaction it decodes the effect, judges it, and — only when no concern is raised
— signs the transaction's hash. The signature binds the *exact* transaction (the
same digest-binding as the fiat proposal, ADR 0005 / INV-9): a Safe 2-of-2 in
place of a credential-holding executor. Turn the co-signer off and the agent, one
of two required signers, cannot reach the threshold — so it cannot move value.

Ethereum signing is an optional dependency (``secondsign[onchain]``), imported
lazily so importing this package pulls in no crypto and the deterministic core
still runs without it.

No concern signs, over the cap refuses, and an amount in the review band is held
for a human: the review is carried through the *same* maker-checker the fiat
gateway uses (``resolve`` consumes a checker's answer, one-shot, expiring, bound
to the transaction hash, no self-approval), and only an approval by a different
principal yields the signature. The one thing the fiat gateway does that this does
not is re-decide before consuming, because the first-cut policy is stateless — see
``resolve``.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Final

from secondsign.approval import CheckerVerdict, MakerChecker, MakerIdentity, Rejected
from secondsign.approval.maker_checker import PendingApproval, RejectionReason
from secondsign.audit import AuditLog, AuditSink, InMemoryAuditSink
from secondsign.contracts import Finding, ReasonCode
from secondsign.decision import Decision, DecisionVerdict
from secondsign.gateway.signer import SignerProvider
from secondsign.intent import IntentDigest, ProposalDigest
from secondsign.onchain import policy
from secondsign.onchain.chain_state import ChainStateReader, ExpectedSafeConfig
from secondsign.onchain.effect import SafeAdapter, SafeCall, SafeOperation
from secondsign.onchain.types import (
    OnchainFinding,
    OnchainJudgement,
    OnchainReasonCode,
    OnchainVerdict,
)

#: The on-chain verdict lattice mirrors the plugin one, so it maps onto the fiat
#: decision verdict the audit receipt records exactly as the decision engine does:
#: ABSTAIN (no concern) is the on-chain ALLOW, and REVIEW/DENY carry across.
_VERDICT_TO_DECISION: dict[OnchainVerdict, DecisionVerdict] = {
    OnchainVerdict.ABSTAIN: DecisionVerdict.ALLOW,
    OnchainVerdict.REVIEW: DecisionVerdict.REVIEW,
    OnchainVerdict.DENY: DecisionVerdict.DENY,
}

#: How long an on-chain review stays answerable — long enough for a human in
#: another timezone, short enough that an unanswered approval dies. Mirrors the
#: fiat gateway's ``REVIEW_TTL``.
REVIEW_TTL: timedelta = timedelta(hours=4)

#: A rejection that *settles* a held review, so it must leave the queue — a decline
#: or an expiry. Mirrors the fiat gateway's ``_TERMINAL_REJECTIONS``: a malformed
#: or self-approval answer is not terminal, and leaves the review answerable by a
#: correct checker. Without this, a declined review stays live and a second checker
#: can approve what the first refused (approver shopping).
_TERMINAL_REJECTIONS: Final[frozenset[RejectionReason]] = frozenset(
    {RejectionReason.not_approved, RejectionReason.expired}
)

_DOMAIN_TYPEHASH_TEXT = "EIP712Domain(uint256 chainId,address verifyingContract)"
_SAFE_TX_TYPEHASH_TEXT = (
    "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,"
    "uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
)
_ZERO_ADDRESS = "0x" + "00" * 20


def _load() -> tuple[Any, Any]:
    """The optional hashing/encoding for the transaction hash. Signing itself is
    the SignerProvider's — the co-signer needs no ``eth_account`` of its own."""
    try:
        from eth_abi import encode
        from eth_utils import keccak
    except ImportError as exc:  # pragma: no cover - the message is asserted, not the import failure
        raise RuntimeError(
            "on-chain co-signing needs the optional dependency: pip install 'secondsign[onchain]'"
        ) from exc
    return keccak, encode


def _require_aware(now: datetime) -> None:
    """Refuse a naive ``now`` at the boundary rather than deep inside the hold.

    A naive datetime works on the DENY/ABSTAIN paths and only fails when a REVIEW
    builds an ``AwareDatetime`` expiry, so a caller could ship it and crash on the
    first review-band transaction. Failing here makes it a clear contract error on
    every path, not a path-dependent one.
    """
    if now.tzinfo is None or now.tzinfo.utcoffset(now) is None:
        raise ValueError("now must be timezone-aware")


@dataclass(frozen=True)
class SafeContext:
    """The account the co-signer signs for: its address and chain."""

    safe_address: str
    chain_id: int


def safe_transaction_hash(call: SafeCall, context: SafeContext, nonce: int) -> bytes:
    """The EIP-712 hash the Safe would accept for this transaction.

    Validated byte-for-byte against Safe 1.5.0's ``getTransactionHash`` by a golden
    test, so a signature over this hash is one the real account will honour. The
    gas parameters are zero: a decision co-signature authorises the action, it does
    not price a relayer refund.
    """
    keccak, encode = _load()
    operation = 0 if call.operation is SafeOperation.call else 1
    data = bytes.fromhex(call.data.removeprefix("0x"))
    domain = keccak(
        encode(
            ["bytes32", "uint256", "address"],
            [keccak(text=_DOMAIN_TYPEHASH_TEXT), context.chain_id, context.safe_address],
        )
    )
    struct = keccak(
        encode(
            [
                "bytes32",
                "address",
                "uint256",
                "bytes32",
                "uint8",
                "uint256",
                "uint256",
                "uint256",
                "address",
                "address",
                "uint256",
            ],
            [
                keccak(text=_SAFE_TX_TYPEHASH_TEXT),
                call.to,
                call.value,
                keccak(data),
                operation,
                0,
                0,
                0,
                _ZERO_ADDRESS,
                _ZERO_ADDRESS,
                nonce,
            ],
        )
    )
    return keccak(b"\x19\x01" + domain + struct)


class CosignStatus(StrEnum):
    """What became of a co-signing request. Three states, no fourth for the agent."""

    #: A concern-free (or approved) action; SecondSign's signature is attached.
    signed = "signed"
    #: Held for a human checker; no signature yet. Answer it with ``resolve``.
    held = "held"
    #: A concern was raised, or a held review's answer was not usable; no
    #: signature. The agent, one of two required signers, cannot reach the threshold.
    refused = "refused"


@dataclass(frozen=True)
class CosignOutcome:
    """The co-signer's answer for one proposed transaction."""

    status: CosignStatus
    #: The on-chain judgement behind the answer. ``None`` only when ``resolve`` is
    #: given an approval id the co-signer is not holding.
    judgement: OnchainJudgement | None = None
    #: The 65-byte co-signature as ``0x``-hex, present only when ``signed``.
    signature: str | None = None
    #: The handle a checker answers, present only when ``held``.
    approval_id: str | None = None


@dataclass(frozen=True)
class _HeldReview:
    tx_hash: bytes
    approval: PendingApproval
    judgement: OnchainJudgement
    #: The chain nonce the held transaction hash was built against. If the chain
    #: nonce has advanced by the time a checker answers, the held content can no
    #: longer be the account's next transaction — it is stale and refuses.
    nonce: int


def _drift_judgement(reasons: tuple[OnchainReasonCode, ...]) -> OnchainJudgement:
    """A DENY judgement carrying the chain-re-verification mismatches, so a refusal
    on drift is as auditable as one from the policy."""
    return OnchainJudgement(
        verdict=OnchainVerdict.DENY,
        findings=tuple(OnchainFinding(code=reason) for reason in reasons),
    )


class OnchainCosigner:
    """Holds the SecondSign signing key and co-signs a concern-free transaction.

    A REVIEW-band action is held for a human through the *same* maker-checker the
    fiat gateway uses, and signed only once a *different* principal approves it —
    no self-approval, one-shot, expiring, bound to the transaction hash.
    """

    def __init__(
        self,
        signer: SignerProvider,
        context: SafeContext,
        *,
        approval_cap: int,
        reader: ChainStateReader | None = None,
        expected: ExpectedSafeConfig | None = None,
        review_above: int | None = None,
        approve_spender_allowlist: frozenset[str] = frozenset(),
        review_ttl: timedelta = REVIEW_TTL,
        audit_sink: AuditSink | None = None,
    ) -> None:
        if expected is not None and expected.chain_id != context.chain_id:
            # The hash domain is built from the context's chain id; re-verification
            # attests to the expected one. If they disagree the co-signer would
            # verify against one chain and sign for another — a config error.
            raise ValueError("context.chain_id and expected.chain_id must agree")
        # The signing capability is a provider contract, never a raw key: the
        # co-signer signs through it and holds no key material (ADR 0007).
        self._signer = signer
        self._context = context
        self._adapter = SafeAdapter(context.safe_address)
        self._approval_cap = approval_cap
        #: The chain reader and the attested configuration. Both are required to
        #: sign: a co-signer wired without them re-verifies nothing and so refuses
        #: (fail-closed) rather than trusting the caller for the account and token.
        self._reader = reader
        self._expected = expected
        #: The pinned token: the policy denies a token operation whose target is
        #: not this asset. Empty (fail-closed) until an ExpectedSafeConfig pins one.
        self._token_allowlist = frozenset({expected.token}) if expected is not None else frozenset()
        self._review_above = review_above
        self._approve_spender_allowlist = approve_spender_allowlist
        self._review_ttl = review_ttl
        self._maker_checker = MakerChecker()
        # The append-only, hash-chained trail. Every judged outcome — a signature
        # produced, a review held, a refusal, a decline — is recorded, so a
        # co-signature that moved value is never trailless. A deployment supplies a
        # durable sink; the in-memory reference is enough standalone. The receipt
        # captures the verdict, the transaction-hash digest and the approval id;
        # the on-chain reason codes ride on the returned outcome, not the fiat
        # receipt vocabulary.
        self._audit = AuditLog(audit_sink if audit_sink is not None else InMemoryAuditSink())
        self._pending: dict[str, _HeldReview] = {}
        #: Approval ids whose review has already been granted and signed. A
        #: re-proposal of an already-signed transaction must not be re-held under
        #: the same (now burnt) id — that would be a review no checker can answer.
        self._settled: set[str] = set()
        #: Serialises the held-review lifecycle. The gateway serves on threads, so
        #: hold/resolve must be atomic: two answers to one review racing through
        #: get/consume/delete could otherwise both consume and the second deletion
        #: raise. Mirrors ``AuthorizationService``'s lock.
        self._lock = threading.Lock()

    @property
    def address(self) -> str:
        """The Safe owner address SecondSign co-signs as."""
        return self._signer.address

    def _judge(self, call: SafeCall) -> OnchainJudgement:
        return policy.evaluate(
            self._adapter.decode(call),
            approval_cap=self._approval_cap,
            review_above=self._review_above,
            approve_spender_allowlist=self._approve_spender_allowlist,
            token_allowlist=self._token_allowlist,
        )

    def _reverify(self) -> tuple[int, tuple[OnchainReasonCode, ...]] | None:
        """Read the Safe's live state and the pinned token's identity, and return
        the chain nonce with the mismatches against the attested configuration.

        ``None`` means the co-signer is not wired to verify — no reader or no
        attested config — which is refusal, not a fallback to trusting the caller.
        """
        if self._reader is None or self._expected is None:
            return None
        state = self._reader.read_safe(self._context.safe_address)
        token = self._reader.token_identity(self._expected.token)
        return state.nonce, self._expected.mismatches(state, token)

    def _sign(self, tx_hash: bytes) -> str:
        return self._signer.sign_hash(tx_hash)

    def _record(
        self, tx_hash: bytes, verdict: OnchainVerdict, *, approval_id: str | None = None
    ) -> None:
        """Append one receipt for a judged outcome — the on-chain audit trail.

        The transaction hash is the digest, so the trail names the exact
        transaction the co-signer signed, held or refused (INV-11 on the on-chain
        path). ``outcome_status`` stays ``None``: the co-signer signs, it does not
        dispatch, so there is no execution outcome to record here.
        """
        self._audit.record(
            digest=IntentDigest(value=tx_hash.hex()),
            verdict=_VERDICT_TO_DECISION[verdict],
            approval_id=approval_id,
        )

    def cosign(self, call: SafeCall, *, proposer: str, now: datetime) -> CosignOutcome:
        """Re-verify the chain, decode, judge, and either sign, hold, or refuse.

        The nonce is read from the Safe's live state, never taken from the caller.
        Before anything is judged the account and the pinned token are confirmed to
        match the attested configuration; any drift, or a co-signer not wired to
        verify, refuses. ``proposer`` is the maker — the principal that proposed
        the transaction — recorded so a checker who later approves cannot be the
        same principal. ``now`` must be timezone-aware.
        """
        _require_aware(now)
        verified = self._reverify()
        if verified is None:
            # No reader / no attested config: the account and token cannot be
            # confirmed, so refuse. Absence is refusal, not a trust of the caller.
            return CosignOutcome(status=CosignStatus.refused)
        nonce, drift = verified
        tx_hash = safe_transaction_hash(call, self._context, nonce)
        if drift:
            # The live account or the pinned token has drifted from what was
            # attested — refuse before judging the call, and record it (C4).
            self._record(tx_hash, OnchainVerdict.DENY)
            return CosignOutcome(status=CosignStatus.refused, judgement=_drift_judgement(drift))
        judgement = self._judge(call)
        # Fail-closed at the signing boundary: ABSTAIN — the absence of any concern
        # — is the *only* state that signs, REVIEW holds for a human, and every
        # other verdict (DENY, or anything the vocabulary gains later) refuses.
        # Signing on "not DENY" would treat silence as consent and hand a
        # signature to any effect a first-cut policy has not yet learned to name.
        if judgement.verdict is OnchainVerdict.REVIEW:
            return self._hold(tx_hash, nonce, proposer, now, judgement)
        if judgement.verdict is OnchainVerdict.ABSTAIN:
            signature = self._sign(tx_hash)
            self._record(tx_hash, OnchainVerdict.ABSTAIN)
            return CosignOutcome(
                status=CosignStatus.signed, judgement=judgement, signature=signature
            )
        self._record(tx_hash, OnchainVerdict.DENY)
        return CosignOutcome(status=CosignStatus.refused, judgement=judgement)

    def _hold(
        self,
        tx_hash: bytes,
        nonce: int,
        proposer: str,
        now: datetime,
        judgement: OnchainJudgement,
    ) -> CosignOutcome:
        approval_id = tx_hash.hex()
        with self._lock:
            if approval_id in self._settled:
                # This exact transaction was already reviewed and signed. Its
                # one-shot approval is burnt, so re-holding it would create a
                # review no checker could ever answer — refuse instead.
                return CosignOutcome(status=CosignStatus.refused, judgement=judgement)
            existing = self._pending.get(approval_id)
            if existing is not None:
                # An identical proposal is already held. Return the live review
                # unchanged rather than minting a new one — re-holding would reset
                # the TTL (defeating the expiry bound) and rebind the maker (so the
                # original proposer could then approve their own review).
                return CosignOutcome(
                    status=CosignStatus.held,
                    judgement=existing.judgement,
                    approval_id=approval_id,
                )
            # The maker-checker binds an approval to a proposal digest; on-chain
            # that digest *is* the transaction hash, so a checker approves this
            # exact transaction and nothing else. A REVIEW `Decision` is what the
            # shared maker-checker consumes, so the review is carried through one.
            # The checker-facing finding carries the observed amount and limit from
            # the judgement, so the human sees the magnitude they are approving
            # rather than a bare "value exceeded" sentence.
            band_finding = judgement.findings[0] if judgement.findings else None
            proposal = ProposalDigest(value=approval_id)
            decision = Decision(
                verdict=DecisionVerdict.REVIEW,
                digest=IntentDigest(value=approval_id),
                findings=(
                    Finding(
                        code=ReasonCode.value_band_exceeded,
                        observed=None if band_finding is None else band_finding.observed,
                        limit=None if band_finding is None else band_finding.limit,
                    ),
                ),
            )
            approval = self._maker_checker.request(
                decision,
                MakerIdentity(subject=proposer),
                approval_id=approval_id,
                proposal=proposal,
                expires_at=now + self._review_ttl,
            )
            self._pending[approval_id] = _HeldReview(
                tx_hash=tx_hash, approval=approval, judgement=judgement, nonce=nonce
            )
            self._record(tx_hash, OnchainVerdict.REVIEW, approval_id=approval_id)
            return CosignOutcome(
                status=CosignStatus.held, judgement=judgement, approval_id=approval_id
            )

    def open_reviews(self) -> tuple[PendingApproval, ...]:
        """The reviews awaiting a checker — the approval channel's window onto them.

        The control-plane approval channel enumerates held reviews through this to
        render each :class:`PendingApproval` to a human; without it a REVIEW-band
        transaction would sit invisible until its TTL killed it. Returns the same
        objects a :meth:`resolve` will consume (B3).
        """
        with self._lock:
            return tuple(held.approval for held in self._pending.values())

    def resolve(self, approval_id: str, verdict: CheckerVerdict, *, now: datetime) -> CosignOutcome:
        """A checker's answer to a held review.

        The one-shot answer is consumed — a self-approval, a replay, an expired or
        digest-mismatched answer is refused by the shared maker-checker — and only
        an approval by a *different* principal yields the signature. A **terminal**
        rejection (a decline or an expiry) settles the review and evicts it, so a
        second checker cannot approve what the first declined; a malformed or
        self-approval answer leaves the review answerable by a correct one.

        The chain is re-verified before the answer is consumed, so drift or a stale
        nonce refuses **without burning the human's answer** — re-decision, not
        re-approval (ADR 0005 applied to the chain moving). Only once the live
        account still matches and the held nonce is still current is the one-shot
        spent and the signature produced.
        """
        _require_aware(now)
        with self._lock:
            held = self._pending.get(approval_id)
            if held is None:
                return CosignOutcome(status=CosignStatus.refused)
            verified = self._reverify()
            if verified is None:
                return CosignOutcome(status=CosignStatus.refused)
            nonce, drift = verified
            if drift or nonce != held.nonce:
                # The account drifted, or the chain nonce advanced past the one the
                # held transaction was built for. Either way the approved content is
                # no longer the account's next transaction: refuse and record, but
                # do not consume — the human's answer is not the problem.
                reasons = list(drift)
                if nonce != held.nonce and OnchainReasonCode.effect_outside_model not in reasons:
                    reasons.append(OnchainReasonCode.effect_outside_model)
                self._record(held.tx_hash, OnchainVerdict.DENY, approval_id=approval_id)
                return CosignOutcome(
                    status=CosignStatus.refused, judgement=_drift_judgement(tuple(reasons))
                )
            consumed = self._maker_checker.consume(held.approval, verdict, now=now)
            if isinstance(consumed, Rejected):
                if consumed.reason in _TERMINAL_REJECTIONS:
                    # A decline or expiry settles the review; it must leave the
                    # queue so it cannot be re-answered (approver shopping), and
                    # the settlement is recorded — the trail shows a review was
                    # refused, not just that it went quiet.
                    del self._pending[approval_id]
                    self._record(held.tx_hash, OnchainVerdict.DENY, approval_id=approval_id)
                return CosignOutcome(status=CosignStatus.refused, judgement=held.judgement)
            del self._pending[approval_id]
            self._settled.add(approval_id)
            signature = self._sign(held.tx_hash)
            self._record(held.tx_hash, OnchainVerdict.ABSTAIN, approval_id=approval_id)
            return CosignOutcome(
                status=CosignStatus.signed,
                judgement=held.judgement,
                signature=signature,
            )
