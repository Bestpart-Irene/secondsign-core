# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The on-chain co-signer — SecondSign's decision as a Safe co-signature.

Control-plane. It holds the SecondSign signing key, which the managed agent never
reaches (the on-chain analogue of the rail credential; INV-12, enforced by this
module living on the control-plane side of the boundary). Given a proposed Safe
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
from secondsign.contracts import Finding, ReasonCode
from secondsign.decision import Decision, DecisionVerdict
from secondsign.intent import IntentDigest, ProposalDigest
from secondsign.onchain import policy
from secondsign.onchain.effect import SafeAdapter, SafeCall, SafeOperation
from secondsign.onchain.types import OnchainJudgement, OnchainVerdict

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

#: A uint256 ceiling: ``value`` and ``nonce`` are ABI-encoded as ``uint256`` when
#: the transaction hash is built, so anything at or above this is not a valid Safe
#: transaction field and is refused before it reaches ``eth_abi`` (which would
#: raise rather than return a clean refusal).
_UINT256 = 1 << 256

_DOMAIN_TYPEHASH_TEXT = "EIP712Domain(uint256 chainId,address verifyingContract)"
_SAFE_TX_TYPEHASH_TEXT = (
    "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,"
    "uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
)
_ZERO_ADDRESS = "0x" + "00" * 20


def _load() -> tuple[Any, Any, Any]:
    """The optional Ethereum crypto, or a clear message pointing at the extra."""
    try:
        from eth_abi import encode
        from eth_account import Account
        from eth_utils import keccak
    except ImportError as exc:  # pragma: no cover - the message is asserted, not the import failure
        raise RuntimeError(
            "on-chain co-signing needs the optional dependency: pip install 'secondsign[onchain]'"
        ) from exc
    return keccak, encode, Account


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
    keccak, encode, _ = _load()
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


class OnchainCosigner:
    """Holds the SecondSign signing key and co-signs a concern-free transaction.

    A REVIEW-band action is held for a human through the *same* maker-checker the
    fiat gateway uses, and signed only once a *different* principal approves it —
    no self-approval, one-shot, expiring, bound to the transaction hash.
    """

    def __init__(
        self,
        private_key: bytes,
        context: SafeContext,
        *,
        approval_cap: int,
        review_above: int | None = None,
        approve_spender_allowlist: frozenset[str] = frozenset(),
        review_ttl: timedelta = REVIEW_TTL,
    ) -> None:
        _, _, account_cls = _load()
        self._account = account_cls.from_key(private_key)
        self._context = context
        self._adapter = SafeAdapter(context.safe_address)
        self._approval_cap = approval_cap
        self._review_above = review_above
        self._approve_spender_allowlist = approve_spender_allowlist
        self._review_ttl = review_ttl
        self._maker_checker = MakerChecker()
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
        return str(self._account.address)

    def _judge(self, call: SafeCall) -> OnchainJudgement:
        return policy.evaluate(
            self._adapter.decode(call),
            approval_cap=self._approval_cap,
            review_above=self._review_above,
            approve_spender_allowlist=self._approve_spender_allowlist,
        )

    def _sign(self, tx_hash: bytes) -> str:
        return "0x" + self._account.unsafe_sign_hash(tx_hash).signature.hex()

    def cosign(self, call: SafeCall, nonce: int, *, proposer: str, now: datetime) -> CosignOutcome:
        """Decode, judge, and either sign, hold for a human, or refuse.

        ``proposer`` is the maker — the principal that proposed the transaction —
        recorded so a checker who later approves cannot be the same principal.
        ``now`` must be timezone-aware, and ``nonce`` a uint256; a naive datetime
        or an out-of-range field is a caller error, refused before any hashing.
        """
        _require_aware(now)
        # `value` is bounded by SafeCall; `nonce` is a bare parameter, so it is
        # range-checked here — an out-of-range uint256 would raise inside eth_abi
        # rather than return a clean refusal.
        if not 0 <= nonce < _UINT256:
            return CosignOutcome(status=CosignStatus.refused)
        judgement = self._judge(call)
        # Fail-closed at the signing boundary: ABSTAIN — the absence of any concern
        # — is the *only* state that signs, REVIEW holds for a human, and every
        # other verdict (DENY, or anything the vocabulary gains later) refuses.
        # Signing on "not DENY" would treat silence as consent and hand a
        # signature to any effect a first-cut policy has not yet learned to name.
        if judgement.verdict is OnchainVerdict.REVIEW:
            return self._hold(
                safe_transaction_hash(call, self._context, nonce), proposer, now, judgement
            )
        if judgement.verdict is OnchainVerdict.ABSTAIN:
            tx_hash = safe_transaction_hash(call, self._context, nonce)
            return CosignOutcome(
                status=CosignStatus.signed, judgement=judgement, signature=self._sign(tx_hash)
            )
        return CosignOutcome(status=CosignStatus.refused, judgement=judgement)

    def _hold(
        self,
        tx_hash: bytes,
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
                tx_hash=tx_hash, approval=approval, judgement=judgement
            )
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

        A re-decision before consuming is deliberately absent while the policy is
        stateless: a held action re-judges to the same REVIEW, so it would change
        nothing. When the policy gains external state that can tighten a held
        action (a velocity window, as the fiat gateway has), re-decide-before-
        consume must return here, exactly as ``AuthorizationService.resolve`` does.
        """
        _require_aware(now)
        with self._lock:
            held = self._pending.get(approval_id)
            if held is None:
                return CosignOutcome(status=CosignStatus.refused)
            consumed = self._maker_checker.consume(held.approval, verdict, now=now)
            if isinstance(consumed, Rejected):
                if consumed.reason in _TERMINAL_REJECTIONS:
                    # A decline or expiry settles the review; it must leave the
                    # queue so it cannot be re-answered (approver shopping).
                    del self._pending[approval_id]
                return CosignOutcome(status=CosignStatus.refused, judgement=held.judgement)
            del self._pending[approval_id]
            self._settled.add(approval_id)
            return CosignOutcome(
                status=CosignStatus.signed,
                judgement=held.judgement,
                signature=self._sign(held.tx_hash),
            )
