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

First cut: an ALLOW (ABSTAIN, no concern) signs and anything stronger refuses. The
REVIEW → maker-checker → sign path (holding for a human, as the fiat gateway does)
is the remaining acceptance criterion of ONCHAIN-S004 and is not wired here yet;
until it is, a review-worthy action is refused rather than signed, which is
fail-closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from secondsign.onchain import policy
from secondsign.onchain.effect import SafeAdapter, SafeCall, SafeOperation
from secondsign.onchain.types import OnchainJudgement, OnchainVerdict

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
    """What became of a co-signing request. No fourth state for the agent to read."""

    #: A concern-free action; SecondSign's signature is attached.
    signed = "signed"
    #: A concern was raised; no signature. The agent cannot reach the threshold.
    refused = "refused"


@dataclass(frozen=True)
class CosignOutcome:
    """The co-signer's answer for one proposed transaction."""

    status: CosignStatus
    judgement: OnchainJudgement
    #: The 65-byte co-signature as ``0x``-hex, present only when ``signed``.
    signature: str | None = None


class OnchainCosigner:
    """Holds the SecondSign signing key and co-signs a concern-free transaction."""

    def __init__(self, private_key: bytes, context: SafeContext, *, approval_cap: int) -> None:
        _, _, account_cls = _load()
        self._account = account_cls.from_key(private_key)
        self._context = context
        self._adapter = SafeAdapter(context.safe_address)
        self._approval_cap = approval_cap

    @property
    def address(self) -> str:
        """The Safe owner address SecondSign co-signs as."""
        return str(self._account.address)

    def cosign(self, call: SafeCall, nonce: int) -> CosignOutcome:
        """Decode, judge, and co-sign only if no concern is raised."""
        effect = self._adapter.decode(call)
        judgement = policy.evaluate(effect, approval_cap=self._approval_cap)
        if judgement.verdict is not OnchainVerdict.ABSTAIN:
            # DENY (and, until maker-checker is wired, a would-be REVIEW) attaches
            # no signature — the agent, one of two required signers, cannot proceed.
            return CosignOutcome(status=CosignStatus.refused, judgement=judgement)
        tx_hash = safe_transaction_hash(call, self._context, nonce)
        signature = self._account.unsafe_sign_hash(tx_hash).signature
        return CosignOutcome(
            status=CosignStatus.signed, judgement=judgement, signature="0x" + signature.hex()
        )
