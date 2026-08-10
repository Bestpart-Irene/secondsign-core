# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The chain-state port — the facts the co-signer re-reads before it signs.

The co-signer must not trust the agent for the signable content or the account it
signs for (ONCHAIN-S007, threat C4). Before every signature it reads the Safe's
live state and the pinned token's identity and confirms both match what was
attested; any drift refuses. This module is that port and its data — not a client.

**No network, no RPC, no secret.** Core defines :class:`ChainStateReader` as a
protocol and ships a deterministic :class:`StaticChainStateReader`; the live Base
RPC implementation — including how a proxy standard resolves its implementation
slot — belongs to the deployment. The decision stays a pure function of the read
state, so the deterministic-kernel invariant (ADR 0001) holds: the chain is the
non-deterministic part, and it lives outside this boundary, exactly as the spend
window and the audit sink do. It is the same open/closed split the signing key
takes — a public contract a self-hoster can implement, an operated live service.

The verdict vocabulary is the shared on-chain one
(:mod:`secondsign.onchain.types`); this module carries no control-plane asset, so
it is ``shared``. The *deciding* — refusing on a non-empty mismatch — is the
co-signer's, control-plane-side.
"""

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from secondsign.onchain.types import OnchainReasonCode

#: A 20-byte Ethereum address. Case is not normalised here (EIP-55 checksums are
#: mixed-case on purpose); comparisons below lower-case both sides.
_ADDRESS = r"^0x[0-9a-fA-F]{40}$"
#: A 32-byte hash as ``0x`` + 64 hex digits — a contract's code hash.
_CODE_HASH = r"^0x[0-9a-fA-F]{64}$"


def _same_address(a: str, b: str) -> bool:
    return a.lower() == b.lower()


class TokenIdentity(BaseModel):
    """A token's *code* identity, resolved through any proxy.

    Binding a proxy's own code hash is not enough — its bytecode is stable while
    the implementation slot moves (C4), and canonical USDC is such a proxy. What
    is bound is the resolved implementation address and that implementation's code
    hash, so an upgrade is visible as drift.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    implementation: str = Field(pattern=_ADDRESS)
    code_hash: str = Field(pattern=_CODE_HASH)

    def matches(self, other: "TokenIdentity") -> bool:
        return _same_address(self.implementation, other.implementation) and (
            self.code_hash.lower() == other.code_hash.lower()
        )


class SafeChainState(BaseModel):
    """The Safe's live configuration, as read from chain.

    Everything the co-signer must confirm before it signs: the nonce it will
    actually sign against, the owner set and threshold, both guards, the chain,
    and the Safe version whose behaviour the topology was falsified against.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    #: A uint256, so bounded — the nonce is ABI-encoded as one when the hash is
    #: built, and an out-of-range value would raise inside eth_abi.
    nonce: int = Field(ge=0, lt=1 << 256)
    owners: tuple[str, ...]
    threshold: int = Field(ge=1)
    #: The installed transaction guard, or the zero address if none.
    transaction_guard: str = Field(pattern=_ADDRESS)
    #: The installed module guard, or the zero address if none.
    module_guard: str = Field(pattern=_ADDRESS)
    chain_id: int = Field(ge=1)
    safe_version: str = Field(min_length=1)


class ExpectedSafeConfig(BaseModel):
    """What the co-signer attests the account and token to be.

    The co-signer signs only while the live :class:`SafeChainState` and the pinned
    token's :class:`TokenIdentity` match this. It is the on-chain analogue of the
    decision-time snapshot: what was true when the account was accepted for
    protection, re-checked before every signature.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    chain_id: int = Field(ge=1)
    safe_version: str = Field(min_length=1)
    owners: frozenset[str]
    threshold: int = Field(ge=1)
    transaction_guard: str = Field(pattern=_ADDRESS)
    module_guard: str = Field(pattern=_ADDRESS)
    #: The one token this Safe may move — the pinned contract (a proxy, for USDC).
    token: str = Field(pattern=_ADDRESS)
    #: The pinned token's resolved implementation and code hash.
    token_identity: TokenIdentity

    def mismatches(
        self, state: SafeChainState, token: TokenIdentity
    ) -> tuple[OnchainReasonCode, ...]:
        """Every way the live chain diverges from what was attested, distinct and
        in a stable order. Empty means safe to sign; the co-signer refuses on any
        non-empty result. The nonce is not compared here — it is *read* from the
        state and signed against, never attested to a fixed value."""
        reasons: list[OnchainReasonCode] = []
        if state.chain_id != self.chain_id:
            # A signature valid on a chain other than the attested one is a
            # cross-chain replay surface (C-RT-019).
            reasons.append(OnchainReasonCode.replayed_signature)
        if state.safe_version != self.safe_version:
            # A version whose behaviour the topology was not falsified against.
            reasons.append(OnchainReasonCode.effect_outside_model)
        if self._structure_changed(state):
            # Owners, threshold, or either guard moved — an account-control change
            # (C-RT-007/016).
            reasons.append(OnchainReasonCode.structural_change)
        if not self.token_identity.matches(token):
            # The pinned token's implementation or code hash drifted (C-RT-010/011).
            reasons.append(OnchainReasonCode.implementation_moved)
        return tuple(dict.fromkeys(reasons))

    def _structure_changed(self, state: SafeChainState) -> bool:
        live_owners = frozenset(owner.lower() for owner in state.owners)
        expected_owners = frozenset(owner.lower() for owner in self.owners)
        return (
            live_owners != expected_owners
            or state.threshold != self.threshold
            or not _same_address(state.transaction_guard, self.transaction_guard)
            or not _same_address(state.module_guard, self.module_guard)
        )


@runtime_checkable
class ChainStateReader(Protocol):
    """Reads the facts the co-signer re-verifies. A deployment implements it
    against a Base RPC; core ships only this contract and a static double."""

    def read_safe(self, safe_address: str) -> SafeChainState: ...

    def token_identity(self, token_address: str) -> TokenIdentity: ...


class StaticChainStateReader:
    """A deterministic reader over preset facts.

    Enough for the tests and for a self-hosted single-config deployment that reads
    the chain out of band and pins the result. A live, multi-block deployment
    implements :class:`ChainStateReader` against RPC instead — this one never
    calls the network, so the decision path over it stays deterministic.
    """

    def __init__(
        self, safe_state: SafeChainState, token_identities: dict[str, TokenIdentity]
    ) -> None:
        self._safe_state = safe_state
        self._tokens = {address.lower(): identity for address, identity in token_identities.items()}

    def read_safe(self, safe_address: str) -> SafeChainState:
        return self._safe_state

    def token_identity(self, token_address: str) -> TokenIdentity:
        return self._tokens[token_address.lower()]
