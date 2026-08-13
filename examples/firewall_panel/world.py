# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The simulated account the panel judges against — and the ways to break it.

The chain is the only thing here that is fake. It is a
:class:`~secondsign.onchain.chain_state.StaticChainStateReader` over facts this
module holds, so the co-signer over it re-verifies for real and refuses for real;
what it reads simply never came from a network.

The point of the module is :meth:`World.tamper`. Watching a firewall sign is not
persuasive — watching it refuse *after you have broken the account by hand* is.
Each tamper moves one attested fact out from under the co-signer, and station ①
of the panel then shows the specific drift it produced.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from secondsign.onchain.chain_state import (
    ExpectedSafeConfig,
    SafeChainState,
    StaticChainStateReader,
    TokenIdentity,
)

#: One USDC in minor units (6 decimals), as the real thing has.
USDC = 1_000_000


def _addr(head: str, tail: str = "") -> str:
    """A 20-byte address from a readable head and tail, zero-filled between.

    The demo addresses are meant to be recognisable at a glance in the UI and
    plainly synthetic — the workspace rule against committing a real account
    identifier applies to demo fixtures too.
    """
    body = head + "0" * (40 - len(head) - len(tail)) + tail
    assert len(body) == 40, f"address body must be 40 hex digits, got {len(body)}"
    return "0x" + body


def _hash(byte: str) -> str:
    return "0x" + byte * 32


ZERO = _addr("")

SAFE = _addr("5afe", "d0d0")
AGENT = _addr("a6e17", "a6e17")
SECONDSIGN = _addr("5ec0", "5ec0")
GUARD = _addr("60a2d", "01")
MODULE_GUARD = _addr("30d01e", "9a1d")
TOKEN = _addr("05dc", "5dc0")
TOKEN_IMPL = _addr("13901", "11")

#: Counterparties the presets aim at.
CLOUDFLARE = _addr("c10cf", "c101")
NEW_VENDOR = _addr("dee0", "beef")
ATTACKER = _addr("a77ac", "dead")

_GENUINE_CODE_HASH = _hash("11")
#: A look-alike token: the same address, different code behind it. This is the
#: shape of the attack the pinned identity exists to catch — the address a human
#: recognises is the half that does not change.
_COUNTERFEIT_CODE_HASH = _hash("ba")
_COUNTERFEIT_IMPL = _addr("bad1", "bad1")

_INTRUDER = _addr("17ce", "e12a")


class Tamper(StrEnum):
    """The ways the panel lets you break the account, each a distinct drift."""

    #: Someone removed the transaction guard — the ``setGuard(0)`` that S001
    #: proved is the attack the double guard exists to survive.
    remove_guard = "remove_guard"
    #: An owner was swapped for one nobody attested.
    swap_owner = "swap_owner"
    #: The 2-of-2 was lowered to 1-of-2, so one signature would suffice.
    lower_threshold = "lower_threshold"
    #: The pinned token now resolves to different code — a look-alike USDC.
    counterfeit_token = "counterfeit_token"  # noqa: S105 — an ERC-20, not a bearer token
    #: The account moved to a chain the attestation was not made on.
    wrong_chain = "wrong_chain"
    #: The co-signer is not wired to read the chain at all.
    unwire_reader = "unwire_reader"


#: What each tamper does, for the UI. The reason code it produces is deliberately
#: *not* written here — that comes from ``ExpectedSafeConfig.mismatches`` at run
#: time, so this catalogue cannot drift into claiming an outcome the engine does
#: not actually produce.
TAMPER_LABELS: dict[Tamper, str] = {
    Tamper.remove_guard: "Remove the transaction guard (setGuard(0))",
    Tamper.swap_owner: "Swap an owner for an unattested account",
    Tamper.lower_threshold: "Lower the threshold from 2-of-2 to 1-of-2",
    Tamper.counterfeit_token: "Replace USDC with a look-alike (same address, new code)",
    Tamper.wrong_chain: "Move the account to a different chain",
    Tamper.unwire_reader: "Unwire the chain reader entirely",
}


@dataclass
class World:
    """The simulated account: what was attested, and what is live right now.

    ``expected`` is fixed at construction — it is the attestation, and an
    attestation that moved with the chain would attest to nothing. ``live`` is
    what :meth:`tamper` edits.
    """

    expected: ExpectedSafeConfig
    live: SafeChainState
    live_token: TokenIdentity
    #: Safe balance in USDC minor units. The panel judges; it does not execute,
    #: so nothing here debits it — see the panel's own stated boundary.
    balance: int = 100 * USDC
    #: Tampers currently in force, in the order they were applied.
    applied: tuple[Tamper, ...] = ()
    reader_wired: bool = True

    @classmethod
    def pristine(cls) -> "World":
        """A correctly configured, untampered account."""
        identity = TokenIdentity(implementation=TOKEN_IMPL, code_hash=_GENUINE_CODE_HASH)
        live = SafeChainState(
            nonce=7,
            owners=(AGENT, SECONDSIGN),
            threshold=2,
            transaction_guard=GUARD,
            module_guard=MODULE_GUARD,
            chain_id=8453,
            safe_version="1.5.0",
        )
        expected = ExpectedSafeConfig(
            chain_id=8453,
            safe_version="1.5.0",
            owners=frozenset({AGENT.lower(), SECONDSIGN.lower()}),
            threshold=2,
            transaction_guard=GUARD,
            module_guard=MODULE_GUARD,
            token=TOKEN,
            token_identity=identity,
        )
        return cls(expected=expected, live=live, live_token=identity)

    def reader(self) -> StaticChainStateReader | None:
        """The reader the co-signer gets, or ``None`` when unwired.

        ``None`` is not a degraded mode with a fallback — the co-signer refuses
        outright when it cannot re-verify, and the panel exists partly to show
        that absence is refusal, not a trust of the caller.
        """
        if not self.reader_wired:
            return None
        return StaticChainStateReader(self.live, {TOKEN: self.live_token})

    def tamper(self, what: Tamper) -> None:
        """Apply one tamper to the live chain. Idempotent."""
        if what in self.applied:
            return
        if what is Tamper.remove_guard:
            self.live = self._live_with(transaction_guard=ZERO)
        elif what is Tamper.swap_owner:
            self.live = self._live_with(owners=(_INTRUDER, SECONDSIGN))
        elif what is Tamper.lower_threshold:
            self.live = self._live_with(threshold=1)
        elif what is Tamper.counterfeit_token:
            self.live_token = TokenIdentity(
                implementation=_COUNTERFEIT_IMPL, code_hash=_COUNTERFEIT_CODE_HASH
            )
        elif what is Tamper.wrong_chain:
            # The attested chain id is also the co-signer's hash domain, so what
            # moves here is the *account* — the chain the live state reports — not
            # the attestation it is checked against.
            self.live = self._live_with(chain_id=1)
        elif what is Tamper.unwire_reader:
            self.reader_wired = False
        self.applied = (*self.applied, what)

    def _live_with(self, **changes: object) -> SafeChainState:
        """The live state with fields replaced, re-validated.

        Constructed rather than ``model_copy``-ed on purpose: ``model_copy``
        skips validation, so a tamper that produced an impossible state (a
        malformed address, a zero threshold) would be discovered downstream in
        the co-signer rather than here, where it is a bug in this file.
        """
        fields: dict[str, object] = {
            "nonce": self.live.nonce,
            "owners": self.live.owners,
            "threshold": self.live.threshold,
            "transaction_guard": self.live.transaction_guard,
            "module_guard": self.live.module_guard,
            "chain_id": self.live.chain_id,
            "safe_version": self.live.safe_version,
        }
        return SafeChainState(**{**fields, **changes})  # type: ignore[arg-type]

    def repair(self) -> None:
        """Undo every tamper — the account as attested."""
        fresh = World.pristine()
        self.live, self.live_token = fresh.live, fresh.live_token
        self.applied, self.reader_wired = (), True
