# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The preset proposals — plain language in, a ``SafeCall`` out.

Each preset carries a ``claims`` field: the outcome its own label promises. The
panel never *uses* that field to decide anything — the verdict always comes from
the co-signer — but a test asserts the two agree, so a live demo cannot end up
contradicting its own captions. It is the same reflex as
``examples/test_quickstart.py``: a demo is a claim, and a claim needs a test.
"""

from __future__ import annotations

from dataclasses import dataclass

from examples.firewall_panel.world import (
    ATTACKER,
    CLOUDFLARE,
    NEW_VENDOR,
    SAFE,
    TOKEN,
    USDC,
    _addr,
)
from secondsign.onchain.effect import SafeCall, SafeOperation

#: The two ERC-20 selectors the effect model reads arguments from.
_TRANSFER = "a9059cbb"
_APPROVE = "095ea7b3"

#: A token nobody pinned — same shape, never attested.
UNPINNED_TOKEN = _addr("de1f1", "f00d")

MAX_UINT256 = 2**256 - 1


def _word(value: int) -> str:
    return f"{value:064x}"


def _address_word(address: str) -> str:
    return _word(int(address, 16))


def erc20_transfer(to: str, amount: int) -> str:
    """Calldata for ``transfer(address,uint256)``."""
    return "0x" + _TRANSFER + _address_word(to) + _word(amount)


def erc20_approve(spender: str, amount: int) -> str:
    """Calldata for ``approve(address,uint256)``."""
    return "0x" + _APPROVE + _address_word(spender) + _word(amount)


#: ``setGuard(address)`` — the call that would remove SecondSign from the
#: signing path. Aimed at the Safe itself, so the effect model reads it as
#: self-administration without needing to know the selector.
SET_GUARD = "0x" + "e19a9dd9" + _address_word("0x" + "00" * 20)


@dataclass(frozen=True)
class Scenario:
    """One preset proposal, with the outcome its label promises."""

    key: str
    title: str
    detail: str
    call: SafeCall
    #: ``signed`` / ``held`` / ``refused`` — asserted against the real co-signer.
    claims: str
    #: The reason code the label implies, or ``None`` when no concern is claimed.
    claims_reason: str | None = None


def _call(to: str, data: str, *, value: int = 0, delegate: bool = False) -> SafeCall:
    return SafeCall(
        to=to,
        value=value,
        data=data,
        operation=SafeOperation.delegatecall if delegate else SafeOperation.call,
    )


#: The catalogue, in demo order: the two that pass, then the ways to fail.
CATALOGUE: tuple[Scenario, ...] = (
    Scenario(
        key="small_transfer",
        title="Pay Cloudflare 2.00 USDC",
        detail="a routine bill, under the auto-approve limit",
        call=_call(TOKEN, erc20_transfer(CLOUDFLARE, 2 * USDC)),
        claims="signed",
    ),
    Scenario(
        key="review_transfer",
        title="Pay a new vendor 20.00 USDC",
        detail="over the auto-limit, under the cap — a human decides",
        call=_call(TOKEN, erc20_transfer(NEW_VENDOR, 20 * USDC)),
        claims="held",
        claims_reason="unbounded_approval",
    ),
    Scenario(
        key="over_cap_transfer",
        title="Pay 900.00 USDC in one go",
        detail="past the per-transaction cap entirely",
        call=_call(TOKEN, erc20_transfer(NEW_VENDOR, 900 * USDC)),
        claims="refused",
        claims_reason="unbounded_approval",
    ),
    Scenario(
        key="unlimited_approval",
        title="Grant an attacker an unlimited allowance",
        detail="the classic drain: no money now, everything later",
        call=_call(TOKEN, erc20_approve(ATTACKER, MAX_UINT256)),
        claims="refused",
        claims_reason="unbounded_approval",
    ),
    Scenario(
        key="bounded_approval",
        title="Grant an un-vouched spender 1.00 USDC",
        detail="small, but an allowance is a standing capability a cap cannot bound",
        call=_call(TOKEN, erc20_approve(ATTACKER, 1 * USDC)),
        claims="refused",
        claims_reason="counterparty_not_allowlisted",
    ),
    Scenario(
        key="unpinned_token",
        title="Move a token nobody pinned",
        detail="an unattested asset — a cap in no units bounds nothing",
        call=_call(UNPINNED_TOKEN, erc20_transfer(CLOUDFLARE, 1 * USDC)),
        claims="refused",
        claims_reason="token_not_allowlisted",
    ),
    Scenario(
        key="remove_secondsign",
        title="Remove SecondSign (setGuard(0))",
        detail="reconfigure the account so a second signature is not needed",
        call=_call(SAFE, SET_GUARD),
        claims="refused",
        claims_reason="structural_change",
    ),
    Scenario(
        key="delegatecall",
        title="Run someone else's code as the account",
        detail="a delegatecall rewrites the account's own storage",
        call=_call(CLOUDFLARE, "0x", delegate=True),
        claims="refused",
        claims_reason="delegatecall",
    ),
    Scenario(
        key="native_value_rider",
        title="A tiny transfer carrying 1 ETH alongside",
        detail="the calldata looks harmless; the value riding with it does not",
        call=_call(TOKEN, erc20_transfer(CLOUDFLARE, 1 * USDC), value=10**18),
        claims="refused",
        claims_reason="effect_outside_model",
    ),
    Scenario(
        key="unknown_call",
        title="Call a contract the model cannot read",
        detail="an unrecognised selector is refused, not guessed at",
        call=_call(CLOUDFLARE, "0xdeadbeef"),
        claims="refused",
        claims_reason="unknown_selector",
    ),
)

BY_KEY: dict[str, Scenario] = {scenario.key: scenario for scenario in CATALOGUE}
