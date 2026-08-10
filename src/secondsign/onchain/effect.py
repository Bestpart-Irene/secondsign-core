# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Decoding a proposed Safe transaction into a structured on-chain effect.

The on-chain analogue of a rail adapter: the agent proposes a raw Safe
transaction (a target, a value, calldata and an operation), and to decide on it
the gateway must first know *what it does*. This module answers that by **static
decode** — reading the selector and, for the operations it recognises, the
arguments — and classifying the result into a closed set of effect kinds.

This is the first cut, deliberately. The architecture's committed effect model is
*simulation* (running the transaction to read its real balance/allowance deltas),
which catches what a static decode cannot — fee-on-transfer tokens, proxies,
anything whose calldata does not spell out its consequence. Simulation replaces
this module's body; the effect *type* it produces is the stable surface the
on-chain policies judge, and is meant to survive that swap.

Two classification rules need no selector table and are the safer for it:

- A ``delegatecall`` is a delegatecall whatever it carries — it can rewrite the
  account's own storage, so its danger is the operation, not the target.
- A **self-call** (``to`` is the Safe itself) is *administration*: setting the
  guard, enabling a module, changing owners or the threshold are all the Safe
  calling itself, and enumerating their selectors would be a table to get wrong.
  The one bit that matters — "this transaction reconfigures the account" — is the
  self-call, not the particular function.

Only the two rock-solid ERC-20 selectors are read for arguments; everything else
is ``unrecognised``, which is the honest answer a static decode can give and the
strictest for a policy to receive.
"""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

#: A 20-byte Ethereum address, ``0x`` and 40 hex digits. Case is not normalised
#: here (EIP-55 checksums are mixed-case on purpose); comparisons lower-case.
_ADDRESS = r"^0x[0-9a-fA-F]{40}$"
#: Calldata: ``0x`` then an even number of hex digits (whole bytes), possibly empty.
_CALLDATA = r"^0x([0-9a-fA-F]{2})*$"

#: ERC-20 ``approve(address,uint256)`` and ``transfer(address,uint256)``. Stable,
#: universally known four-byte selectors — safe to name as constants.
_APPROVE = "0x095ea7b3"
_TRANSFER = "0xa9059cbb"

#: ``0x`` + selector(4 bytes) + two 32-byte words. Shorter data under one of the
#: known selectors is malformed and decodes as ``unrecognised`` rather than being
#: read past its end.
_ARGS_TWO_WORDS = 2 + 8 + 64 + 64


class SafeOperation(StrEnum):
    """The Safe execution operation. ``delegatecall`` runs the target's code in
    the account's own context, which is why it is a first-class concern."""

    call = "call"
    delegatecall = "delegatecall"


class SafeCall(BaseModel):
    """A proposed Safe transaction, as the agent proposes it — the on-chain wire.

    The agent supplies the target, the native value, the calldata and the
    operation. It supplies no signature and no decision; those are the gateway's.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    to: str = Field(pattern=_ADDRESS)
    #: Native value in wei. A uint256: non-negative and below ``2**256`` — the
    #: upper bound matters because the value is ABI-encoded as a uint256 when the
    #: transaction hash is built, and an out-of-range int would raise there.
    value: int = Field(ge=0, lt=1 << 256)
    #: ``0x`` then whole bytes. The pattern's paired hex enforces even length, so
    #: a nibble-length calldata is rejected here rather than read past its end.
    data: str = Field(pattern=_CALLDATA)
    operation: SafeOperation


class EffectKind(StrEnum):
    """What a Safe transaction does, in closed vocabulary."""

    erc20_approval = "erc20_approval"
    erc20_transfer = "erc20_transfer"
    self_administration = "self_administration"
    delegatecall = "delegatecall"
    unrecognised = "unrecognised"


class OnchainEffect(BaseModel):
    """The decoded effect of a Safe transaction — what a policy judges.

    Closed vocabulary, no free text. ``counterparty`` and ``amount`` are present
    only for the token operations that carry them; ``selector`` is the four-byte
    function selector for a call, absent for a bare value transfer.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: EffectKind
    #: The contract the call is aimed at (``SafeCall.to``).
    target: str = Field(pattern=_ADDRESS)
    #: The native value (wei) the transaction carries alongside its calldata. The
    #: first-cut model has no native-value dimension, so any non-zero value is an
    #: effect outside the model — carried here so the policy can refuse it rather
    #: than judge the calldata and silently ignore the value moving with it.
    native_value: int = Field(default=0, ge=0)
    #: The spender (approval) or recipient (transfer); absent otherwise.
    counterparty: str | None = Field(default=None, pattern=_ADDRESS)
    #: The allowance (approval) or amount (transfer), a uint256 — unbounded above,
    #: because ``approve(spender, 2**256-1)`` is exactly the effect to surface.
    amount: int | None = Field(default=None, ge=0)
    #: The four-byte selector as hex, for a call. Absent for a bare value transfer.
    selector: str | None = None


class SafeAdapter:
    """Decodes proposals against one Safe account.

    Stateless but for the account address it decodes against — a self-call is
    recognised by comparing the target to it.
    """

    def __init__(self, safe_address: str) -> None:
        SafeCall(
            to=safe_address, value=0, data="0x", operation=SafeOperation.call
        )  # validates the address
        self._safe = safe_address.lower()

    def decode(self, call: SafeCall) -> OnchainEffect:
        # The native value rides along on every kind: it is judged separately from
        # the calldata, so it must reach the policy whatever the calldata decodes to.
        if call.operation is SafeOperation.delegatecall:
            return OnchainEffect(
                kind=EffectKind.delegatecall,
                target=call.to,
                selector=_selector(call.data),
                native_value=call.value,
            )
        if call.to.lower() == self._safe:
            return OnchainEffect(
                kind=EffectKind.self_administration,
                target=call.to,
                selector=_selector(call.data),
                native_value=call.value,
            )
        selector = _selector(call.data)
        if selector in (_APPROVE, _TRANSFER) and len(call.data) >= _ARGS_TWO_WORDS:
            counterparty, amount = _decode_address_and_amount(call.data)
            kind = EffectKind.erc20_approval if selector == _APPROVE else EffectKind.erc20_transfer
            return OnchainEffect(
                kind=kind,
                target=call.to,
                counterparty=counterparty,
                amount=amount,
                selector=selector,
                native_value=call.value,
            )
        return OnchainEffect(
            kind=EffectKind.unrecognised,
            target=call.to,
            selector=selector,
            native_value=call.value,
        )


def _selector(data: str) -> str | None:
    """The four-byte selector as ``0x`` + 8 hex, or ``None`` if the calldata is
    too short to carry one."""
    return data[:10] if len(data) >= 10 else None


def _decode_address_and_amount(data: str) -> tuple[str, int]:
    """Read ``(address, uint256)`` from the two words after the selector.

    An address is the low 20 bytes of its 32-byte word; the amount is the whole
    second word. Only ever called once the length has been checked.
    """
    body = data[10:]  # drop "0x" and the four-byte selector
    address = "0x" + body[24:64]  # low 20 bytes of the first word
    amount = int(body[64:128], 16)
    return address, amount
