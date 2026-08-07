# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The static-decode adapter: a Safe transaction in, a classified effect out.

The effect *type* is the surface on-chain policies judge, so these pin what each
kind of proposal decodes to — including the two that need no selector table (a
delegatecall, and any self-call as administration) and the unlimited approval the
whole on-chain story turns on.
"""

import pytest
from pydantic import ValidationError

from secondsign.onchain import (
    EffectKind,
    OnchainEffect,
    SafeAdapter,
    SafeCall,
    SafeOperation,
)

_SAFE = "0x" + "11" * 20
_TOKEN = "0x" + "22" * 20
_SPENDER = "0x" + "33" * 20
_APPROVE = "0x095ea7b3"
_TRANSFER = "0xa9059cbb"


def _word(value: str) -> str:
    return value.removeprefix("0x").rjust(64, "0")


def _approve_data(spender: str, amount: int) -> str:
    return _APPROVE + _word(spender) + _word(f"{amount:x}")


def _call(
    to: str, data: str, *, value: int = 0, op: SafeOperation = SafeOperation.call
) -> SafeCall:
    return SafeCall(to=to, value=value, data=data, operation=op)


def test_a_bounded_approval_decodes_to_a_erc20_approval_with_its_amount():
    effect = SafeAdapter(_SAFE).decode(_call(_TOKEN, _approve_data(_SPENDER, 100)))
    assert effect.kind is EffectKind.erc20_approval
    assert effect.target == _TOKEN
    assert effect.counterparty == _SPENDER
    assert effect.amount == 100
    assert effect.selector == _APPROVE


def test_an_unlimited_approval_decodes_with_the_full_uint256():
    unlimited = 2**256 - 1
    effect = SafeAdapter(_SAFE).decode(_call(_TOKEN, _approve_data(_SPENDER, unlimited)))
    assert effect.kind is EffectKind.erc20_approval
    assert effect.amount == unlimited  # the drain vector is preserved, not clipped


def test_a_transfer_decodes_to_a_erc20_transfer():
    data = _TRANSFER + _word(_SPENDER) + _word(f"{250:x}")
    effect = SafeAdapter(_SAFE).decode(_call(_TOKEN, data))
    assert effect.kind is EffectKind.erc20_transfer
    assert effect.counterparty == _SPENDER
    assert effect.amount == 250


def test_a_delegatecall_is_a_delegatecall_whatever_it_carries():
    effect = SafeAdapter(_SAFE).decode(
        _call(_TOKEN, _approve_data(_SPENDER, 1), op=SafeOperation.delegatecall)
    )
    assert effect.kind is EffectKind.delegatecall  # the operation wins over the selector
    assert effect.target == _TOKEN


def test_a_self_call_is_administration_whatever_the_function():
    # to == the Safe itself — setGuard/enableModule/owner changes are all this.
    effect = SafeAdapter(_SAFE).decode(_call(_SAFE, "0xe19a9dd9" + _word("0x0")))
    assert effect.kind is EffectKind.self_administration
    assert effect.target == _SAFE
    assert effect.selector == "0xe19a9dd9"


def test_an_unknown_selector_decodes_as_unrecognised():
    effect = SafeAdapter(_SAFE).decode(_call(_TOKEN, "0xdeadbeef" + _word("0x1")))
    assert effect.kind is EffectKind.unrecognised
    assert effect.selector == "0xdeadbeef"


def test_a_bare_value_transfer_has_no_selector_and_is_unrecognised():
    effect = SafeAdapter(_SAFE).decode(_call(_SPENDER, "0x", value=10**18))
    assert effect.kind is EffectKind.unrecognised
    assert effect.selector is None


def test_a_malformed_approval_is_not_read_past_its_end():
    # approve selector but only one word of arguments — decodes as unrecognised.
    effect = SafeAdapter(_SAFE).decode(_call(_TOKEN, _APPROVE + _word(_SPENDER)))
    assert effect.kind is EffectKind.unrecognised


def test_the_adapter_rejects_a_malformed_safe_address():
    with pytest.raises((ValidationError, ValueError)):
        SafeAdapter("0xnot_an_address")


def test_safecall_validates_addresses_and_calldata():
    with pytest.raises(ValidationError):
        SafeCall(to="0xzzzz", value=0, data="0x", operation=SafeOperation.call)
    with pytest.raises(ValidationError):
        _call(_TOKEN, "0x123")  # odd hex length
    with pytest.raises(ValidationError):
        SafeCall(to=_TOKEN, value=-1, data="0x", operation=SafeOperation.call)


def test_effect_is_frozen_and_closed():
    effect = OnchainEffect(kind=EffectKind.unrecognised, target=_TOKEN)
    with pytest.raises(ValidationError):
        effect.kind = EffectKind.delegatecall  # frozen
    with pytest.raises(ValidationError):
        OnchainEffect(kind=EffectKind.unrecognised, target=_TOKEN, smuggled="x")  # extra forbidden
