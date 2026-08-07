# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The on-chain co-signer: it signs a hash the real Safe accepts, only on ALLOW.

The load-bearing test is the golden hash — the Python EIP-712 hash is asserted
byte-for-byte against a value produced by Safe 1.5.0's own ``getTransactionHash``
(a Safe at 0x2e23…470b, chain 1, an approve at nonce 0), so a signature over it is
one the account will honour. The rest proves the boundary: an allowed action gets
a real, recoverable signature; a refused one gets none; the signing key lives on
the control-plane side the agent cannot reach; and the crypto is optional.
"""

import tomllib
from pathlib import Path

from eth_account import Account

from secondsign.gateway.onchain_cosigner import (
    CosignStatus,
    OnchainCosigner,
    SafeContext,
    safe_transaction_hash,
)
from secondsign.isolation import Side, classify
from secondsign.onchain.effect import SafeCall, SafeOperation

_GOLDEN_SAFE = "0x2e234DAe75C793f67A35089C9d99245E1C58470b"
_GOLDEN_CHAIN = 1
_GOLDEN_TO = "0x2222222222222222222222222222222222222222"
_GOLDEN_SPENDER = "0x3333333333333333333333333333333333333333"
_GOLDEN_HASH = bytes.fromhex("bbdf078a1eee6cb2e877f7725ceeb6d0e83094367b6346787fe6fc273f662068")

_KEY = b"\xa1" * 32
_APPROVE = "0x095ea7b3"


def _word(hex_or_int: str) -> str:
    return hex_or_int.removeprefix("0x").rjust(64, "0")


def _approve_data(spender: str, amount: int) -> str:
    return _APPROVE + _word(spender) + _word(f"{amount:x}")


def test_the_hash_matches_the_real_safe_getTransactionHash():
    call = SafeCall(
        to=_GOLDEN_TO,
        value=0,
        data=_approve_data(_GOLDEN_SPENDER, 100),
        operation=SafeOperation.call,
    )
    context = SafeContext(safe_address=_GOLDEN_SAFE, chain_id=_GOLDEN_CHAIN)
    assert safe_transaction_hash(call, context, nonce=0) == _GOLDEN_HASH


def test_an_allowed_action_is_signed_and_the_signature_recovers_to_the_cosigner():
    context = SafeContext(safe_address=_GOLDEN_SAFE, chain_id=_GOLDEN_CHAIN)
    cosigner = OnchainCosigner(_KEY, context, approval_cap=1_000)
    call = SafeCall(
        to=_GOLDEN_TO,
        value=0,
        data=_approve_data(_GOLDEN_SPENDER, 100),
        operation=SafeOperation.call,
    )
    outcome = cosigner.cosign(call, nonce=0)
    assert outcome.status is CosignStatus.signed
    assert outcome.signature is not None
    # The signature is real: it recovers to the address SecondSign co-signs as.
    signature = bytes.fromhex(outcome.signature.removeprefix("0x"))
    recovered = Account._recover_hash(_GOLDEN_HASH, signature=signature)
    assert recovered == cosigner.address


def test_an_unlimited_approval_is_refused_with_no_signature():
    context = SafeContext(safe_address=_GOLDEN_SAFE, chain_id=_GOLDEN_CHAIN)
    cosigner = OnchainCosigner(_KEY, context, approval_cap=1_000)
    call = SafeCall(
        to=_GOLDEN_TO,
        value=0,
        data=_approve_data(_GOLDEN_SPENDER, 2**256 - 1),
        operation=SafeOperation.call,
    )
    outcome = cosigner.cosign(call, nonce=0)
    assert outcome.status is CosignStatus.refused
    assert outcome.signature is None


def test_a_delegatecall_is_refused():
    context = SafeContext(safe_address=_GOLDEN_SAFE, chain_id=_GOLDEN_CHAIN)
    cosigner = OnchainCosigner(_KEY, context, approval_cap=1_000)
    call = SafeCall(to=_GOLDEN_TO, value=0, data="0x", operation=SafeOperation.delegatecall)
    assert cosigner.cosign(call, nonce=0).status is CosignStatus.refused


def test_the_signing_key_lives_on_the_control_plane_side():
    # INV-12: the co-signer holds the key, so it must be control plane — the agent
    # surface cannot import it, exactly as it cannot reach the rail credential.
    assert classify("secondsign.gateway.onchain_cosigner") == Side.control_plane


def test_ethereum_crypto_is_an_optional_dependency_not_a_runtime_one():
    pyproject = tomllib.loads((Path(__file__).parents[2] / "pyproject.toml").read_text())
    required = pyproject["project"]["dependencies"]
    optional = pyproject["project"]["optional-dependencies"]
    assert not any("eth-account" in dep for dep in required), (
        "eth-account must not be a runtime dependency"
    )
    assert any("eth-account" in dep for dep in optional["onchain"])
