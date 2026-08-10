# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The chain-state port: the facts re-verified before signing, and their drift.

``ExpectedSafeConfig.mismatches`` is the load-bearing pure function — it names,
in the closed on-chain vocabulary, every way the live chain can diverge from what
was attested. The co-signer refuses on any non-empty result; these pin which
divergence maps to which reason.
"""

import pytest
from pydantic import ValidationError

from secondsign.onchain.chain_state import (
    ChainStateReader,
    ExpectedSafeConfig,
    SafeChainState,
    StaticChainStateReader,
    TokenIdentity,
)
from secondsign.onchain.types import OnchainReasonCode

_ZERO = "0x" + "00" * 20
_SAFE = "0x2e234DAe75C793f67A35089C9d99245E1C58470b"
_OWNER_AGENT = "0x" + "a1" * 20
_OWNER_SS = "0x" + "b2" * 20
_TX_GUARD = "0x" + "c3" * 20
_MOD_GUARD = "0x" + "d4" * 20
_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"  # canonical Base USDC
_USDC_IMPL = "0x" + "e5" * 20
_USDC_CODEHASH = "0x" + "11" * 32


def _state(**over: object) -> SafeChainState:
    base: dict[str, object] = dict(
        nonce=0,
        owners=(_OWNER_AGENT, _OWNER_SS),
        threshold=2,
        transaction_guard=_TX_GUARD,
        module_guard=_MOD_GUARD,
        chain_id=8453,
        safe_version="1.5.0",
    )
    base.update(over)
    return SafeChainState(**base)  # type: ignore[arg-type]


def _token(**over: object) -> TokenIdentity:
    base: dict[str, object] = dict(implementation=_USDC_IMPL, code_hash=_USDC_CODEHASH)
    base.update(over)
    return TokenIdentity(**base)  # type: ignore[arg-type]


def _expected(**over: object) -> ExpectedSafeConfig:
    base: dict[str, object] = dict(
        chain_id=8453,
        safe_version="1.5.0",
        owners=frozenset({_OWNER_AGENT, _OWNER_SS}),
        threshold=2,
        transaction_guard=_TX_GUARD,
        module_guard=_MOD_GUARD,
        token=_USDC,
        token_identity=_token(),
    )
    base.update(over)
    return ExpectedSafeConfig(**base)  # type: ignore[arg-type]


def test_a_matching_state_has_no_mismatches():
    assert _expected().mismatches(_state(), _token()) == ()


def test_a_wrong_chain_id_is_a_replay_surface():
    assert _expected().mismatches(_state(chain_id=1), _token()) == (
        OnchainReasonCode.replayed_signature,
    )


def test_an_unexpected_safe_version_is_outside_the_model():
    assert _expected().mismatches(_state(safe_version="1.4.1"), _token()) == (
        OnchainReasonCode.effect_outside_model,
    )


def test_a_changed_owner_set_is_a_structural_change():
    other = _state(owners=(_OWNER_AGENT, "0x" + "cc" * 20))
    assert _expected().mismatches(other, _token()) == (OnchainReasonCode.structural_change,)


def test_a_changed_threshold_is_a_structural_change():
    assert _expected().mismatches(_state(threshold=1), _token()) == (
        OnchainReasonCode.structural_change,
    )


def test_a_removed_or_replaced_guard_is_a_structural_change():
    assert _expected().mismatches(_state(transaction_guard=_ZERO), _token()) == (
        OnchainReasonCode.structural_change,
    )
    assert _expected().mismatches(_state(module_guard=_ZERO), _token()) == (
        OnchainReasonCode.structural_change,
    )


def test_a_drifted_token_implementation_is_implementation_moved():
    moved = _token(implementation="0x" + "ff" * 20)
    assert _expected().mismatches(_state(), moved) == (OnchainReasonCode.implementation_moved,)


def test_a_drifted_token_code_hash_is_implementation_moved():
    moved = _token(code_hash="0x" + "22" * 32)
    assert _expected().mismatches(_state(), moved) == (OnchainReasonCode.implementation_moved,)


def _hex_upper(address: str) -> str:
    # EIP-55 checksums keep "0x" lower and mix-case the hex; upper the hex only.
    return "0x" + address[2:].upper()


def test_owner_and_guard_comparisons_are_case_insensitive():
    # EIP-55 checksums are mixed-case; a different casing is the same address.
    upper = _state(
        owners=(_hex_upper(_OWNER_AGENT), _hex_upper(_OWNER_SS)),
        transaction_guard=_hex_upper(_TX_GUARD),
    )
    assert _expected().mismatches(upper, _token(implementation=_hex_upper(_USDC_IMPL))) == ()


def test_mismatches_are_distinct_and_in_a_stable_order():
    everything = _state(chain_id=1, threshold=1, safe_version="1.4.1")
    reasons = _expected().mismatches(everything, _token(implementation="0x" + "ff" * 20))
    assert reasons == (
        OnchainReasonCode.replayed_signature,
        OnchainReasonCode.effect_outside_model,
        OnchainReasonCode.structural_change,
        OnchainReasonCode.implementation_moved,
    )


def test_the_models_are_frozen_and_reject_unknown_fields():
    with pytest.raises(ValidationError):
        SafeChainState(
            nonce=0,
            owners=(),
            threshold=2,
            transaction_guard=_ZERO,
            module_guard=_ZERO,
            chain_id=8453,
            safe_version="1.5.0",
            smuggled="x",
        )  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        _token(code_hash="not-hex-0x")  # a code hash must be 0x + 32 bytes


def test_the_static_reader_satisfies_the_protocol_and_returns_preset_facts():
    reader: ChainStateReader = StaticChainStateReader(
        safe_state=_state(), token_identities={_USDC: _token()}
    )
    assert reader.read_safe(_SAFE) == _state()
    # Lookup is case-insensitive on the token address.
    assert reader.token_identity(_USDC.lower()) == _token()
