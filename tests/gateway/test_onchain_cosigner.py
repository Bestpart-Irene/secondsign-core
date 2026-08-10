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
from datetime import datetime, timedelta, timezone
from pathlib import Path

from eth_account import Account

from secondsign.approval import CheckerIdentity, CheckerVerdict
from secondsign.gateway.onchain_cosigner import (
    CosignStatus,
    OnchainCosigner,
    SafeContext,
    safe_transaction_hash,
)
from secondsign.intent import ProposalDigest
from secondsign.isolation import Side, classify
from secondsign.onchain.effect import SafeCall, SafeOperation

_GOLDEN_SAFE = "0x2e234DAe75C793f67A35089C9d99245E1C58470b"
_GOLDEN_CHAIN = 1
_GOLDEN_TO = "0x2222222222222222222222222222222222222222"
_GOLDEN_SPENDER = "0x3333333333333333333333333333333333333333"
_GOLDEN_HASH = bytes.fromhex("bbdf078a1eee6cb2e877f7725ceeb6d0e83094367b6346787fe6fc273f662068")

_KEY = b"\xa1" * 32
_APPROVE = "0x095ea7b3"
_PROPOSER = "agent-workload"
_NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def _context() -> SafeContext:
    return SafeContext(safe_address=_GOLDEN_SAFE, chain_id=_GOLDEN_CHAIN)


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
    cosigner = OnchainCosigner(
        _KEY, context, approval_cap=1_000, approve_spender_allowlist=frozenset({_GOLDEN_SPENDER})
    )
    call = SafeCall(
        to=_GOLDEN_TO,
        value=0,
        data=_approve_data(_GOLDEN_SPENDER, 100),
        operation=SafeOperation.call,
    )
    outcome = cosigner.cosign(call, nonce=0, proposer=_PROPOSER, now=_NOW)
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
    outcome = cosigner.cosign(call, nonce=0, proposer=_PROPOSER, now=_NOW)
    assert outcome.status is CosignStatus.refused
    assert outcome.signature is None


def test_a_delegatecall_is_refused():
    context = SafeContext(safe_address=_GOLDEN_SAFE, chain_id=_GOLDEN_CHAIN)
    cosigner = OnchainCosigner(_KEY, context, approval_cap=1_000)
    call = SafeCall(to=_GOLDEN_TO, value=0, data="0x", operation=SafeOperation.delegatecall)
    assert (
        cosigner.cosign(call, nonce=0, proposer=_PROPOSER, now=_NOW).status is CosignStatus.refused
    )


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


def _review_cosigner() -> OnchainCosigner:
    return OnchainCosigner(
        _KEY,
        _context(),
        approval_cap=1_000,
        review_above=100,
        approve_spender_allowlist=frozenset({_GOLDEN_SPENDER}),
    )


def _review_call() -> SafeCall:
    return SafeCall(
        to=_GOLDEN_TO,
        value=0,
        data=_approve_data(_GOLDEN_SPENDER, 500),
        operation=SafeOperation.call,
    )


def _checker_verdict(
    approval_id: str, *, subject: str = "human-checker", approved: bool = True
) -> CheckerVerdict:
    return CheckerVerdict(
        checker=CheckerIdentity(subject=subject),
        approval_id=approval_id,
        proposal=ProposalDigest(value=approval_id),
        approved=approved,
    )


def test_a_review_band_action_is_held_not_signed():
    outcome = _review_cosigner().cosign(_review_call(), nonce=0, proposer=_PROPOSER, now=_NOW)
    assert outcome.status is CosignStatus.held
    assert outcome.approval_id is not None
    assert outcome.signature is None


def test_a_held_review_is_signed_once_a_different_checker_approves():
    cosigner = _review_cosigner()
    held = cosigner.cosign(_review_call(), nonce=0, proposer=_PROPOSER, now=_NOW)
    resolved = cosigner.resolve(held.approval_id, _checker_verdict(held.approval_id), now=_NOW)
    assert resolved.status is CosignStatus.signed
    # the signature recovers to the co-signer — the account will honour it.
    sig = bytes.fromhex(resolved.signature.removeprefix("0x"))
    assert Account._recover_hash(bytes.fromhex(held.approval_id), signature=sig) == cosigner.address


def test_a_self_approval_is_refused():
    cosigner = _review_cosigner()
    held = cosigner.cosign(_review_call(), nonce=0, proposer=_PROPOSER, now=_NOW)
    # the checker is the same principal as the maker (the proposer): no self-approval.
    resolved = cosigner.resolve(
        held.approval_id, _checker_verdict(held.approval_id, subject=_PROPOSER), now=_NOW
    )
    assert resolved.status is CosignStatus.refused
    assert resolved.signature is None


def test_a_declined_review_is_refused():
    cosigner = _review_cosigner()
    held = cosigner.cosign(_review_call(), nonce=0, proposer=_PROPOSER, now=_NOW)
    resolved = cosigner.resolve(
        held.approval_id, _checker_verdict(held.approval_id, approved=False), now=_NOW
    )
    assert resolved.status is CosignStatus.refused


def test_an_expired_review_is_refused():
    cosigner = _review_cosigner()
    held = cosigner.cosign(_review_call(), nonce=0, proposer=_PROPOSER, now=_NOW)
    late = _NOW + timedelta(hours=5)  # past the 4h review TTL
    resolved = cosigner.resolve(held.approval_id, _checker_verdict(held.approval_id), now=late)
    assert resolved.status is CosignStatus.refused


def test_an_unknown_approval_is_refused_with_no_judgement():
    unknown = "00" * 32
    resolved = _review_cosigner().resolve(unknown, _checker_verdict(unknown), now=_NOW)
    assert resolved.status is CosignStatus.refused
    assert resolved.judgement is None


def test_a_bounded_approval_to_an_unlisted_spender_is_not_silently_signed():
    # The review's drain path: approve(attacker, cap-1) is bounded, so the
    # amount rules alone raise no concern — and a signature hands the attacker
    # a live allowance to pull with transferFrom, repeatable every nonce.
    cosigner = OnchainCosigner(_KEY, _context(), approval_cap=1_000)
    attacker = "0x4444444444444444444444444444444444444444"
    call = SafeCall(
        to=_GOLDEN_TO,
        value=0,
        data=_approve_data(attacker, 999),
        operation=SafeOperation.call,
    )
    outcome = cosigner.cosign(call, nonce=0, proposer=_PROPOSER, now=_NOW)
    assert outcome.status is not CosignStatus.signed
    assert outcome.signature is None


def test_a_verdict_the_cosigner_does_not_recognise_refuses_rather_than_signs(monkeypatch):
    # Silence is the only state that signs. A verdict outside the vocabulary —
    # a future addition, a bug — must refuse, not fall through to a signature.
    from types import SimpleNamespace

    from secondsign.gateway import onchain_cosigner as module

    cosigner = OnchainCosigner(_KEY, _context(), approval_cap=1_000)
    monkeypatch.setattr(
        module.policy, "evaluate", lambda *args, **kwargs: SimpleNamespace(verdict=object())
    )
    call = SafeCall(
        to=_GOLDEN_TO,
        value=0,
        data=_approve_data(_GOLDEN_SPENDER, 100),
        operation=SafeOperation.call,
    )
    outcome = cosigner.cosign(call, nonce=0, proposer=_PROPOSER, now=_NOW)
    assert outcome.status is CosignStatus.refused
    assert outcome.signature is None


def test_native_value_alongside_a_bounded_call_is_refused():
    # The second drain: a bounded approve carrying ~1000 ETH of native value. The
    # calldata is concern-free, but the value moving with it must not be ignored.
    cosigner = OnchainCosigner(
        _KEY, _context(), approval_cap=1_000, approve_spender_allowlist=frozenset({_GOLDEN_SPENDER})
    )
    call = SafeCall(
        to=_GOLDEN_TO,
        value=10**21,
        data=_approve_data(_GOLDEN_SPENDER, 1),
        operation=SafeOperation.call,
    )
    outcome = cosigner.cosign(call, nonce=0, proposer=_PROPOSER, now=_NOW)
    assert outcome.status is CosignStatus.refused
    assert outcome.signature is None


def test_a_declined_review_cannot_be_approved_by_a_second_checker():
    # Approver shopping: checker A declines, checker B must not be able to approve
    # what A refused. A terminal decline settles and evicts the review.
    cosigner = _review_cosigner()
    held = cosigner.cosign(_review_call(), nonce=0, proposer=_PROPOSER, now=_NOW)
    declined = cosigner.resolve(
        held.approval_id,
        _checker_verdict(held.approval_id, subject="checker-a", approved=False),
        now=_NOW,
    )
    assert declined.status is CosignStatus.refused
    # A second, different checker now tries to approve the same review.
    second = cosigner.resolve(
        held.approval_id,
        _checker_verdict(held.approval_id, subject="checker-b", approved=True),
        now=_NOW,
    )
    assert second.status is CosignStatus.refused
    assert second.signature is None


def test_re_proposing_a_held_review_does_not_refresh_its_ttl():
    cosigner = _review_cosigner()
    held = cosigner.cosign(_review_call(), nonce=0, proposer=_PROPOSER, now=_NOW)
    # Re-propose the identical transaction 100h later — well past the 4h TTL.
    later = _NOW + timedelta(hours=100)
    re_held = cosigner.cosign(_review_call(), nonce=0, proposer=_PROPOSER, now=later)
    assert re_held.status is CosignStatus.held
    assert re_held.approval_id == held.approval_id  # same review, not a fresh one
    # Resolving 101h after the first hold must fail: the clock was not reset.
    resolved = cosigner.resolve(
        held.approval_id, _checker_verdict(held.approval_id), now=_NOW + timedelta(hours=101)
    )
    assert resolved.status is CosignStatus.refused


def test_re_proposing_does_not_rebind_the_maker_to_a_new_proposer():
    cosigner = _review_cosigner()
    held = cosigner.cosign(_review_call(), nonce=0, proposer=_PROPOSER, now=_NOW)
    # A different principal re-proposes the same tx; the recorded maker must not
    # change, or the original proposer could approve their own review.
    cosigner.cosign(_review_call(), nonce=0, proposer="someone-else", now=_NOW)
    resolved = cosigner.resolve(
        held.approval_id, _checker_verdict(held.approval_id, subject=_PROPOSER), now=_NOW
    )
    assert resolved.status is CosignStatus.refused  # original proposer still the maker


def test_re_proposing_an_already_signed_review_is_refused_not_re_held():
    cosigner = _review_cosigner()
    held = cosigner.cosign(_review_call(), nonce=0, proposer=_PROPOSER, now=_NOW)
    signed = cosigner.resolve(held.approval_id, _checker_verdict(held.approval_id), now=_NOW)
    assert signed.status is CosignStatus.signed
    # Retrying the identical tx must not create a review no checker can answer.
    retry = cosigner.cosign(_review_call(), nonce=0, proposer=_PROPOSER, now=_NOW)
    assert retry.status is CosignStatus.refused


def test_a_naive_datetime_is_refused_on_every_path():
    cosigner = _review_cosigner()
    naive = datetime(2026, 1, 1, 12, 0)  # no tzinfo
    import pytest

    with pytest.raises(ValueError, match="timezone-aware"):
        cosigner.cosign(_review_call(), nonce=0, proposer=_PROPOSER, now=naive)
    with pytest.raises(ValueError, match="timezone-aware"):
        cosigner.resolve("00" * 32, _checker_verdict("00" * 32), now=naive)


def test_an_out_of_range_nonce_is_refused_before_hashing():
    cosigner = OnchainCosigner(
        _KEY, _context(), approval_cap=1_000, approve_spender_allowlist=frozenset({_GOLDEN_SPENDER})
    )
    call = SafeCall(
        to=_GOLDEN_TO, value=0, data=_approve_data(_GOLDEN_SPENDER, 1), operation=SafeOperation.call
    )
    outcome = cosigner.cosign(call, nonce=2**256, proposer=_PROPOSER, now=_NOW)
    assert outcome.status is CosignStatus.refused
    assert outcome.signature is None


def test_an_out_of_range_native_value_is_rejected_at_the_wire():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        SafeCall(to=_GOLDEN_TO, value=2**256, data="0x", operation=SafeOperation.call)


def test_open_reviews_lets_the_approval_channel_see_held_reviews():
    cosigner = _review_cosigner()
    assert cosigner.open_reviews() == ()
    held = cosigner.cosign(_review_call(), nonce=0, proposer=_PROPOSER, now=_NOW)
    reviews = cosigner.open_reviews()
    assert len(reviews) == 1
    assert reviews[0].approval_id == held.approval_id
    # It is the same object a resolve will consume, so the human sees what executes.
    assert reviews[0].maker.subject == _PROPOSER


def test_the_held_review_shows_the_amount_and_limit_to_the_human():
    cosigner = _review_cosigner()
    cosigner.cosign(_review_call(), nonce=0, proposer=_PROPOSER, now=_NOW)
    (review,) = cosigner.open_reviews()
    (finding,) = review.decision.findings
    # Not a bare "value exceeded" sentence: the magnitude and threshold are shown.
    assert finding.observed == 500
    assert finding.limit == 100
