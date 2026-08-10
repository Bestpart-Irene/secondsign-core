# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The on-chain co-signer: it re-verifies the chain, then signs only on ALLOW.

Two load-bearing groups. The **golden hashes** assert the Python EIP-712 hash
byte-for-byte against Safe 1.5.0's own ``getTransactionHash`` (chain 1 / call /
nonce 0, and a second at chain 8453 / delegatecall / nonce 5), so a signature is
one the account will honour. The **re-verification** cases (ONCHAIN-S007) prove
the co-signer reads the live Safe state before signing: it uses the chain nonce,
refuses on any drift from the attested config or the pinned token, and refuses
outright when it is not wired to verify — fail-closed, never trusting the caller.
"""

import tomllib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from eth_account import Account

from secondsign.approval import CheckerIdentity, CheckerVerdict
from secondsign.audit import InMemoryAuditSink, verify_chain
from secondsign.decision import DecisionVerdict
from secondsign.gateway.onchain_cosigner import (
    CosignStatus,
    OnchainCosigner,
    SafeContext,
    safe_transaction_hash,
)
from secondsign.gateway.signer import LocalSigner
from secondsign.intent import ProposalDigest
from secondsign.isolation import Side, classify
from secondsign.onchain.chain_state import (
    ExpectedSafeConfig,
    SafeChainState,
    StaticChainStateReader,
    TokenIdentity,
)
from secondsign.onchain.effect import SafeCall, SafeOperation
from secondsign.onchain.types import OnchainReasonCode

_GOLDEN_SAFE = "0x2e234DAe75C793f67A35089C9d99245E1C58470b"
_GOLDEN_CHAIN = 1
_GOLDEN_TO = "0x2222222222222222222222222222222222222222"
_GOLDEN_SPENDER = "0x3333333333333333333333333333333333333333"
_GOLDEN_HASH = bytes.fromhex("bbdf078a1eee6cb2e877f7725ceeb6d0e83094367b6346787fe6fc273f662068")

_KEY = b"\xa1" * 32


def _signer() -> LocalSigner:
    return LocalSigner(_KEY)


_APPROVE = "0x095ea7b3"
_PROPOSER = "agent-workload"
_NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)

# The attested account/token the wired co-signer signs for. The pinned token is
# _GOLDEN_TO, the asset the approve/transfer calls in these tests target.
_OWNER_AGENT = "0x" + "a1" * 20
_OWNER_SS = "0x" + "b2" * 20
_TX_GUARD = "0x" + "c3" * 20
_MOD_GUARD = "0x" + "d4" * 20
_TOKEN_IMPL = "0x" + "e5" * 20
_TOKEN_CODEHASH = "0x" + "11" * 32


def _context() -> SafeContext:
    return SafeContext(safe_address=_GOLDEN_SAFE, chain_id=_GOLDEN_CHAIN)


def _token_identity(
    implementation: str = _TOKEN_IMPL, code_hash: str = _TOKEN_CODEHASH
) -> TokenIdentity:
    return TokenIdentity(implementation=implementation, code_hash=code_hash)


def _safe_state(nonce: int = 0, **over: object) -> SafeChainState:
    base: dict[str, object] = dict(
        nonce=nonce,
        owners=(_OWNER_AGENT, _OWNER_SS),
        threshold=2,
        transaction_guard=_TX_GUARD,
        module_guard=_MOD_GUARD,
        chain_id=_GOLDEN_CHAIN,
        safe_version="1.5.0",
    )
    base.update(over)
    return SafeChainState(**base)  # type: ignore[arg-type]


def _expected(**over: object) -> ExpectedSafeConfig:
    base: dict[str, object] = dict(
        chain_id=_GOLDEN_CHAIN,
        safe_version="1.5.0",
        owners=frozenset({_OWNER_AGENT, _OWNER_SS}),
        threshold=2,
        transaction_guard=_TX_GUARD,
        module_guard=_MOD_GUARD,
        token=_GOLDEN_TO,
        token_identity=_token_identity(),
    )
    base.update(over)
    return ExpectedSafeConfig(**base)  # type: ignore[arg-type]


def _reader(
    state: SafeChainState | None = None,
    implementation: str = _TOKEN_IMPL,
    code_hash: str = _TOKEN_CODEHASH,
) -> StaticChainStateReader:
    return StaticChainStateReader(
        safe_state=state if state is not None else _safe_state(),
        token_identities={_GOLDEN_TO: _token_identity(implementation, code_hash)},
    )


def _cosigner(
    *,
    approval_cap: int = 1_000,
    review_above: int | None = None,
    spenders: frozenset[str] = frozenset({_GOLDEN_SPENDER}),
    reader: StaticChainStateReader | None = None,
    expected: ExpectedSafeConfig | None = None,
    audit_sink: InMemoryAuditSink | None = None,
) -> OnchainCosigner:
    return OnchainCosigner(
        _signer(),
        _context(),
        approval_cap=approval_cap,
        reader=reader if reader is not None else _reader(),
        expected=expected if expected is not None else _expected(),
        review_above=review_above,
        approve_spender_allowlist=spenders,
        audit_sink=audit_sink,
    )


def _word(hex_or_int: str) -> str:
    return hex_or_int.removeprefix("0x").rjust(64, "0")


def _approve_data(spender: str, amount: int) -> str:
    return _APPROVE + _word(spender) + _word(f"{amount:x}")


def _approve_call(
    spender: str = _GOLDEN_SPENDER, amount: int = 100, to: str = _GOLDEN_TO
) -> SafeCall:
    return SafeCall(
        to=to, value=0, data=_approve_data(spender, amount), operation=SafeOperation.call
    )


# --- golden hashes: the Python EIP-712 hash matches the real Safe ---


def test_the_hash_matches_the_real_safe_getTransactionHash():
    context = SafeContext(safe_address=_GOLDEN_SAFE, chain_id=_GOLDEN_CHAIN)
    assert safe_transaction_hash(_approve_call(), context, nonce=0) == _GOLDEN_HASH


_GOLDEN2_CHAIN = 8453
_GOLDEN2_TO = "0x1111111111111111111111111111111111111111"
_GOLDEN2_DATA = "0xdeadbeef"
_GOLDEN2_NONCE = 5
_GOLDEN2_HASH = bytes.fromhex("52178f40a03b4cc044824cd216ad5caf32b885616ae40bece1fa48d876bca6bf")


def test_the_hash_matches_the_real_safe_for_a_delegatecall_on_another_chain():
    call = SafeCall(
        to=_GOLDEN2_TO, value=0, data=_GOLDEN2_DATA, operation=SafeOperation.delegatecall
    )
    context = SafeContext(safe_address=_GOLDEN_SAFE, chain_id=_GOLDEN2_CHAIN)
    assert safe_transaction_hash(call, context, nonce=_GOLDEN2_NONCE) == _GOLDEN2_HASH


# --- the signing boundary ---


def test_an_allowed_action_is_signed_and_the_signature_recovers_to_the_cosigner():
    cosigner = _cosigner()
    outcome = cosigner.cosign(_approve_call(), proposer=_PROPOSER, now=_NOW)
    assert outcome.status is CosignStatus.signed
    assert outcome.signature is not None
    # Signed against the chain nonce (0), so the hash is the golden one.
    signature = bytes.fromhex(outcome.signature.removeprefix("0x"))
    assert Account._recover_hash(_GOLDEN_HASH, signature=signature) == cosigner.address


def test_the_cosigner_signs_only_through_the_provider_contract():
    # ONCHAIN-S009: the co-signer holds no key — it signs through the SignerProvider
    # it is handed. A provider that never touches eth_account drives it end to end,
    # returning exactly that provider's signature. If the co-signer reintroduced a
    # raw key it would not produce the provider's canned value.
    canned = "0x" + "cd" * 65

    class FakeKmsSigner:
        @property
        def address(self) -> str:
            return "0x" + "ab" * 20

        def sign_hash(self, tx_hash: bytes) -> str:
            return canned

    cosigner = OnchainCosigner(
        FakeKmsSigner(),
        _context(),
        approval_cap=1_000,
        reader=_reader(),
        expected=_expected(),
        approve_spender_allowlist=frozenset({_GOLDEN_SPENDER}),
    )
    outcome = cosigner.cosign(_approve_call(), proposer=_PROPOSER, now=_NOW)
    assert outcome.status is CosignStatus.signed
    assert outcome.signature == canned
    assert cosigner.address == "0x" + "ab" * 20


def test_an_unlimited_approval_is_refused_with_no_signature():
    cosigner = _cosigner()
    outcome = cosigner.cosign(_approve_call(amount=2**256 - 1), proposer=_PROPOSER, now=_NOW)
    assert outcome.status is CosignStatus.refused
    assert outcome.signature is None


def test_a_delegatecall_is_refused():
    cosigner = _cosigner()
    call = SafeCall(to=_GOLDEN_TO, value=0, data="0x", operation=SafeOperation.delegatecall)
    assert cosigner.cosign(call, proposer=_PROPOSER, now=_NOW).status is CosignStatus.refused


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


def test_a_bounded_approval_to_an_unlisted_spender_is_not_silently_signed():
    # approve(attacker, 999) is bounded, so the amount alone raises no concern — a
    # signature would hand the attacker a live allowance to pull with transferFrom.
    cosigner = _cosigner(spenders=frozenset())
    attacker = "0x4444444444444444444444444444444444444444"
    outcome = cosigner.cosign(
        _approve_call(spender=attacker, amount=999), proposer=_PROPOSER, now=_NOW
    )
    assert outcome.status is not CosignStatus.signed
    assert outcome.signature is None


def test_a_verdict_the_cosigner_does_not_recognise_refuses_rather_than_signs(monkeypatch):
    # ABSTAIN is the only state that signs. A verdict outside the vocabulary must
    # refuse, not fall through — checked after re-verification, which stays real.
    from types import SimpleNamespace

    from secondsign.gateway import onchain_cosigner as module

    cosigner = _cosigner()
    monkeypatch.setattr(
        module.policy, "evaluate", lambda *args, **kwargs: SimpleNamespace(verdict=object())
    )
    outcome = cosigner.cosign(_approve_call(), proposer=_PROPOSER, now=_NOW)
    assert outcome.status is CosignStatus.refused
    assert outcome.signature is None


def test_native_value_alongside_a_bounded_call_is_refused():
    # A bounded approve carrying ~1000 ETH of native value: the value moving with
    # the concern-free calldata must not be ignored.
    cosigner = _cosigner()
    call = SafeCall(
        to=_GOLDEN_TO,
        value=10**21,
        data=_approve_data(_GOLDEN_SPENDER, 1),
        operation=SafeOperation.call,
    )
    outcome = cosigner.cosign(call, proposer=_PROPOSER, now=_NOW)
    assert outcome.status is CosignStatus.refused
    assert outcome.signature is None


def test_an_out_of_range_native_value_is_rejected_at_the_wire():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        SafeCall(to=_GOLDEN_TO, value=2**256, data="0x", operation=SafeOperation.call)


# --- ONCHAIN-S007: chain re-verification and token identity ---


def test_a_cosigner_not_wired_to_verify_refuses_to_sign():
    # Fail-closed: without a reader and an attested config the co-signer cannot
    # confirm the account or token, so it refuses rather than trust the caller.
    no_reader = OnchainCosigner(_signer(), _context(), approval_cap=1_000)
    assert no_reader.cosign(_approve_call(), proposer=_PROPOSER, now=_NOW).status is (
        CosignStatus.refused
    )
    reader_only = OnchainCosigner(_signer(), _context(), approval_cap=1_000, reader=_reader())
    assert reader_only.cosign(_approve_call(), proposer=_PROPOSER, now=_NOW).status is (
        CosignStatus.refused
    )


def test_the_chain_nonce_is_used_not_a_caller_value():
    # The co-signer signs against the nonce it reads from chain (7 here), so the
    # signature recovers against the hash at nonce 7, not nonce 0.
    cosigner = _cosigner(reader=_reader(state=_safe_state(nonce=7)))
    outcome = cosigner.cosign(_approve_call(), proposer=_PROPOSER, now=_NOW)
    assert outcome.status is CosignStatus.signed
    expected_hash = safe_transaction_hash(_approve_call(), _context(), nonce=7)
    signature = bytes.fromhex(outcome.signature.removeprefix("0x"))
    assert Account._recover_hash(expected_hash, signature=signature) == cosigner.address
    assert expected_hash != _GOLDEN_HASH  # nonce 7 is not nonce 0


def test_a_drifted_guard_refuses():
    cosigner = _cosigner(reader=_reader(state=_safe_state(transaction_guard="0x" + "00" * 20)))
    outcome = cosigner.cosign(_approve_call(), proposer=_PROPOSER, now=_NOW)
    assert outcome.status is CosignStatus.refused
    assert outcome.judgement.reasons == (OnchainReasonCode.structural_change,)


def test_a_changed_owner_set_refuses():
    cosigner = _cosigner(reader=_reader(state=_safe_state(owners=(_OWNER_AGENT, "0x" + "cc" * 20))))
    outcome = cosigner.cosign(_approve_call(), proposer=_PROPOSER, now=_NOW)
    assert outcome.status is CosignStatus.refused
    assert outcome.judgement.reasons == (OnchainReasonCode.structural_change,)


def test_a_wrong_live_chain_refuses():
    cosigner = _cosigner(reader=_reader(state=_safe_state(chain_id=999)))
    outcome = cosigner.cosign(_approve_call(), proposer=_PROPOSER, now=_NOW)
    assert outcome.status is CosignStatus.refused
    assert outcome.judgement.reasons == (OnchainReasonCode.replayed_signature,)


def test_a_drifted_token_implementation_refuses():
    cosigner = _cosigner(reader=_reader(implementation="0x" + "ff" * 20))
    outcome = cosigner.cosign(_approve_call(), proposer=_PROPOSER, now=_NOW)
    assert outcome.status is CosignStatus.refused
    assert outcome.judgement.reasons == (OnchainReasonCode.implementation_moved,)


def test_a_call_to_an_unpinned_token_refuses():
    # The pinned token is _GOLDEN_TO; a transfer/approve on any other token refuses.
    cosigner = _cosigner()
    other = "0x5555555555555555555555555555555555555555"
    outcome = cosigner.cosign(_approve_call(to=other), proposer=_PROPOSER, now=_NOW)
    assert outcome.status is CosignStatus.refused
    assert outcome.judgement.reasons == (OnchainReasonCode.token_not_allowlisted,)


def test_construction_rejects_a_chain_id_disagreement():
    import pytest

    with pytest.raises(ValueError, match="chain_id"):
        OnchainCosigner(
            _signer(),
            SafeContext(safe_address=_GOLDEN_SAFE, chain_id=1),
            approval_cap=1_000,
            reader=_reader(),
            expected=_expected(chain_id=8453),
        )


def test_a_drift_refusal_is_recorded():
    sink = InMemoryAuditSink()
    cosigner = _cosigner(
        reader=_reader(state=_safe_state(transaction_guard="0x" + "00" * 20)), audit_sink=sink
    )
    cosigner.cosign(_approve_call(), proposer=_PROPOSER, now=_NOW)
    (receipt,) = sink.entries()
    assert receipt.verdict is DecisionVerdict.DENY


# --- review flow ---


def _review_cosigner(reader: StaticChainStateReader | None = None) -> OnchainCosigner:
    return _cosigner(review_above=100, reader=reader)


def _review_call() -> SafeCall:
    return _approve_call(amount=500)


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
    outcome = _review_cosigner().cosign(_review_call(), proposer=_PROPOSER, now=_NOW)
    assert outcome.status is CosignStatus.held
    assert outcome.approval_id is not None
    assert outcome.signature is None


def test_a_held_review_is_signed_once_a_different_checker_approves():
    cosigner = _review_cosigner()
    held = cosigner.cosign(_review_call(), proposer=_PROPOSER, now=_NOW)
    resolved = cosigner.resolve(held.approval_id, _checker_verdict(held.approval_id), now=_NOW)
    assert resolved.status is CosignStatus.signed
    sig = bytes.fromhex(resolved.signature.removeprefix("0x"))
    assert Account._recover_hash(bytes.fromhex(held.approval_id), signature=sig) == cosigner.address


def test_a_self_approval_is_refused():
    cosigner = _review_cosigner()
    held = cosigner.cosign(_review_call(), proposer=_PROPOSER, now=_NOW)
    resolved = cosigner.resolve(
        held.approval_id, _checker_verdict(held.approval_id, subject=_PROPOSER), now=_NOW
    )
    assert resolved.status is CosignStatus.refused
    assert resolved.signature is None


def test_a_declined_review_is_refused():
    cosigner = _review_cosigner()
    held = cosigner.cosign(_review_call(), proposer=_PROPOSER, now=_NOW)
    resolved = cosigner.resolve(
        held.approval_id, _checker_verdict(held.approval_id, approved=False), now=_NOW
    )
    assert resolved.status is CosignStatus.refused


def test_resolve_refuses_if_the_account_drifts_while_held():
    # The chain re-verifies before consuming: a guard removed while the review was
    # held refuses on resolve — drift, not a stale nonce, so no effect_outside_model.
    cosigner = _review_cosigner()
    held = cosigner.cosign(_review_call(), proposer=_PROPOSER, now=_NOW)
    cosigner._reader = _reader(state=_safe_state(transaction_guard="0x" + "00" * 20))
    resolved = cosigner.resolve(held.approval_id, _checker_verdict(held.approval_id), now=_NOW)
    assert resolved.status is CosignStatus.refused
    assert resolved.judgement.reasons == (OnchainReasonCode.structural_change,)


def test_resolve_refuses_if_the_cosigner_is_unwired_after_holding():
    # Defensive fail-closed: if the reader is gone by resolve time, refuse rather
    # than sign a held review no longer confirmable against the chain.
    cosigner = _review_cosigner()
    held = cosigner.cosign(_review_call(), proposer=_PROPOSER, now=_NOW)
    cosigner._reader = None
    resolved = cosigner.resolve(held.approval_id, _checker_verdict(held.approval_id), now=_NOW)
    assert resolved.status is CosignStatus.refused
    assert resolved.signature is None


def test_an_expired_review_is_refused():
    cosigner = _review_cosigner()
    held = cosigner.cosign(_review_call(), proposer=_PROPOSER, now=_NOW)
    late = _NOW + timedelta(hours=5)
    resolved = cosigner.resolve(held.approval_id, _checker_verdict(held.approval_id), now=late)
    assert resolved.status is CosignStatus.refused


def test_an_unknown_approval_is_refused_with_no_judgement():
    unknown = "00" * 32
    resolved = _review_cosigner().resolve(unknown, _checker_verdict(unknown), now=_NOW)
    assert resolved.status is CosignStatus.refused
    assert resolved.judgement is None


def test_a_declined_review_cannot_be_approved_by_a_second_checker():
    cosigner = _review_cosigner()
    held = cosigner.cosign(_review_call(), proposer=_PROPOSER, now=_NOW)
    declined = cosigner.resolve(
        held.approval_id,
        _checker_verdict(held.approval_id, subject="checker-a", approved=False),
        now=_NOW,
    )
    assert declined.status is CosignStatus.refused
    second = cosigner.resolve(
        held.approval_id,
        _checker_verdict(held.approval_id, subject="checker-b", approved=True),
        now=_NOW,
    )
    assert second.status is CosignStatus.refused
    assert second.signature is None


def test_re_proposing_a_held_review_does_not_refresh_its_ttl():
    cosigner = _review_cosigner()
    held = cosigner.cosign(_review_call(), proposer=_PROPOSER, now=_NOW)
    later = _NOW + timedelta(hours=100)
    re_held = cosigner.cosign(_review_call(), proposer=_PROPOSER, now=later)
    assert re_held.status is CosignStatus.held
    assert re_held.approval_id == held.approval_id
    resolved = cosigner.resolve(
        held.approval_id, _checker_verdict(held.approval_id), now=_NOW + timedelta(hours=101)
    )
    assert resolved.status is CosignStatus.refused


def test_re_proposing_does_not_rebind_the_maker_to_a_new_proposer():
    cosigner = _review_cosigner()
    held = cosigner.cosign(_review_call(), proposer=_PROPOSER, now=_NOW)
    cosigner.cosign(_review_call(), proposer="someone-else", now=_NOW)
    resolved = cosigner.resolve(
        held.approval_id, _checker_verdict(held.approval_id, subject=_PROPOSER), now=_NOW
    )
    assert resolved.status is CosignStatus.refused


def test_re_proposing_an_already_signed_review_is_refused_not_re_held():
    cosigner = _review_cosigner()
    held = cosigner.cosign(_review_call(), proposer=_PROPOSER, now=_NOW)
    signed = cosigner.resolve(held.approval_id, _checker_verdict(held.approval_id), now=_NOW)
    assert signed.status is CosignStatus.signed
    retry = cosigner.cosign(_review_call(), proposer=_PROPOSER, now=_NOW)
    assert retry.status is CosignStatus.refused


def test_a_held_review_whose_chain_nonce_advanced_is_stale():
    # The chain moved on while the review was held: the approved content is no
    # longer the account's next transaction, so resolve refuses (re-decision).
    reader = _reader(state=_safe_state(nonce=5))
    cosigner = _review_cosigner(reader=reader)
    held = cosigner.cosign(_review_call(), proposer=_PROPOSER, now=_NOW)
    # The Safe executed something else; the nonce advanced to 6.
    cosigner._reader = _reader(state=_safe_state(nonce=6))
    resolved = cosigner.resolve(held.approval_id, _checker_verdict(held.approval_id), now=_NOW)
    assert resolved.status is CosignStatus.refused
    assert resolved.signature is None
    assert OnchainReasonCode.effect_outside_model in resolved.judgement.reasons


def test_a_naive_datetime_is_refused_on_every_path():
    cosigner = _review_cosigner()
    naive = datetime(2026, 1, 1, 12, 0)
    import pytest

    with pytest.raises(ValueError, match="timezone-aware"):
        cosigner.cosign(_review_call(), proposer=_PROPOSER, now=naive)
    with pytest.raises(ValueError, match="timezone-aware"):
        cosigner.resolve("00" * 32, _checker_verdict("00" * 32), now=naive)


def test_open_reviews_lets_the_approval_channel_see_held_reviews():
    cosigner = _review_cosigner()
    assert cosigner.open_reviews() == ()
    held = cosigner.cosign(_review_call(), proposer=_PROPOSER, now=_NOW)
    reviews = cosigner.open_reviews()
    assert len(reviews) == 1
    assert reviews[0].approval_id == held.approval_id
    assert reviews[0].maker.subject == _PROPOSER


def test_the_held_review_shows_the_amount_and_limit_to_the_human():
    cosigner = _review_cosigner()
    cosigner.cosign(_review_call(), proposer=_PROPOSER, now=_NOW)
    (review,) = cosigner.open_reviews()
    (finding,) = review.decision.findings
    assert finding.observed == 500
    assert finding.limit == 100


# --- audit trail ---


def test_a_signature_is_recorded_in_the_audit_trail():
    sink = InMemoryAuditSink()
    cosigner = _cosigner(audit_sink=sink)
    cosigner.cosign(_approve_call(), proposer=_PROPOSER, now=_NOW)
    (receipt,) = sink.entries()
    assert receipt.verdict is DecisionVerdict.ALLOW
    assert receipt.digest.value == safe_transaction_hash(_approve_call(), _context(), 0).hex()
    assert verify_chain(sink.entries())


def test_a_refusal_is_recorded_in_the_audit_trail():
    sink = InMemoryAuditSink()
    cosigner = _cosigner(spenders=frozenset(), audit_sink=sink)
    cosigner.cosign(_approve_call(), proposer=_PROPOSER, now=_NOW)
    (receipt,) = sink.entries()
    assert receipt.verdict is DecisionVerdict.DENY


def test_a_held_review_and_its_decline_are_both_recorded():
    sink = InMemoryAuditSink()
    cosigner = _cosigner(review_above=100, audit_sink=sink)
    held = cosigner.cosign(_review_call(), proposer=_PROPOSER, now=_NOW)
    cosigner.resolve(
        held.approval_id,
        _checker_verdict(held.approval_id, subject="checker-a", approved=False),
        now=_NOW,
    )
    verdicts = [r.verdict for r in sink.entries()]
    assert verdicts == [DecisionVerdict.REVIEW, DecisionVerdict.DENY]
    assert all(r.approval_id == held.approval_id for r in sink.entries())


def test_a_review_signed_after_approval_is_recorded():
    sink = InMemoryAuditSink()
    cosigner = _cosigner(review_above=100, audit_sink=sink)
    held = cosigner.cosign(_review_call(), proposer=_PROPOSER, now=_NOW)
    cosigner.resolve(held.approval_id, _checker_verdict(held.approval_id), now=_NOW)
    verdicts = [r.verdict for r in sink.entries()]
    assert verdicts == [DecisionVerdict.REVIEW, DecisionVerdict.ALLOW]


def test_a_cosigner_not_wired_to_verify_writes_no_receipt():
    # An unwired co-signer refuses before any judgement — nothing to record.
    sink = InMemoryAuditSink()
    OnchainCosigner(_signer(), _context(), approval_cap=1_000, audit_sink=sink).cosign(
        _approve_call(), proposer=_PROPOSER, now=_NOW
    )
    assert sink.entries() == ()
