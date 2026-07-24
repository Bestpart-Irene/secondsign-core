# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the hash-chained AuditReceipt.

The chain's job is that a break is *detectable* — a removed, reordered, or
tampered receipt cannot pass verification. Each receipt links the previous one
by hash, so editing any field or dropping any entry desynchronises the chain.
"""

from secondsign.audit import GENESIS_HASH, hash_of, verify_chain
from secondsign.contracts import ReasonCode
from secondsign.decision import DecisionVerdict
from tests.audit.conftest import make_chain


def test_a_fresh_chain_starts_from_genesis():
    entries = make_chain().entries()
    assert entries[0].prev_hash == GENESIS_HASH
    assert entries[0].sequence == 0


def test_each_receipt_links_the_previous_one():
    entries = make_chain().entries()
    for earlier, later in zip(entries, entries[1:], strict=False):
        assert later.prev_hash == earlier.receipt_hash
        assert later.sequence == earlier.sequence + 1


def test_a_valid_chain_verifies():
    assert verify_chain(make_chain().entries()) is True


def test_the_receipt_hash_matches_its_content():
    for receipt in make_chain().entries():
        assert hash_of(receipt) == receipt.receipt_hash


def test_a_tampered_field_breaks_the_chain():
    entries = list(make_chain().entries())
    # Rewrite a field but keep the stored hash — verification recomputes it.
    entries[1] = entries[1].model_copy(update={"verdict": DecisionVerdict.ALLOW})
    assert verify_chain(entries) is False


def test_a_removed_receipt_breaks_the_chain():
    entries = list(make_chain().entries())
    del entries[1]
    assert verify_chain(entries) is False


def test_a_reordered_chain_breaks():
    entries = list(make_chain().entries())
    entries[0], entries[1] = entries[1], entries[0]
    assert verify_chain(entries) is False


def test_a_broken_prev_link_is_detected_even_if_self_consistent():
    """A receipt with the right sequence and a matching self-hash but a prev_hash
    that points nowhere in the chain is still caught by the linkage check."""
    entries = list(make_chain().entries())
    forged = entries[1].model_copy(update={"prev_hash": "f" * 64})
    forged = forged.model_copy(update={"receipt_hash": hash_of(forged)})
    assert hash_of(forged) == forged.receipt_hash  # self-consistent...
    entries[1] = forged
    assert verify_chain(entries) is False  # ...but the link is broken


def test_an_empty_chain_verifies_vacuously():
    assert verify_chain(()) is True


def test_receipt_is_frozen():
    import pytest
    from pydantic import ValidationError

    receipt = make_chain().entries()[0]
    with pytest.raises(ValidationError):
        receipt.sequence = 99


def test_receipt_carries_only_redacted_references():
    """A1/A5 — a receipt records the digest and reason codes, never a raw value."""
    receipt = make_chain().entries()[0]
    dumped = receipt.model_dump()
    assert set(dumped) == {
        "sequence",
        "prev_hash",
        "digest",
        "verdict",
        "reasons",
        "outcome_status",
        "approval_id",
        "receipt_hash",
    }
    assert all(isinstance(code, ReasonCode) for code in receipt.reasons)
