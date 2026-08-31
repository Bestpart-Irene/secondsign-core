# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the audit trail export and the offline verifier (CORE-S025).

What is under test is the A7 story: a trail leaves the running system as a
canonical document, and a third party re-verifies it later with nothing but
the document — and, for the truncation case, an externally held head
commitment. Every tamper case here edits the *document*, not the objects,
because the document is what an auditor actually receives.
"""

import json

import pytest

from secondsign.audit import GENESIS_HASH, first_break, verify_chain
from secondsign.audit.export import (
    EXPORT_FORMAT,
    EXPORT_VERSION,
    MalformedTrail,
    export_trail,
    load_trail,
)
from secondsign.audit.receipt import AuditReceipt
from secondsign.audit.verify import VerificationFailure, main, verify_document
from tests.audit.conftest import make_chain


def _document() -> str:
    return export_trail(make_chain().entries())


def _tampered(mutate) -> str:
    """The exported document with one edit applied to its parsed form."""
    material = json.loads(_document())
    mutate(material["receipts"])
    return json.dumps(material, sort_keys=True, separators=(",", ":"))


# --- export ---------------------------------------------------------------


def test_a_trail_round_trips_and_verifies():
    entries = make_chain().entries()
    assert load_trail(export_trail(entries)) == entries
    assert verify_chain(load_trail(export_trail(entries))) is True


def test_export_is_deterministic():
    entries = make_chain().entries()
    assert export_trail(entries) == export_trail(entries)


def test_an_empty_trail_round_trips():
    assert load_trail(export_trail(())) == ()


def test_the_export_carries_only_receipt_fields():
    """A5 discipline at the boundary: nothing beyond the receipt's
    already-redacted scalars leaves in the document."""
    material = json.loads(_document())
    for entry in material["receipts"]:
        assert set(entry) == set(AuditReceipt.model_fields)


def test_an_unknown_format_is_refused():
    material = json.loads(_document())
    material["format"] = "someone-elses-trail"
    with pytest.raises(MalformedTrail):
        load_trail(json.dumps(material))


def test_an_unknown_version_is_refused():
    material = json.loads(_document())
    material["version"] = EXPORT_VERSION + 1
    with pytest.raises(MalformedTrail):
        load_trail(json.dumps(material))


def test_a_receipt_with_an_extra_field_is_refused():
    document = _tampered(lambda receipts: receipts[0].update(note="hello"))
    with pytest.raises(MalformedTrail):
        load_trail(document)


def test_a_document_that_is_not_an_object_is_refused():
    with pytest.raises(MalformedTrail):
        load_trail("[]")


def test_receipts_that_are_not_a_list_are_refused():
    material = json.loads(_document())
    material["receipts"] = "three of them, honest"
    with pytest.raises(MalformedTrail):
        load_trail(json.dumps(material))


def test_the_document_names_its_format():
    material = json.loads(_document())
    assert material["format"] == EXPORT_FORMAT
    assert material["version"] == EXPORT_VERSION


# --- first_break: one implementation of the chain checks ------------------


def test_first_break_names_the_edited_sequence():
    entries = list(make_chain().entries())
    entries[1] = entries[1].model_copy(update={"approval_id": "forged"})
    assert first_break(tuple(entries)) == 1


def test_first_break_names_the_drop():
    entries = list(make_chain().entries())
    del entries[1]
    assert first_break(tuple(entries)) == 1


def test_first_break_names_the_reorder():
    entries = list(make_chain().entries())
    entries[0], entries[1] = entries[1], entries[0]
    assert first_break(tuple(entries)) == 0


def test_first_break_is_none_for_an_intact_chain():
    assert first_break(make_chain().entries()) is None
    assert first_break(()) is None


def test_verify_chain_and_first_break_never_disagree():
    """The control against a second implementation: over the whole tamper
    matrix, the boolean and the diagnosis are the same judgement."""
    tampers = [
        lambda e: e,
        lambda e: e[1:],
        lambda e: e[:-1],
        lambda e: (e[1], e[0], e[2]),
        lambda e: (e[0].model_copy(update={"approval_id": "x"}),) + e[1:],
        lambda e: e + (e[0],),
    ]
    entries = make_chain().entries()
    for tamper in tampers:
        candidate = tuple(tamper(entries))
        assert verify_chain(candidate) is (first_break(candidate) is None)


# --- offline verification -------------------------------------------------


def test_a_genuine_document_verifies():
    report = verify_document(_document())
    assert report.intact is True
    assert report.failure is None
    assert report.receipts == 3
    assert report.head_hash == make_chain().entries()[-1].receipt_hash


def test_an_empty_document_verifies_to_genesis():
    report = verify_document(export_trail(()))
    assert report.intact is True
    assert report.head_hash == GENESIS_HASH


def test_an_edited_field_fails_and_names_the_sequence():
    document = _tampered(lambda receipts: receipts[1].update(approval_id="forged"))
    report = verify_document(document)
    assert report.intact is False
    assert report.failure is VerificationFailure.broken_chain
    assert report.broken_sequence == 1


def test_a_dropped_receipt_fails_and_names_the_sequence():
    document = _tampered(lambda receipts: receipts.pop(1))
    report = verify_document(document)
    assert report.intact is False
    assert report.failure is VerificationFailure.broken_chain
    assert report.broken_sequence == 1


def test_a_reordered_pair_fails_and_names_the_sequence():
    def swap(receipts):
        receipts[0], receipts[1] = receipts[1], receipts[0]

    report = verify_document(_tampered(swap))
    assert report.intact is False
    assert report.failure is VerificationFailure.broken_chain
    assert report.broken_sequence == 0


def test_a_malformed_document_is_a_failure_not_a_crash():
    report = verify_document("not json at all")
    assert report.intact is False
    assert report.failure is VerificationFailure.malformed_document


def test_a_truncated_tail_passes_the_chain_alone():
    """The documented gap, pinned: dropping the last receipts leaves a shorter
    but internally valid chain. This is exactly why the commitment exists."""
    document = _tampered(lambda receipts: receipts.pop())
    assert verify_document(document).intact is True


def test_the_head_commitment_catches_the_truncated_tail():
    head = make_chain().entries()[-1].receipt_hash
    document = _tampered(lambda receipts: receipts.pop())
    report = verify_document(document, expected_head=head)
    assert report.intact is False
    assert report.failure is VerificationFailure.head_mismatch


def test_the_head_commitment_accepts_the_genuine_trail():
    head = make_chain().entries()[-1].receipt_hash
    assert verify_document(_document(), expected_head=head).intact is True


# --- the CLI --------------------------------------------------------------


def _write(tmp_path, document: str):
    path = tmp_path / "trail.json"
    path.write_text(document, encoding="utf-8")
    return path


def test_the_cli_verifies_a_genuine_export(tmp_path, capsys):
    assert main([str(_write(tmp_path, _document()))]) == 0
    out = capsys.readouterr().out
    assert "VERIFIED" in out
    assert make_chain().entries()[-1].receipt_hash in out


def test_the_cli_rejects_a_tampered_export(tmp_path, capsys):
    document = _tampered(lambda receipts: receipts[1].update(approval_id="forged"))
    assert main([str(_write(tmp_path, document))]) == 1
    assert "sequence 1" in capsys.readouterr().out


def test_the_cli_enforces_the_head_commitment(tmp_path):
    head = make_chain().entries()[-1].receipt_hash
    truncated = _tampered(lambda receipts: receipts.pop())
    assert main([str(_write(tmp_path, truncated)), "--expect-head", head]) == 1
    assert main([str(_write(tmp_path, _document())), "--expect-head", head]) == 0


def test_the_cli_reports_a_missing_file_as_failure(tmp_path, capsys):
    assert main([str(tmp_path / "absent.json")]) == 1
    assert "NOT VERIFIED" in capsys.readouterr().out


def test_the_cli_reports_a_malformed_document_as_failure(tmp_path, capsys):
    assert main([str(_write(tmp_path, "not json at all"))]) == 1
    assert "NOT VERIFIED" in capsys.readouterr().out
