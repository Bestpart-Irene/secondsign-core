# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The offline verifier — the A7 answer an auditor can run.

    python -m secondsign.audit.verify trail.json [--expect-head HASH]

Takes an exported trail document and recomputes the chain with nothing but
this package: no running gateway, no network, no trust in the system that
produced the document. What it proves is what :func:`verify_chain` proves —
an edited, dropped, or reordered receipt is named — plus the one break the
chain alone cannot see: tail truncation, caught by comparing the recomputed
head against a commitment the auditor holds independently (a head hash
recorded at export time, out of band).

The verdict logic contains no chain arithmetic of its own. Diagnosis is
:func:`~secondsign.audit.receipt.first_break`, the same implementation
`verify_chain` delegates to, so this tool cannot disagree with the library
about whether a trail is intact.
"""

import argparse
import sys
from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from secondsign.audit.export import MalformedTrail, load_trail
from secondsign.audit.receipt import GENESIS_HASH, first_break


class VerificationFailure(StrEnum):
    """Why a document did not verify. Three findings, kept distinct: not a
    trail, a tampered trail, and a trail shorter than the one committed to."""

    malformed_document = "malformed_document"
    broken_chain = "broken_chain"
    head_mismatch = "head_mismatch"


class VerificationReport(BaseModel):
    """One verification, as data. The CLI renders this; tests read it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    intact: bool
    receipts: int = 0
    #: The recomputed head of the chain — :data:`GENESIS_HASH` for an empty
    #: trail, absent when the document could not be read at all.
    head_hash: str | None = None
    failure: VerificationFailure | None = None
    #: Where the chain broke, for `broken_chain` only.
    broken_sequence: int | None = None


def verify_document(document: str, *, expected_head: str | None = None) -> VerificationReport:
    """Re-verify an exported trail, months later, with nothing but the bytes.

    `expected_head` is the external commitment: the chain's head hash as
    recorded when the trail was exported. Without it, a truncated tail still
    verifies — the chain alone cannot know how long it was meant to be.
    """
    try:
        receipts = load_trail(document)
    except MalformedTrail:
        return VerificationReport(intact=False, failure=VerificationFailure.malformed_document)

    broken = first_break(receipts)
    if broken is not None:
        return VerificationReport(
            intact=False,
            receipts=len(receipts),
            failure=VerificationFailure.broken_chain,
            broken_sequence=broken,
        )

    head = receipts[-1].receipt_hash if receipts else GENESIS_HASH
    if expected_head is not None and head != expected_head:
        return VerificationReport(
            intact=False,
            receipts=len(receipts),
            head_hash=head,
            failure=VerificationFailure.head_mismatch,
        )
    return VerificationReport(intact=True, receipts=len(receipts), head_hash=head)


def main(argv: Sequence[str]) -> int:
    """The CLI. Exit 0 iff the trail verified, 1 for every other finding."""
    parser = argparse.ArgumentParser(
        prog="python -m secondsign.audit.verify",
        description="Re-verify an exported SecondSign audit trail, offline.",
    )
    parser.add_argument("trail", help="path to the exported trail document")
    parser.add_argument(
        "--expect-head",
        default=None,
        metavar="HASH",
        help="the head hash committed to at export time; catches tail truncation",
    )
    args = parser.parse_args(argv)

    try:
        document = Path(args.trail).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"could not read {args.trail}: {exc}")
        print("verdict: NOT VERIFIED")
        return 1

    report = verify_document(document, expected_head=args.expect_head)
    print(f"receipts: {report.receipts}")
    if report.head_hash is not None:
        print(f"head: {report.head_hash}")
    if report.failure is VerificationFailure.malformed_document:
        print("document: not a readable trail")
    elif report.failure is VerificationFailure.broken_chain:
        print(f"chain: broken at sequence {report.broken_sequence}")
    elif report.failure is VerificationFailure.head_mismatch:
        print(f"head commitment: MISMATCH — expected {args.expect_head}")
    else:
        print("chain: intact")
        if args.expect_head is not None:
            print("head commitment: matches")
    print(f"verdict: {'VERIFIED' if report.intact else 'NOT VERIFIED'}")
    return 0 if report.intact else 1


if __name__ == "__main__":  # pragma: no cover — the module trampoline; main() is tested directly
    raise SystemExit(main(sys.argv[1:]))
