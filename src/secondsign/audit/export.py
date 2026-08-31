# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The audit trail as a document that leaves the running system.

A trail inside the process is a tuple of receipts; a trail handed to an
auditor is this document — canonical JSON, a named format, a version, and
nothing else. Canonical (sorted keys, no whitespace) so that the same receipts
always produce the same bytes: two exports of one trail can be compared as
files, and a commitment made over one holds over the other.

Loading is fail-closed and whole-document: an unknown format, an unknown
version, or a single receipt that does not validate refuses the entire trail
(A5 — a receipt with an extra field is not a receipt). A partially read trail
would verify a chain nobody exported.
"""

import json
from typing import Final

from pydantic import ValidationError

from secondsign.audit.receipt import AuditReceipt

#: The format tag every export carries. A reader that does not recognise it
#: must refuse, so the tag is checked, never assumed.
EXPORT_FORMAT: Final[str] = "secondsign-audit-trail"

#: The document version. Revved when the shape changes; an older reader
#: refuses a newer document rather than misreading it.
EXPORT_VERSION: Final[int] = 1


class MalformedTrail(ValueError):
    """The document is not a trail this version can read. Refused whole:
    nothing is loaded from a document that is partly wrong."""


def export_trail(receipts: tuple[AuditReceipt, ...]) -> str:
    """The trail as a canonical, self-describing JSON document."""
    material = {
        "format": EXPORT_FORMAT,
        "version": EXPORT_VERSION,
        "receipts": [receipt.model_dump(mode="json") for receipt in receipts],
    }
    return json.dumps(material, sort_keys=True, separators=(",", ":"))


def load_trail(document: str) -> tuple[AuditReceipt, ...]:
    """The receipts back from a document, or :class:`MalformedTrail`.

    Loading validates shape, not integrity — a loaded trail may still fail
    :func:`~secondsign.audit.receipt.verify_chain`. The split is deliberate:
    "this is not a trail" and "this trail was tampered with" are different
    findings, and a verifier reports them differently.
    """
    try:
        material = json.loads(document)
    except json.JSONDecodeError as exc:
        raise MalformedTrail("the document is not JSON") from exc
    if not isinstance(material, dict):
        raise MalformedTrail("the document is not an object")
    if material.get("format") != EXPORT_FORMAT:
        raise MalformedTrail("the document does not name this format")
    if material.get("version") != EXPORT_VERSION:
        raise MalformedTrail("the document names a version this reader cannot read")
    entries = material.get("receipts")
    if not isinstance(entries, list):
        raise MalformedTrail("the document carries no receipt list")
    try:
        return tuple(AuditReceipt.model_validate(entry) for entry in entries)
    except ValidationError as exc:
        raise MalformedTrail("a receipt in the document does not validate") from exc
