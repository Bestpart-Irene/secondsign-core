# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""A file-backed audit sink: one receipt per JSONL line.

Deliberately boring. The value of this example is that it is complete and
certified, not that it is clever — a real deployment would swap the file for
its log pipeline or WORM store and keep everything else.

Two properties carry the contract, and both are visible in ``append``:

*A write failure is a failure* (INV-11). Nothing here catches ``OSError``. A
sink that swallows a failed write turns a hole in the audit trail into a
success code, which is the exact thing an audit trail exists to make
impossible. If the disk is full, the caller finds out, and the fail-closed
machinery above this sink treats the action accordingly.

*Nothing written is a raw identifier.* A receipt is already redacted — the
digest is a hash, the principal is a keyed fingerprint — and this sink asserts
that shape on every write rather than trusting it in a comment.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from secondsign.audit import AuditReceipt

#: The only reference-shaped values a receipt may carry: a 64-hex digest or
#: hash, and a keyed fingerprint. Anything else in those positions is treated
#: as a raw identifier and refused before it reaches disk.
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_FINGERPRINT = re.compile(r"^fp:[0-9a-f]{64}$")


def _assert_redacted(payload: dict[str, object]) -> None:
    """Refuse to persist anything shaped like an identity.

    The receipt model is closed (`extra="forbid"`), so unknown keys cannot
    arrive through it — this asserts the *values* in the reference-carrying
    positions still have their redacted shapes at the moment of writing.
    """
    unknown = set(payload) - set(AuditReceipt.model_fields)
    if unknown:
        raise AssertionError(f"receipt payload carries unknown fields: {sorted(unknown)}")
    for key in ("prev_hash", "receipt_hash"):
        value = payload[key]
        if not (isinstance(value, str) and _HEX_64.match(value)):
            raise AssertionError(f"{key} is not a 64-hex hash: {value!r}")
    digest = payload["digest"]
    if not (
        isinstance(digest, dict)
        and isinstance(digest.get("value"), str)
        and _HEX_64.match(digest["value"])
    ):
        raise AssertionError(f"digest is not a 64-hex hash: {digest!r}")
    principal = payload["principal_ref"]
    if principal is not None and not (isinstance(principal, str) and _FINGERPRINT.match(principal)):
        raise AssertionError(f"principal_ref is not a keyed fingerprint: {principal!r}")


class JsonlAuditSink:
    """Appends each receipt as one JSON line; reads the file back on demand.

    Satisfies :class:`secondsign.audit.AuditSink` structurally — ``append`` and
    ``entries`` are the whole protocol.
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)

    def append(self, receipt: AuditReceipt) -> None:
        payload = receipt.model_dump(mode="json")
        _assert_redacted(payload)
        line = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        # `open` before `write` before `flush`: any OSError propagates. The one
        # write is a single line, so a failure cannot leave a half-receipt that
        # parses — a torn final line fails `entries()` loudly instead.
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()

    def entries(self) -> tuple[AuditReceipt, ...]:
        if not self._path.exists():
            return ()
        lines = self._path.read_text(encoding="utf-8").splitlines()
        return tuple(AuditReceipt.model_validate(json.loads(line)) for line in lines)
