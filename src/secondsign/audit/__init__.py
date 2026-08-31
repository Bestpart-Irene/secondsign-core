# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The audit layer.

The fail-closed, hash-chained AuditReceipt and the append-only sink contract
(CORE-S013). Every non-ALLOW path produces a receipt; a write that cannot be
persisted fails closed; a broken chain is detectable.
"""

from secondsign.audit.export import (
    EXPORT_FORMAT,
    EXPORT_VERSION,
    MalformedTrail,
    export_trail,
    load_trail,
)
from secondsign.audit.log import AuditLog, AuditSink, InMemoryAuditSink
from secondsign.audit.receipt import (
    GENESIS_HASH,
    AuditReceipt,
    first_break,
    hash_of,
    verify_chain,
)
from secondsign.audit.verify import (
    VerificationFailure,
    VerificationReport,
    verify_document,
)

__all__ = [
    "EXPORT_FORMAT",
    "EXPORT_VERSION",
    "GENESIS_HASH",
    "AuditLog",
    "AuditReceipt",
    "AuditSink",
    "InMemoryAuditSink",
    "MalformedTrail",
    "VerificationFailure",
    "VerificationReport",
    "export_trail",
    "first_break",
    "hash_of",
    "load_trail",
    "verify_chain",
    "verify_document",
]
