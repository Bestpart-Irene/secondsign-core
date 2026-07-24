# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The audit layer.

The fail-closed, hash-chained AuditReceipt and the append-only sink contract
(CORE-S013). Every non-ALLOW path produces a receipt; a write that cannot be
persisted fails closed; a broken chain is detectable.
"""

from secondsign.audit.log import AuditLog, AuditSink, InMemoryAuditSink
from secondsign.audit.receipt import (
    GENESIS_HASH,
    AuditReceipt,
    hash_of,
    verify_chain,
)

__all__ = [
    "GENESIS_HASH",
    "AuditLog",
    "AuditReceipt",
    "AuditSink",
    "InMemoryAuditSink",
    "hash_of",
    "verify_chain",
]
