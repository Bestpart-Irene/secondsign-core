# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The hash-chained AuditReceipt.

A receipt records what happened to one intent — the digest it was, the verdict
it got, the approval it carried, and how its execution ended — and links to the
receipt before it by hash. The chain's purpose is *detectability*: editing any
field, dropping any entry, or reordering the log desynchronises the hashes, so a
tamper cannot pass :func:`verify_chain`.

The field set is an exact scalar allow-list (A5), ratcheted in the tests: a
receipt carries the digest and reason codes, never a raw value or a free-form
field (A1). It never holds an amount, an account, or a counterparty — only their
already-redacted forms as they appear upstream.
"""

import hashlib
import json

from pydantic import BaseModel, ConfigDict, Field

from secondsign.contracts import Fingerprint, ReasonCode
from secondsign.decision import DecisionVerdict
from secondsign.gateway import ExecutionStatus
from secondsign.intent import IntentDigest

#: The prev_hash of the first receipt in a chain. A fixed, recognisable anchor.
GENESIS_HASH = "0" * 64

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class AuditReceipt(BaseModel):
    """One link in the audit chain. Frozen, closed, redacted."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    sequence: int = Field(ge=0)
    prev_hash: str = Field(pattern=_HASH_PATTERN)
    digest: IntentDigest
    verdict: DecisionVerdict
    reasons: tuple[ReasonCode, ...] = ()
    outcome_status: ExecutionStatus | None = None
    approval_id: str | None = None
    #: Which workload asked, as a keyed fingerprint — never the raw URI SAN the
    #: certificate carried (ADR 0004 §1). The trail has to be able to answer
    #: "who asked for this" without the trail itself becoming a directory of
    #: workload identities, and the fingerprint key is control plane, so a reader
    #: of the ledger alone cannot resolve one.
    #:
    #: Optional because a receipt can be recorded for an action that reached no
    #: authenticated caller — an operator-run reconciliation, a test. A missing
    #: value means "no principal", never "the principal was not recorded".
    principal_ref: Fingerprint | None = None
    receipt_hash: str = Field(pattern=_HASH_PATTERN)


def _content_hash(
    *,
    sequence: int,
    prev_hash: str,
    digest: IntentDigest,
    verdict: DecisionVerdict,
    reasons: tuple[ReasonCode, ...],
    outcome_status: ExecutionStatus | None,
    approval_id: str | None,
    principal_ref: str | None,
) -> str:
    material = {
        "sequence": sequence,
        "prev_hash": prev_hash,
        "digest": digest.value,
        "digest_version": digest.digest_version,
        "verdict": verdict.value,
        "reasons": [code.value for code in reasons],
        "outcome_status": outcome_status.value if outcome_status is not None else None,
        "approval_id": approval_id,
        "principal_ref": principal_ref,
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def hash_of(receipt: AuditReceipt) -> str:
    """Recompute a receipt's hash from its content, ignoring its stored hash."""
    return _content_hash(
        sequence=receipt.sequence,
        prev_hash=receipt.prev_hash,
        digest=receipt.digest,
        verdict=receipt.verdict,
        reasons=receipt.reasons,
        outcome_status=receipt.outcome_status,
        approval_id=receipt.approval_id,
        principal_ref=receipt.principal_ref,
    )


def verify_chain(receipts: tuple[AuditReceipt, ...]) -> bool:
    """True iff the receipts form an intact chain from genesis.

    A mid-chain removed, reordered, or edited receipt fails one of three checks:
    the sequence runs, the prev_hash links, and each stored hash matches a fresh
    recomputation of its content.

    One break this does *not* catch by itself is tail truncation — dropping the
    last receipts leaves a shorter but internally-valid chain. Detecting that
    requires an external commitment to the chain's head or length, held in the
    control plane; it is not a property of the chain alone.
    """
    previous = GENESIS_HASH
    for index, receipt in enumerate(receipts):
        if receipt.sequence != index:
            return False
        if receipt.prev_hash != previous:
            return False
        if hash_of(receipt) != receipt.receipt_hash:
            return False
        previous = receipt.receipt_hash
    return True
