# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""IntentDigest — the value decision, approval and execution all bind to.

The digest is a total, deterministic, versioned fingerprint over every material
field of a :class:`TransactionIntent`. Three later guarantees rest on it:

- **decided value equals executed value** (B1) — the gateway re-verifies the
  digest immediately before dispatch, so a value swapped in between is rejected;
- **approvals are one-shot and digest-bound** (B2) — an approval names a single
  digest and nothing else;
- **audit is reconcilable** — two operators recording the same action record the
  same digest.

Determinism is achieved by hashing a canonical JSON form: keys sorted, no
insignificant whitespace, enums and timestamps in their JSON representation. The
algorithm is versioned, and the version is part of what is hashed, so a change
to the canonicalisation is a change to every digest — a breaking change by
construction, never a silent one.
"""

import hashlib
import json

from pydantic import BaseModel, ConfigDict, Field

from secondsign.intent.transaction import TransactionIntent

#: Version of the digest algorithm. Bumping it changes every digest, which is
#: why a change here is a breaking change and must be treated as one.
DIGEST_VERSION = 1


class IntentDigest(BaseModel):
    """A versioned SHA-256 over an intent's material fields."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    digest_version: int = DIGEST_VERSION
    #: Lowercase hex SHA-256. A fixed shape, so a malformed digest cannot bind.
    value: str = Field(pattern=r"^[0-9a-f]{64}$")


def _canonical_bytes(intent: TransactionIntent, version: int) -> bytes:
    material = {"digest_version": version, "intent": intent.model_dump(mode="json")}
    return json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_digest(intent: TransactionIntent, *, version: int = DIGEST_VERSION) -> IntentDigest:
    """The digest of ``intent`` under algorithm ``version``.

    Total: defined for every valid intent. Deterministic: equal intents yield
    byte-identical digests. Versioned: the version is hashed in, so it cannot be
    changed without changing the result.
    """
    checksum = hashlib.sha256(_canonical_bytes(intent, version)).hexdigest()
    return IntentDigest(digest_version=version, value=checksum)
