# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The two digests: one for what was decided, one for what a human approved.

:class:`IntentDigest` is a total, deterministic, versioned fingerprint over
every material field of a :class:`TransactionIntent`. Three guarantees rest
on it:

- **decided value equals executed value** (B1) — the gateway re-verifies the
  digest immediately before dispatch, so a value swapped in between is rejected;
- **replays are recognisable** (B2) — an execution names a single digest;
- **audit is reconcilable** — two operators recording the same action record the
  same digest.

:class:`ProposalDigest` is the same hash over the same intent with the validity
window removed, and nothing else removed. It exists because the two rules above
and the review flow cannot all be true at once: the window is material, a human
takes longer to answer than the window lasts, and re-deciding for a fresh window
produces a digest the human never saw. An approval therefore binds to the
proposal digest and execution stays bound to the intent digest — ADR 0005, which
also records why the three obvious alternatives are worse.

Determinism is achieved by hashing a canonical JSON form: keys sorted, no
insignificant whitespace, enums and timestamps in their JSON representation.
Each algorithm is versioned, and the version is part of what is hashed, so a
change to the canonicalisation is a change to every digest — a breaking change
by construction, never a silent one. The two hashes cover structurally different
material, so no intent can produce the same value under both.
"""

import hashlib
import json
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from secondsign.intent.transaction import TransactionIntent

#: Version of the digest algorithm. Bumping it changes every digest, which is
#: why a change here is a breaking change and must be treated as one.
DIGEST_VERSION = 1

#: Version of the proposal-digest algorithm. Separate from `DIGEST_VERSION`
#: because the two answer different questions and will not always change
#: together.
PROPOSAL_DIGEST_VERSION = 1

#: The fields the proposal digest excludes: the validity window, and nothing
#: else. Stated once, here, and asserted against `DecisionDimensions` in
#: `tests/intent/test_proposal_digest.py` — a rename must fail loudly rather
#: than quietly widen what a human is deemed to have approved.
WINDOW_FIELDS: Final[tuple[str, ...]] = ("not_before", "not_after")


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


class ProposalDigest(BaseModel):
    """A versioned SHA-256 over an intent's material fields except its window.

    A separate type from :class:`IntentDigest` rather than the same shape used
    in two places. They are both 64 hex characters and they mean different
    things, so a call site that confuses them is a call site that authorises
    something nobody approved — and the type system is the cheapest place to
    make that impossible.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    digest_version: int = PROPOSAL_DIGEST_VERSION
    value: str = Field(pattern=r"^[0-9a-f]{64}$")


def _proposal_bytes(intent: TransactionIntent, version: int) -> bytes:
    proposal = intent.model_dump(mode="json")
    dimensions = proposal["dimensions"]
    for field in WINDOW_FIELDS:
        # `del`, not `pop(field, None)`: a window field that is no longer there
        # means this function is no longer excluding what it says it excludes,
        # and the only safe response is to stop rather than to hash on.
        del dimensions[field]
    material = {"digest_version": version, "domain": "proposal", "proposal": proposal}
    return json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_proposal_digest(
    intent: TransactionIntent, *, version: int = PROPOSAL_DIGEST_VERSION
) -> ProposalDigest:
    """What a human approves: ``intent`` without its validity window.

    The material carries a domain label as well as a different shape, so this
    can never collide with :func:`compute_digest` over the same intent even if a
    future canonicalisation makes the two structures converge.
    """
    checksum = hashlib.sha256(_proposal_bytes(intent, version)).hexdigest()
    return ProposalDigest(digest_version=version, value=checksum)
