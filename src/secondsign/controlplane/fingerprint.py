# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The fingerprint key — the one thing that makes an opaque reference opaque.

Every reference that crosses a boundary in this system is a keyed fingerprint:
``fp:`` followed by 64 hex characters, and nothing else is representable in a
reference field. That shape is worth very little without this module. An
*unkeyed* hash of an account number is a lookup table away from being the
account number — the space of card numbers is small enough to enumerate — so the
opacity comes from the key, and the key is control plane.

INV-12 names it among the five assets a managed agent must not reach: an agent
that holds this key can mint a reference for any value it likes, and every
downstream check that treats a reference as opaque is then reasoning about a
value the agent chose.

Three deliberate properties:

**The key never renders.** ``repr`` and ``str`` are overridden, and the material
is not a public attribute. A key that appears in a traceback, a log line, or a
pytest assertion diff has already left the control plane, and the places it would
leak from are exactly the places nobody is looking.

**Fingerprinting is one-way and domain-separated.** HMAC-SHA256, with the domain
mixed in, so a principal and an account that happen to share a string do not
share a fingerprint. Two deployments with different keys produce different
fingerprints for the same value, which is intended: a reference is meaningful
inside one deployment's audit trail and meaningless outside it.

**There is no reverse.** This module offers no lookup, no mapping, and no
registry. Resolving a fingerprint back to a value is not a capability the
codebase has, so it is not a capability an attacker can reach.
"""

from __future__ import annotations

import hmac
import secrets
from hashlib import sha256
from typing import Final

#: Length of a generated key. 32 bytes is HMAC-SHA256's block-independent
#: security level; more buys nothing, less is a real reduction.
KEY_BYTES: Final[int] = 32

#: Domain separators. A principal and a counterparty that happen to be the same
#: string must not fingerprint alike — otherwise a workload identity could be
#: confirmed by comparing it against a reference the agent already holds.
PRINCIPAL_DOMAIN: Final[str] = "principal"
DECISION_DOMAIN: Final[str] = "decision"
#: An open review's handle. Keyed, so an agent cannot compute the id of its own
#: pending approval and cannot enumerate anyone else's.
APPROVAL_DOMAIN: Final[str] = "approval"
#: The maker of a review. The workload that proposed an action is its maker, and
#: it appears as a fingerprint for the same reason every other identity does —
#: an approval record is not a place to write down who an agent is.
MAKER_DOMAIN: Final[str] = "maker"


class FingerprintKey:
    """Holds the keying material for a deployment's opaque references."""

    __slots__ = ("_material",)

    def __init__(self, material: bytes) -> None:
        if len(material) < KEY_BYTES:
            raise ValueError(
                f"a fingerprint key must be at least {KEY_BYTES} bytes; a short "
                "key makes every reference in the deployment guessable"
            )
        self._material = material

    @classmethod
    def generate(cls) -> FingerprintKey:
        """A fresh key from the system CSPRNG."""
        return cls(secrets.token_bytes(KEY_BYTES))

    def fingerprint(self, domain: str, value: str) -> str:
        """The keyed, domain-separated fingerprint of ``value``.

        Returns the ``fp:``-prefixed form the boundary models accept, so the
        result is usable wherever a reference is, and a raw value is not.
        """
        material = f"{domain}\x00{value}".encode()
        return "fp:" + hmac.new(self._material, material, sha256).hexdigest()

    def __repr__(self) -> str:
        """Deliberately uninformative. See the module docstring."""
        return "FingerprintKey(<redacted>)"

    __str__ = __repr__
