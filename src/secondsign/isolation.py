# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Which side of the isolation boundary each module is on (INV-12).

The control plane holds the five assets that decide what the managed agent is
allowed to do: limits, the approver roster, the idempotency store, the audit
ledger, and the fingerprint keys. An agent that can reach any of them can raise
its own limit, approve its own action, replay a spent approval, edit its own
history, or forge a reference — so *unreachable* has to be a structural fact
about imports, not a rule a reviewer applies.

Three deliberate choices about this file.

**It reads nothing.** No environment, no file, no configuration object, no
filesystem access — this module imports from ``dataclasses``, ``enum`` and
``typing`` and defines constants. An isolation judgement that consults an input is
a judgement someone can answer differently, which is the entire failure mode
INV-12 exists to prevent. ``tests/architecture/test_control_plane_isolation.py``
enforces that by parsing this file's own imports, not by trusting this paragraph —
and it caught an earlier draft of this file reading source to detect concerns,
which is why the detection now lives in the suite instead of here.

**A concern is declared here and detected there.** Each :class:`Concern` names the
symbols that constitute it, and the architecture suite asks the question the other
way round: which modules *define* those symbols, and are all of them classified as
control plane? That inversion is what makes a future slice adding an undeclared
limits store fail the suite instead of silently widening reach. The parsing that
answers it belongs to the test, because a judgement that reads files is not a
judgement that reads nothing.

**Everything is classified, including the parts that are neither.** Contracts,
intent models and rail payloads are ``SHARED``: safe for both sides, because they
are frozen boundary objects carrying fingerprints rather than raw values. The
distinction between "shared" and "unclassified" matters — an unclassified module
is a gap, and the suite fails on it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final


class Side(StrEnum):
    """Which side of the boundary a module sits on."""

    #: Holds or mediates a control-plane asset. Never reachable from the agent.
    control_plane = "control_plane"
    #: The surface the managed agent may import, and nothing further.
    agent_surface = "agent_surface"
    #: Frozen boundary objects, safe for both sides.
    shared = "shared"


@dataclass(frozen=True)
class Concern:
    """One of INV-12's five assets, and the symbols that constitute it.

    ``symbols`` are the top-level names that mean a module is holding this asset.
    A coarse signal on purpose: a module defining something called
    ``IdempotencyStore`` holds that concern whatever else it does, and for this
    question over-including is the safe direction.

    Deliberately inert. It declares what to look for and performs no lookup —
    finding the holders means reading source, and this module must be able to
    claim it reads nothing.
    """

    description: str
    symbols: tuple[str, ...]

    def is_held_by(self, defined_names: frozenset[str]) -> bool:
        """True if a module defining ``defined_names`` holds this concern.

        The caller does the reading and passes in the result, which keeps the
        judgement here a pure function of its arguments.
        """
        return any(symbol in defined_names for symbol in self.symbols)


#: INV-12's five assets. Keys are stable identifiers; the architecture suite
#: parametrises over them, so adding one here adds a test.
CONTROL_PLANE_CONCERNS: Final[dict[str, Concern]] = {
    "limits": Concern(
        description="What the agent is allowed to move, and the windows it is measured over.",
        symbols=("AmountLimit", "AmountWindowPolicy", "WindowAggregate", "PolicyContext"),
    ),
    "approver_roster": Concern(
        description="Who may approve, and the maker-checker separation between them.",
        symbols=("CheckerIdentity", "MakerIdentity", "MakerChecker", "ApprovalProvider"),
    ),
    "idempotency_store": Concern(
        description="Which authorizations have been spent. Reachable means replayable.",
        symbols=("IdempotencyStore", "InMemoryIdempotencyStore", "ExecutionGateway"),
    ),
    "audit_ledger": Concern(
        description="The hash-chained record. Reachable means the history is editable.",
        symbols=("AuditLog", "AuditSink", "InMemoryAuditSink", "AuditReceipt"),
    ),
    "relaxation_authority": Concern(
        description="What may loosen a setting below its strictest default, and on whose authority.",
        symbols=("Relaxation", "RelaxationDecision", "resolve", "strictest"),
    ),
    "fingerprint_key": Concern(
        description=(
            "What makes a reference opaque. Reachable means every reference in the "
            "deployment is mintable, and an unkeyed hash of an account number is a "
            "lookup table away from being the account number."
        ),
        symbols=("FingerprintKey",),
    ),
}

#: The one module a managed agent imports. It carries a request and an outcome,
#: and reaches nothing that decides either.
AGENT_SURFACE: Final[str] = "secondsign.agent"

#: Module prefixes that hold control-plane assets. Prefix rather than exact name
#: so a package and its submodules are classified together — a new file under
#: `controlplane/` is control plane the moment it exists, without an edit here.
#:
#: Two entries are here because of what they *reach*, not what they hold, and
#: the reasoning belongs beside the classification (CORE-S024, issue #58):
#:
#: - `conformance` certifies extensions on both sides of the boundary, so its
#:   kits import the approval and audit packages by construction. A kit runs in
#:   a test harness on a developer's machine, never inside a managed agent —
#:   classifying it control plane means an agent that imports it fails the
#:   gate, which is the correct outcome.
#: - `decision` reads the limits (`PolicyContext`) to decide. The deciding half
#:   of the control plane is the control plane; what is safe for both sides is
#:   the contract it serves, not the engine that serves it.
_CONTROL_PLANE_PREFIXES: Final[tuple[str, ...]] = (
    "secondsign.approval",
    "secondsign.audit",
    "secondsign.conformance",
    "secondsign.controlplane",
    "secondsign.decision",
    "secondsign.gateway",
    "secondsign.policy",
    "secondsign.rails",
)

#: Prefixes that are safe for both sides: frozen boundary models, the plugin
#: contract, and the digest. Since CORE-S024 this list is a *checked claim*,
#: not a comment — every module under these prefixes must have an import
#: closure free of control-plane modules, enforced by
#: `tests/architecture/test_shared_side_isolation.py` and by the shared-side
#: import contract in `pyproject.toml`. (`secondsign.redteam` was listed here
#: from CORE-S016 to CORE-S024, but no such module exists — the red-team
#: matrix lives under `tests/redteam/` — and a phantom entry in a checked
#: claim is unfalsifiable, so it is gone.)
_SHARED_PREFIXES: Final[tuple[str, ...]] = (
    "secondsign.adapters",
    "secondsign.contracts",
    "secondsign.intent",
    "secondsign.isolation",
    # The experimental, unfrozen on-chain vocabulary (ONCHAIN-S002). Frozen
    # boundary models carrying no control-plane asset, like `contracts` — so it
    # is shared, and its import closure is held free of the control plane by the
    # shared-side contract in `pyproject.toml`. That no v1 module reaches it yet
    # is a separate, stronger fact asserted in `tests/onchain/`.
    "secondsign.onchain",
)


def _matches(module: str, prefixes: tuple[str, ...]) -> bool:
    return any(module == p or module.startswith(f"{p}.") for p in prefixes)


def classify(module: str) -> Side | None:
    """Which side ``module`` is on, or ``None`` if it is not classified.

    ``None`` is a failure, not a default. The architecture suite asserts every
    module in the package classifies, because an unclassified module is neither
    guarded as control plane nor proven safe to expose.
    """
    if module == AGENT_SURFACE or module.startswith(f"{AGENT_SURFACE}."):
        return Side.agent_surface
    if _matches(module, _CONTROL_PLANE_PREFIXES):
        return Side.control_plane
    if module == "secondsign" or _matches(module, _SHARED_PREFIXES):
        return Side.shared
    return None


def is_control_plane(module: str) -> bool:
    """True only for modules classified as control plane.

    Note the direction: an unclassified module is *not* reported as control plane,
    so it cannot be quietly hidden behind this function. It fails
    ``test_inv12_every_module_is_classified`` instead, which is the error a
    contributor can act on.
    """
    return classify(module) is Side.control_plane


def control_plane_modules() -> tuple[str, ...]:
    """The control-plane prefixes, for tests and for documentation."""
    return _CONTROL_PLANE_PREFIXES
