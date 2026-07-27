# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The surface a managed agent may import, and nothing further (INV-12).

This module is defined by what it cannot reach. An agent-side caller imports
this and gets two things: a way to *ask* for an action, and a way to read the
answer. It gets no limits, no approver roster, no idempotency store, no audit
ledger, no fingerprint key, and no rail credential — not because it is asked not
to use them, but because there is no import path from here to any of them.

``tests/architecture/test_control_plane_isolation.py`` walks this module's whole
transitive import closure and fails if a single control-plane module appears in
it. That test, not this docstring, is the guarantee.

**Why the request carries fingerprints and not values.** An agent proposing a
payment names a counterparty and a source account by opaque handle, because the
alternative — the agent holding the raw account number — puts the identifier
inside the process the threat model treats as untrusted. The agent cannot mint a
handle either: fingerprinting needs the key, and the key is control plane.

**Why there is no ``approve`` here.** Nothing on this surface can grant, extend
or waive anything. The verbs an agent gets are *request* and *read*. If a future
change adds a verb here that changes state on the control plane, the architecture
suite fails, which is the intended outcome rather than a nuisance.
"""

from secondsign.agent.surface import (
    AuthorizationOutcome,
    AuthorizationRequest,
    SecondSignClient,
)

__all__ = [
    "AuthorizationOutcome",
    "AuthorizationRequest",
    "SecondSignClient",
]
