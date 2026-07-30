# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The wire contract's core-side declaration: the dialect, and what it refuses.

`secondsign.agent.surface` says what crosses the boundary; this module says
which dialect it crosses in, and which field names are a smuggled identity
rather than part of the proposal. Both are properties of the boundary itself,
so they live beside the models on the agent surface rather than inside the
gateway that happens to serve them or the kit that happens to certify against
them. One declaration on this side, imported by both.

It is deliberately *not* one declaration across the whole system. The agent-side
distribution states the same version again in `secondsign_client.wire`, because
neither package may import the other (ADR 0003 §1) — and two declarations that
can drift are held equal in `tests/client/test_wire_contract.py`, the one place
both are visible. That duplication buys package independence and is paid for by
a test. Duplicating it a third time *inside* core would buy nothing.

This module imports nothing from core, so it stays reachable from the managed
agent without widening what the agent can reach (INV-12).
"""

from __future__ import annotations

from typing import Final

#: The dialect this repository speaks on the agent/gateway boundary. Adding a
#: field, a status, or an enum member is a version change.
#:
#: Independent of `secondsign.contracts.CONTRACT_VERSION` on purpose: the plugin
#: contract and the wire contract change for different reasons at different
#: times, and coupling them would force a release of one surface to announce a
#: change in the other.
WIRE_VERSION: Final[int] = 1

#: Dialects a peer may announce. A peer announcing anything else is refused
#: rather than best-effort parsed (ADR 0003 §3, mirroring ADR 0002): a peer
#: speaking a different dialect may mean something different by every word in
#: it, including `refused`.
#:
#: A set rather than the constant alone, because accepting an old dialect
#: alongside a new one during a rollout is a decision this shape can express
#: without the parser learning to guess.
SUPPORTED_WIRE_VERSIONS: Final[frozenset[int]] = frozenset({WIRE_VERSION})

#: Field names whose presence in a request body is a smuggled identity. Refused,
#: never ignored (ADR 0004 §1): a field that is accepted and discarded is one a
#: later change can quietly start honouring. Identity comes from the transport's
#: authenticated peer and from nowhere else.
PRINCIPAL_FIELDS: Final[tuple[str, ...]] = ("client_principal", "principal")
