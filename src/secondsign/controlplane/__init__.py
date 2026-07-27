# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Control-plane components: reachable from the gateway, never from the agent.

Everything under this package is classified `control_plane` by
:mod:`secondsign.isolation`, by prefix rather than by name — a module added here
is on the protected side of the boundary the moment the file exists, with no
second edit needed to make that true.

Nothing here is exported from the top-level package. An agent-side caller imports
:mod:`secondsign.agent` and reaches none of this.
"""

from secondsign.controlplane.relaxation import (
    Relaxation,
    RelaxationDecision,
    Resolution,
    Setting,
    is_looser,
    resolve,
    strictest,
)

__all__ = [
    "Relaxation",
    "RelaxationDecision",
    "Resolution",
    "Setting",
    "is_looser",
    "resolve",
    "strictest",
]
