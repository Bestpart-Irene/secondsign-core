# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The approver-boundary gate can fail. Proven by making it fail (CORE-S023).

`test_approver_isolation.py` asserts a negative — the agent has no route to
the second door — and negatives pass for boring reasons. So this module builds
the deployment where the claim is false: `compose.approver-joined.yaml`
overlays one line, `approvernet` on the agent, onto the shipped topology and
changes nothing else. Then it re-runs the real isolation cases, imported from
the suite they live in, and **requires them to fail**.

The same argument `test_gate_liveness.py` makes about the rail boundary,
applied to the door humans answer reviews through.
"""

from __future__ import annotations

import pytest

from tests.deployment import test_approver_isolation as approver_suite
from tests.deployment.conftest import AGENT, APPROVER_ADDRESS, APPROVER_PORT, Stack

pytestmark = pytest.mark.deployment_mutation

#: The cases the join must break, named by method rather than described — the
#: real code from the real suite, so nothing here can drift from what the gate
#: asserts.
FALSIFIED_BY_A_ROUTE = ("test_the_approver_address_is_unroutable_from_the_agent",)


class TestTheApproverGateCanFail:
    def test_the_agent_can_reach_the_second_door_when_joined(
        self, approver_joined_stack: Stack
    ) -> None:
        """First, the mutation is verified to have taken effect — concluded
        from a route that now exists, not from the overlay file's presence."""
        verdict = approver_joined_stack.probe(AGENT, APPROVER_ADDRESS, APPROVER_PORT)
        assert verdict["connected"] is True, (
            f"the joined topology did not grant the agent a route to the "
            f"approver listener: {verdict} — the mutation never took effect, "
            "and nothing below would falsify anything"
        )

    @pytest.mark.parametrize("case", FALSIFIED_BY_A_ROUTE)
    def test_the_isolation_case_fails_against_the_joined_topology(
        self, approver_joined_stack: Stack, case: str
    ) -> None:
        suite = approver_suite.TestTheAgentHasNoRouteToTheApproverChannel()
        with pytest.raises(AssertionError):
            getattr(suite, case)(approver_joined_stack)

    def test_what_the_join_does_not_falsify_stays_green(self, approver_joined_stack: Stack) -> None:
        """Pinned on purpose: joining the agent to approvernet grants a route,
        not a credential. The handshake still refuses an agent that connects,
        because the approver CA never issued it anything — so the bind-side
        case keeps its meaning even against the mutated topology."""
        suite = approver_suite.TestTheAgentHasNoRouteToTheApproverChannel()
        suite.test_the_approver_holds_no_rail_credential_and_no_rail_route(approver_joined_stack)
