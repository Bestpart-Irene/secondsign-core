# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The deployment gate can fail. Proven by making it fail.

`tests/deployment/test_reference_topology.py` asserts a *negative*: hostile code
in the agent container cannot reach the rail. Negatives pass for boring reasons.
Nothing was listening. A container never started. A name did not resolve. The
harness stopped probing and nobody noticed. Every one of those produces the same
green as a correctly isolated deployment.

That suite already guards the first of them with `TestTheSuiteIsNotVacuous` —
but that guard is an assertion *inside the suite being questioned*. It can say
the addresses were reachable; it cannot say the suite would have noticed a
reachable **rail**, because in a correct deployment there is never one to
notice.

So this module builds one. `deploy/reference/compose.joined.yaml` overlays a
single line — `railnet` on the agent — onto the shipped topology, changing
nothing else: same images, same mounts, same credential placement, same
certificates. Then it re-runs the real isolation cases, unmodified, imported
from the suite they live in, and **requires them to fail**.

The pattern is the conformance kits' own: a check that certifies everything
certifies nothing, so the thing that must be caught is written down and the
catcher is held to it. It is the same argument the Solidity job's mutation step
makes about `forge test`, applied to a gate whose subject is a network.

Run as its own CI step, under its own marker, because it stands up a second
stack and because a mutation is not a gate — it is the evidence that the gate is
one.
"""

from __future__ import annotations

import pytest

from tests.deployment import test_reference_topology as reference_suite
from tests.deployment.conftest import AGENT, RAIL, Stack

#: Imported as a module, deliberately. Pulling `TestTheAgentHasNoRouteToTheRail`
#: into this namespace would make pytest collect it here as well, and it would
#: then run against the *reference* stack under this module's marker — a second
#: deployment stood up to assert something the gate already asserts.
RAIL_HOST = reference_suite.RAIL_HOST
RAIL_PORT = reference_suite.RAIL_PORT

pytestmark = pytest.mark.deployment_mutation

#: The cases the join must break, named by method rather than described. Each is
#: the real code from the real suite: no copy, no re-statement, nothing that can
#: drift from what the gate actually asserts.
FALSIFIED_BY_A_ROUTE = (
    "test_a_raw_socket_to_the_rail_cannot_connect",
    "test_the_failure_is_absence_of_a_route_not_a_refusal",
    "test_an_http_request_to_the_rail_fails_the_same_way",
)


class TestTheGateCanFail:
    def test_the_direct_to_rail_case_succeeds_when_the_networks_are_joined(
        self, joined_stack: Stack
    ) -> None:
        """The mutation took effect, stated before anything is concluded from it.

        If this were false — if the join silently did nothing — every assertion
        below would still hold, for the same boring reason the whole module
        exists to rule out.
        """
        verdict = joined_stack.probe(AGENT, RAIL_HOST, RAIL_PORT)

        assert verdict["connected"] is True, (
            "the agent still cannot reach the rail with the networks joined, so "
            "this mutation proves nothing about the gate: "
            f"errno {verdict['errno']} ({verdict['errno_name']})"
        )

    @pytest.mark.parametrize("case", FALSIFIED_BY_A_ROUTE)
    def test_the_isolation_case_fails_against_the_joined_topology(
        self, case: str, joined_stack: Stack
    ) -> None:
        """Run the gate's own assertion against a deployment that violates it.

        An `AssertionError` here is the passing result. Anything else means the
        case would report green on a deployment where the agent reaches the rail
        directly — which is the entire property `deploy/reference/` claims.
        """
        suite = reference_suite.TestTheAgentHasNoRouteToTheRail()

        with pytest.raises(AssertionError):
            getattr(suite, case)(joined_stack)

    def test_the_rail_records_the_agent_s_own_request(self, joined_stack: Stack) -> None:
        """Destination-side evidence of the bypass, read at the destination.

        The cases above are all source-side: the agent's attempt succeeded. This
        one asks the rail, which is the only party whose answer distinguishes
        "my attempt did not fail" from "something arrived". A gate that could
        not see this line in the ledger would be blind to exactly the bypass
        that worked.
        """
        before = len(joined_stack.rail_requests())
        script = (
            "import urllib.request\n"
            f"urllib.request.urlopen('http://{RAIL_HOST}:{RAIL_PORT}/', timeout=5).read()\n"
        )

        result = joined_stack.exec(AGENT, "python", "-c", script)

        assert result.returncode == 0, (
            f"the agent's HTTP request to the rail failed with the networks "
            f"joined: {result.stderr!r}"
        )
        assert len(joined_stack.rail_requests()) == before + 1, (
            "the rail recorded nothing from a request that demonstrably reached "
            "it — the ledger is not seeing traffic, and destination-side "
            "accounting is the one check a successful bypass cannot hide from"
        )

    def test_a_bare_connect_is_not_enough_to_reach_the_ledger(self, joined_stack: Stack) -> None:
        """What this mutation does *not* falsify, pinned rather than left implicit.

        `test_the_rail_records_nothing_from_these_attempts` stays green even
        here, and that is not a bug in it: it probes with a raw socket that
        sends no bytes, and an HTTP server records requests, not connections.
        The case is real — it just answers a narrower question than its name
        suggests, and the answer to the wider one comes from the ledger check
        above.

        Asserted rather than written in a comment, because a comment about a
        gate's blind spot goes stale the moment somebody widens the probe.
        """
        before = len(joined_stack.rail_requests())

        verdict = joined_stack.probe(AGENT, RAIL_HOST, RAIL_PORT)

        assert verdict["connected"] is True
        assert len(joined_stack.rail_requests()) == before, (
            "a bare TCP connect now reaches the ledger; the case above is no "
            "longer describing this deployment and should be re-read"
        )

    def test_the_mutation_changes_the_route_and_nothing_else(self, joined_stack: Stack) -> None:
        """The join must not accidentally be a different deployment.

        A mutation that also moved the rail credential, or dropped a mount,
        would still make the isolation cases fail — and would prove nothing,
        because the failure could be the other change. The two facts the
        credential and custody cases rest on are asserted here to be unchanged.
        """
        assert joined_stack.env_of(AGENT, "SECONDSIGN_RAIL_API_KEY") is None, (
            "the joined topology gave the agent the rail credential; it is "
            "supposed to differ from the reference deployment by a route alone"
        )
        assert joined_stack.env_of(RAIL, "RAIL_LEDGER"), "the rail lost its ledger"
