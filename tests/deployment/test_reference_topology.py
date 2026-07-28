# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""No-bypass, demonstrated where hostile code actually runs.

Every other suite in this repository tests the engine from inside a process that
is cooperating with it. That is the right way to test a decision, and it is the
wrong way to test a boundary: an agent that has stopped cooperating is the only
agent worth defending against, and it does not import `secondsign-client`.

So these cases run **inside the agent container**, against the **standard
library**, and they attack the mock rail directly. The client is not involved.

What they are testing is the conjunction, of which the package split is one term:

    the agent process holds no rail credential
  ∧ the agent process has no network route to the rail
  ∧ its only route out is the gateway
  ∧ the agent cannot alter any of the above

`ModuleNotFoundError` in the agent environment proves the first term and nothing
else. `tests/architecture/` asserts that separately. These cases are the rest.

Two disciplines keep the suite from passing vacuously, and both are as important
as the attacks themselves. The gateway must be **reachable** from the same
container the attacks fail from, or "nothing was reachable" would pass as
"the rail was unreachable". And the mock rail must be interrogated at the
**destination**, because the agent's own view can only say "my attempt failed",
which is a different statement from "nothing arrived".
"""

from __future__ import annotations

import errno

import pytest

from tests.deployment.conftest import AGENT, GATEWAY, Stack

pytestmark = pytest.mark.deployment

#: Where the mock rail listens, on the rail network the agent is not joined to.
RAIL_HOST = "rail"
RAIL_PORT = 9000

#: Where the gateway listens, on the internal network the agent *is* joined to.
GATEWAY_HOST = "gateway"
GATEWAY_PORT = 8787

#: The variable a rail credential would arrive in.
CREDENTIAL_VARIABLE = "SECONDSIGN_RAIL_API_KEY"

#: Errnos that mean "there is no route", as opposed to "something said no".
#: EHOSTUNREACH and ENETUNREACH are unambiguous. ETIMEDOUT is included because a
#: silently dropping network boundary is the common shape in practice; a refusal
#: would be ECONNREFUSED, which is deliberately absent from this set.
NO_ROUTE = {errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ETIMEDOUT}


class TestTheSuiteIsNotVacuous:
    """Before believing any negative result, prove the environment works.

    Every case below this class asserts that something *fails*. A container with
    no network at all, a mistyped service name, or a stack that never came up
    would satisfy all of them. These two cases are what separate "the rail is
    unreachable" from "nothing is reachable".
    """

    def test_the_gateway_is_reachable_from_the_agent_container(self, stack: Stack) -> None:
        verdict = stack.probe(AGENT, GATEWAY_HOST, GATEWAY_PORT)

        assert verdict["connected"] is True, (
            "the agent cannot reach the gateway either, so this suite's negative "
            "results prove nothing about the rail"
        )

    def test_the_rail_is_reachable_from_the_gateway_container(self, stack: Stack) -> None:
        verdict = stack.probe(GATEWAY, RAIL_HOST, RAIL_PORT)

        assert verdict["connected"] is True, (
            "the gateway cannot reach the rail, so the rail being unreachable "
            "from the agent says nothing about network isolation"
        )


class TestTheAgentHasNoRouteToTheRail:
    """The second term: no network path, asserted by hostile code."""

    def test_a_raw_socket_to_the_rail_cannot_connect(self, stack: Stack) -> None:
        verdict = stack.probe(AGENT, RAIL_HOST, RAIL_PORT)

        assert verdict["connected"] is False

    def test_the_failure_is_absence_of_a_route_not_a_refusal(self, stack: Stack) -> None:
        """A refusal and an absence are the same exit code and different claims.

        `ECONNREFUSED` would mean the agent reached the rail's network and
        something declined the connection — a control that is running, and can
        therefore be misconfigured off. The claim this deployment makes is
        stronger and duller: there is no route at all.
        """
        verdict = stack.probe(AGENT, RAIL_HOST, RAIL_PORT)

        assert verdict["errno"] in NO_ROUTE, (
            f"expected no route, got errno {verdict['errno']} "
            f"({verdict['errno_name']}) — a refusal is a running control, not an absent path"
        )

    def test_an_http_request_to_the_rail_fails_the_same_way(self, stack: Stack) -> None:
        """The standard library offers more than one way out; both must close.

        A raw socket is the obvious probe. `urllib` is the one an agent would
        actually reach for, and it resolves names and follows redirects — enough
        extra machinery to be worth attacking separately rather than assuming it
        shares the socket's fate.
        """
        script = (
            "import sys, urllib.error, urllib.request\n"
            "try:\n"
            f"    urllib.request.urlopen('http://{RAIL_HOST}:{RAIL_PORT}/', timeout=5)\n"
            "except OSError:\n"
            "    sys.exit(7)\n"
            "sys.exit(0)\n"
        )

        result = stack.exec(AGENT, "python", "-c", script)

        assert result.returncode == 7, (
            "an HTTP request from the agent to the rail did not fail; "
            f"exit={result.returncode} stderr={result.stderr!r}"
        )

    def test_the_rail_records_nothing_from_these_attempts(self, stack: Stack) -> None:
        """Destination-side accounting. The agent's view is not evidence."""
        before = len(stack.rail_requests())

        stack.probe(AGENT, RAIL_HOST, RAIL_PORT)

        assert len(stack.rail_requests()) == before, (
            "the rail recorded a request while the agent was attacking it directly"
        )


class TestCredentialLocality:
    """The first term, at the deployment level rather than the package level."""

    def test_the_gateway_holds_the_rail_credential(self, stack: Stack) -> None:
        assert stack.env_of(GATEWAY, CREDENTIAL_VARIABLE) is not None

    def test_the_agent_does_not(self, stack: Stack) -> None:
        assert stack.env_of(AGENT, CREDENTIAL_VARIABLE) is None

    def test_the_agent_cannot_read_it_out_of_the_gateway(self, stack: Stack) -> None:
        """A credential the agent can fetch over the wire is not isolated.

        The outcome model is closed and carries no credential field, so this
        should be impossible by construction. Asserting it anyway is cheap, and
        the construction is exactly the kind of thing a later slice could widen
        without noticing.
        """
        result = stack.exec(
            AGENT,
            "python",
            "-c",
            "import urllib.request\n"
            f"body = urllib.request.urlopen('http://{GATEWAY_HOST}:{GATEWAY_PORT}/healthz',"
            " timeout=5).read().decode()\n"
            "print(body)\n",
        )

        assert CREDENTIAL_VARIABLE not in result.stdout
        assert "sk_" not in result.stdout


class TestWithTheGatewayStopped:
    """The falsification test from README, run for real.

    *Turn SecondSign off. If the agent can still move money, you have not
    installed a boundary.*
    """

    @pytest.fixture(autouse=True)
    def _gateway_down(self, stack: Stack):
        stack.stop(GATEWAY)
        yield
        stack.start(GATEWAY)

    def test_the_gateway_is_gone(self, stack: Stack) -> None:
        verdict = stack.probe(AGENT, GATEWAY_HOST, GATEWAY_PORT)

        assert verdict["connected"] is False

    def test_the_rail_is_still_unreachable(self, stack: Stack) -> None:
        """Execution becomes impossible, not merely unauthorized.

        This is the case that distinguishes a boundary from a library. With the
        authorizing component removed, a library leaves the caller free to
        proceed; a boundary leaves it with nowhere to go.
        """
        verdict = stack.probe(AGENT, RAIL_HOST, RAIL_PORT)

        assert verdict["connected"] is False
        assert verdict["errno"] in NO_ROUTE

    def test_the_rail_records_zero_requests_for_the_whole_case(self, stack: Stack) -> None:
        before = len(stack.rail_requests())

        stack.probe(AGENT, RAIL_HOST, RAIL_PORT)
        stack.probe(AGENT, GATEWAY_HOST, GATEWAY_PORT)

        assert len(stack.rail_requests()) == before


class TestDestinationSideAccounting:
    """What arrived at the rail must be exactly what the gateway sent.

    Counting failures at the source cannot detect a bypass that worked. This is
    the only case that can.
    """

    def test_the_rail_saw_only_requests_the_gateway_dispatched(self, stack: Stack) -> None:
        requests = stack.rail_requests()

        assert all(item.get("via") == "gateway" for item in requests), (
            "the rail recorded a request that did not arrive through the gateway"
        )
