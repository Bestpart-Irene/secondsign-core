# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The second door, demonstrated where hostile code actually runs (CORE-S023).

B6 says an agent cannot reach the approval channel. In this deployment that is
a routing fact — the approver listener binds to the gateway's address on
`approvernet`, a network the agent has no interface on — and these cases
assert it the way the rail boundary is asserted: from inside the agent
container, with the standard library, distinguishing "no route" from
"something said no".

The other half is the flow the channel exists for. A proposal inside the
review band parks; the approver container — the only holder of a credential
under the approver CA — lists it, answers it, and the agent's re-send of its
own handle reads `completed`, with the rail's ledger longer by exactly one.
The human's door works, and the agent's does not open onto it.
"""

from __future__ import annotations

import json

import pytest

from tests.deployment.conftest import AGENT, APPROVER, APPROVER_PORT, Stack
from tests.deployment.test_reference_topology import (
    _AUTHORIZE,
    GATEWAY_HOST,
    GATEWAY_PORT,
    NO_ROUTE,
)

pytestmark = pytest.mark.deployment

#: Inside the reference review band: above 200_00, below the 500_00 cap.
REVIEW_AMOUNT = 300_00


def _authorize(stack: Stack, *, amount: int, ref: str) -> dict[str, object]:
    script = _AUTHORIZE.format(host=GATEWAY_HOST, port=GATEWAY_PORT, amount=amount, ref=ref)
    result = stack.exec(AGENT, "python", "-c", script)
    if not result.stdout.strip():
        pytest.fail(
            f"the client produced no outcome in the agent container.\n"
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
    return dict(json.loads(result.stdout.splitlines()[-1]))


def _console(stack: Stack, *argv: str) -> dict[str, object]:
    """Run the approver's console: `<verb> <host> <port> [answer args...]`."""
    result = stack.exec(
        APPROVER,
        "python",
        "/approver/console.py",
        argv[0],
        stack.approver_address,
        str(APPROVER_PORT),
        *argv[1:],
    )
    if not result.stdout.strip():
        pytest.fail(
            f"the approver console produced no output.\n"
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
    return dict(json.loads(result.stdout.splitlines()[-1]))


class TestTheSuiteIsNotVacuous:
    def test_the_approver_can_reach_the_second_door(self, stack: Stack) -> None:
        """Before believing the agent cannot connect, show that something can."""
        verdict = stack.probe(APPROVER, stack.approver_address, APPROVER_PORT)
        assert verdict["connected"] is True, (
            f"the approver container cannot reach the approver listener: {verdict} — "
            "nothing below may be concluded from the agent failing to"
        )


class TestTheAgentHasNoRouteToTheApproverChannel:
    def test_the_approver_address_is_unroutable_from_the_agent(self, stack: Stack) -> None:
        """The claim itself: no interface on approvernet means no route to the
        address the second door lives on."""
        verdict = stack.probe(AGENT, stack.approver_address, APPROVER_PORT)
        assert verdict["connected"] is False, (
            "the agent connected to the approver listener — the second door "
            f"is on the agent's network: {verdict}"
        )
        assert verdict["errno_name"] in NO_ROUTE, (
            f"expected the absence of a route, got {verdict} — ECONNREFUSED here "
            "would mean the door exists on the agent's network and something "
            "declined, which is a control that can be switched off"
        )

    def test_the_second_door_is_not_bound_on_the_agents_network(self, stack: Stack) -> None:
        """A different statement from the one above: the gateway *is* on
        agentnet, and the approver port must simply not exist there. A refusal
        is the correct verdict — nothing is bound — and a connection would mean
        the listener answers on a network the checker never agreed to share."""
        verdict = stack.probe(AGENT, GATEWAY_HOST, APPROVER_PORT)
        assert verdict["connected"] is False, (
            f"the approver port answers on the agent network: {verdict}"
        )

    def test_the_approver_holds_no_rail_credential_and_no_rail_route(self, stack: Stack) -> None:
        """The checker's door must not be a side entrance to the money. The
        approver container holds an answer credential, not a rail one, and has
        no route to the rail at all."""
        assert stack.env_of(APPROVER, "SECONDSIGN_RAIL_API_KEY") is None
        verdict = stack.probe(APPROVER, "rail", 9000)
        assert verdict["connected"] is False
        assert verdict["errno_name"] in NO_ROUTE


class TestTheReviewRoundTripAcrossContainers:
    def test_parked_answered_executed_and_read_back(self, stack: Stack) -> None:
        """The slice's acceptance criterion, run in the shipped topology."""
        before = len(stack.rail_requests())

        held = _authorize(stack, amount=REVIEW_AMOUNT, ref="66")
        assert held["status"] == "awaiting_review", (
            f"a proposal inside the review band did not park: {held}"
        )
        assert len(stack.rail_requests()) == before, "a held review reached the rail"

        listing = _console(stack, "list")
        assert listing["http_status"] == 200
        reviews = [
            item for item in listing["body"]["reviews"] if item["amount_minor"] == REVIEW_AMOUNT
        ]
        assert reviews, "the parked review is not visible to the approver"
        review = reviews[0]

        answered = _console(
            stack, "answer", "approve", str(review["approval_id"]), str(review["proposal"])
        )
        assert answered["http_status"] == 200
        assert answered["body"] == {"status": "executed", "reason": None}
        assert len(stack.rail_requests()) == before + 1, (
            "an approved review must reach the rail exactly once"
        )

        again = _authorize(stack, amount=REVIEW_AMOUNT, ref="66")
        assert again["status"] == "completed", (
            "the agent re-sending its own handle must read the settled answer"
        )
        assert len(stack.rail_requests()) == before + 1, "the re-send dispatched again"
