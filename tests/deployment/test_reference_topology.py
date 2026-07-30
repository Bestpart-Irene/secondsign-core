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

import json

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

#: Where the harness mounts generated key material, read-only, per ADR 0004 §3.
#: Files rather than environment variables: a mount can be scoped per container,
#: and an environment variable is inherited by every child process.
MOUNT_ROOT = "/etc/secondsign/tls"
CLIENT_KEY_PATH = f"{MOUNT_ROOT}/client-key.pem"
CLIENT_CERT_PATH = f"{MOUNT_ROOT}/client-cert.pem"

#: Errnos that mean "there is no route", as opposed to "something said no".
#: EHOSTUNREACH and ENETUNREACH are unambiguous. ETIMEDOUT is included because a
#: silently dropping network boundary is the common shape in practice; a refusal
#: would be ECONNREFUSED, which is deliberately absent from this set.
#:
#: By symbolic name, not through the `errno` module: the probe reports what the
#: *container's* kernel said, and the container is always Linux, while this
#: module runs on whatever the developer has. Numeric comparison worked on the
#: Linux CI runner and failed on macOS, where ENETUNREACH is 51 to Linux's 101 —
#: the same claim, refused for being asserted in the wrong kernel's numbering.
#:
#: EAI_NONAME is the probe's name-resolution verdict: the agent's resolver has
#: no notion of the rail's name at all, because Docker's DNS answers only for
#: services sharing a network. At least as strong as an unreachable address —
#: the probe already collapses it into ENETUNREACH numerically — and which of
#: the two a given Docker version produces varies, so both names are accepted.
NO_ROUTE = {"EHOSTUNREACH", "ENETUNREACH", "ETIMEDOUT", "EAI_NONAME"}


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

        assert verdict["errno_name"] in NO_ROUTE, (
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


class TestKeyCustodySeparation:
    """Which container holds which key (ADR 0004 §3).

    The reference deployment does not pretend to be a secret store. It generates
    an ephemeral CA and leaves at start-up, commits nothing, and mounts material
    read-only. What it demonstrates is *custody separation*, and these cases are
    that demonstration.
    """

    def test_the_agent_holds_its_own_client_key(self, stack: Stack) -> None:
        """Stated first, because the next three would otherwise read as a stronger
        claim than this deployment makes.

        The agent container *does* hold a credential: its client private key. It
        has to, or it could not authenticate. "The agent holds no credential"
        would be false, and asserting it would repeat the error of calling
        `ModuleNotFoundError` the boundary.
        """
        result = stack.exec(AGENT, "test", "-r", CLIENT_KEY_PATH)

        assert result.returncode == 0, "the agent cannot read its own client key"

    def test_the_agent_cannot_reach_the_gateway_key(self, stack: Stack) -> None:
        assert self._search(stack, AGENT, "gateway") == [], (
            "gateway key material is visible from the agent container"
        )

    def test_the_agent_cannot_reach_the_ca_signing_key(self, stack: Stack) -> None:
        """The one that would let an agent mint its own identity."""
        assert self._search(stack, AGENT, "ca-key") == [], (
            "the CA signing key is visible from the agent container; "
            "an agent that can sign can name itself any principal it likes"
        )

    def test_the_rail_credential_is_nowhere_in_the_agent_container(self, stack: Stack) -> None:
        """Environment and filesystem both, because either would be enough."""
        env = stack.exec(AGENT, "printenv")
        files = self._search(stack, AGENT, "rail")

        assert CREDENTIAL_VARIABLE not in env.stdout
        assert files == []

    @staticmethod
    def _search(stack: Stack, service: str, needle: str) -> list[str]:
        """Filenames under the mount root whose name matches ``needle``.

        Deliberately a filename search rather than a content scan: the point is
        that the material is not *delivered* here at all, which is a stronger
        and more stable property than no file happening to contain a key today.
        """
        result = stack.exec(service, "sh", "-c", f"ls -1 {MOUNT_ROOT} 2>/dev/null || true")
        return [name for name in result.stdout.split() if needle in name]


class TestCertificateLifetime:
    """Short-lived certificates are the whole revocation story (ADR 0004 §4).

    There is no CRL and no OCSP. A leaked certificate stays valid until it
    expires, so how long that is *is* the security property, not a detail.
    """

    def test_the_client_certificate_expires_within_the_hour(self, stack: Stack) -> None:
        result = stack.exec(
            AGENT,
            "python",
            "-c",
            "import datetime, ssl, sys\n"
            f"info = ssl._ssl._test_decode_cert('{CLIENT_CERT_PATH}')\n"
            "end = datetime.datetime.strptime(info['notAfter'], '%b %d %H:%M:%S %Y %Z')\n"
            "start = datetime.datetime.strptime(info['notBefore'], '%b %d %H:%M:%S %Y %Z')\n"
            "print(int((end - start).total_seconds()))\n",
        )

        assert result.returncode == 0, f"could not read the client certificate: {result.stderr!r}"
        assert int(result.stdout.strip()) <= 3600, (
            "the reference deployment must issue 1-hour client certificates; "
            "a longer one weakens the only revocation mechanism there is"
        )


class TestThePrincipalCannotBeSelfAsserted:
    """Scope comes from the authenticated caller, never from what a request says.

    This is the sentence ADR 0004 exists to protect, tested at the wire: a body
    that carries a principal must be **refused**, not accepted-and-ignored.
    Ignoring it leaves a field that a later change can quietly start honouring.
    """

    def test_a_body_supplied_principal_is_refused(self, stack: Stack) -> None:
        script = (
            "import json, sys, urllib.error, urllib.request\n"
            "body = json.dumps({'client_principal': 'sppiffe://impersonated'}).encode()\n"
            f"req = urllib.request.Request('http://{GATEWAY_HOST}:{GATEWAY_PORT}/authorize',"
            " data=body, headers={'Content-Type': 'application/json'})\n"
            "try:\n"
            "    urllib.request.urlopen(req, timeout=5)\n"
            "except urllib.error.HTTPError as exc:\n"
            "    print(exc.code)\n"
            "    sys.exit(0)\n"
            "except OSError as exc:\n"
            "    print(f'transport:{exc}')\n"
            "    sys.exit(0)\n"
            "print('accepted')\n"
        )

        result = stack.exec(AGENT, "python", "-c", script)

        assert "accepted" not in result.stdout, (
            "the gateway accepted a request carrying its own principal; "
            "scope must derive from the TLS session alone"
        )


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
        assert verdict["errno_name"] in NO_ROUTE

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


#: One authorization, driven from inside the agent container through the
#: sanctioned client. Written as a script rather than a fixture because it must
#: run *there* — in an environment holding a client certificate, no rail
#: credential, and no route to the rail.
_AUTHORIZE = """
import json
from secondsign_client.transport import GatewayClient
from secondsign_client.wire import AuthorizationRequest

client = GatewayClient(
    host="{host}",
    port={port},
    ca_file="/etc/secondsign/tls/ca-cert.pem",
    client_cert="/etc/secondsign/tls/client-cert.pem",
    client_key="/etc/secondsign/tls/client-key.pem",
)
outcome = client.request_authorization(
    AuthorizationRequest(
        action="payment",
        rail="card",
        currency="USD",
        amount_minor={amount},
        reversibility="irreversible",
        counterparty_ref="fp:" + "ab" * 32,
        source_account_ref="fp:" + "cd" * 32,
        request_ref="fp:" + "{ref}" * 32,
    )
)
print(json.dumps({{"status": outcome.status.value}}))
"""


class TestTheSanctionedPath:
    """The other half of the demonstration.

    Every case above is about what the agent cannot do. If that were all, the
    deployment would be indistinguishable from one where the gateway is broken:
    a boundary that refuses everything is not a boundary, it is an outage. These
    cases run the same container, asking properly, and require money to move —
    through the gateway, holding a credential this container does not have, over
    a route this container does not have.
    """

    def _authorize(self, stack: Stack, *, amount: int, ref: str) -> dict[str, object]:
        script = _AUTHORIZE.format(host=GATEWAY_HOST, port=GATEWAY_PORT, amount=amount, ref=ref)
        result = stack.exec(AGENT, "python", "-c", script)
        if not result.stdout.strip():
            pytest.fail(
                f"the client produced no outcome in the agent container.\n"
                f"stdout={result.stdout!r} stderr={result.stderr!r}"
            )
        return dict(json.loads(result.stdout.splitlines()[-1]))

    def test_the_agent_environment_holds_the_client_and_no_control_plane(
        self, stack: Stack
    ) -> None:
        """Executed, not asserted. `secondsign_client` imports; every
        control-plane module is a ModuleNotFoundError — one term of no-bypass,
        never the boundary itself."""
        result = stack.exec(AGENT, "python", "-c", "import secondsign_client")
        assert result.returncode == 0, f"the client is not installed: {result.stderr!r}"

        for module in ("gateway", "rails", "approval", "audit", "policy"):
            denied = stack.exec(AGENT, "python", "-c", f"import secondsign.{module}")
            assert denied.returncode != 0, f"secondsign.{module} is importable in the agent"
            assert "ModuleNotFoundError" in denied.stderr

    def test_a_proposal_through_the_client_is_authorized_and_executed(self, stack: Stack) -> None:
        outcome = self._authorize(stack, amount=4_200, ref="11")

        assert outcome["status"] == "completed", (
            "the sanctioned path did not complete; a boundary that refuses "
            f"everything is an outage, not a control: {outcome}"
        )

    def test_the_rail_recorded_exactly_that_dispatch(self, stack: Stack) -> None:
        """Destination-side, and now non-vacuous: the ledger is compared before
        and after one authorization, so the count is evidence rather than two
        zeroes agreeing with each other."""
        before = len(stack.rail_requests())

        self._authorize(stack, amount=1_500, ref="22")

        after = stack.rail_requests()
        assert len(after) == before + 1, (
            f"one authorization produced {len(after) - before} rail requests"
        )
        assert after[-1]["via"] == "gateway"

    def test_the_agent_still_holds_no_rail_credential_while_doing_it(self, stack: Stack) -> None:
        """The claim the slice rests on, checked at the moment it matters: the
        workload that just moved money cannot move any itself."""
        self._authorize(stack, amount=900, ref="33")

        assert stack.env_of(AGENT, "SECONDSIGN_RAIL_API_KEY") is None
        assert stack.probe(AGENT, RAIL_HOST, RAIL_PORT)["connected"] is False

    def test_a_proposal_over_the_limit_is_refused_and_moves_nothing(self, stack: Stack) -> None:
        before = len(stack.rail_requests())

        outcome = self._authorize(stack, amount=900_000_00, ref="44")

        assert outcome["status"] == "refused"
        assert len(stack.rail_requests()) == before, "a refused proposal reached the rail"

    def test_with_the_gateway_stopped_the_sanctioned_path_refuses_too(self, stack: Stack) -> None:
        """Not a locally computed verdict, and not an exception the agent could
        mistake for one. Stop the gateway and authorization is impossible."""
        stack.stop(GATEWAY)
        try:
            outcome = self._authorize(stack, amount=100, ref="55")
        finally:
            stack.start(GATEWAY)

        assert outcome["status"] == "refused"
