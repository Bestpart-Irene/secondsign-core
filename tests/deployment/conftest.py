# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Driving the reference deployment from outside it.

These fixtures stand up `deploy/reference/`, run commands inside its containers,
and read what the mock rail received. They are the only place in this suite that
talks to Docker; the tests themselves speak in terms of "from the agent
container" and "what the rail recorded", because that is the vocabulary the
guarantee is written in.

**Absence of Docker is a failure, not a skip.** This suite runs only when the
`deployment` marker is selected, which means somebody asked for the deployment
gate specifically. A gate that reports "skipped" when it cannot run is a gate
that reports green on a machine where nothing was verified — the same failure
mode the Solidity job's mutation check exists to prevent. If you do not want
these tests, do not select them; if you selected them, they must run or fail.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
REFERENCE = REPO_ROOT / "deploy" / "reference"
COMPOSE_FILE = REFERENCE / "compose.yaml"

#: The override that joins the agent to the rail's network. Not a deployment —
#: the mutation `test_gate_liveness.py` requires the isolation cases to fail
#: against.
JOINED_OVERRIDE = REFERENCE / "compose.joined.yaml"

#: The same construction for the second door (CORE-S023): the agent joined to
#: the approver's network. Only `test_approver_gate_liveness.py` stands it up.
APPROVER_JOINED_OVERRIDE = REFERENCE / "compose.approver-joined.yaml"

#: Services, named once so a rename breaks in one place.
AGENT = "agent"
GATEWAY = "gateway"
RAIL = "rail"
APPROVER = "approver"

#: Where the approver listener binds: the gateway's fixed address on
#: approvernet, and that address only — which is the isolation claim.
APPROVER_ADDRESS = "172.28.99.10"
APPROVER_PORT = 8788

#: The port the gateway binds inside its own container.
GATEWAY_LISTEN_PORT = 8787

#: How long a gateway that is going to start is given to finish starting. Long
#: enough for a cold image build's first boot; expiring is not itself an error.
GATEWAY_START_SECONDS = 30.0


def _docker() -> str:
    executable = shutil.which("docker")
    if executable is None:
        pytest.fail(
            "docker is not on PATH, and this suite cannot verify anything without it.\n"
            "It fails rather than skips: a deployment gate that reports 'skipped' is a\n"
            "gate that reports green on a machine where nothing ran."
        )
    return executable


def _run(
    *args: str, check: bool = False, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 — resolved executable, fixed arguments
        [_docker(), *args],
        capture_output=True,
        text=True,
        check=check,
        env={**os.environ, **env} if env else None,
    )


@dataclass(frozen=True)
class Topology:
    """One Compose invocation: a project name and the files that define it.

    The reference topology is the deployment this project ships; each joined
    one is the same deployment with a single route added, stood up under its
    own project name so no two can share a container, a network or a ledger.
    Everything else about them is identical by construction, because each is
    the reference plus one override file.

    ``env`` is interpolation input for the compose files — today, only where
    the approver subnet lives (`SECONDSIGN_APPROVERNET_*`). The mutation
    session stands up two stacks at once, and a subnet written once in the
    compose file would make the second stack's network refuse to create,
    overlapping the first — which took down the *rail* mutation suite, three
    tests of which never mention the approver.
    """

    project: str
    files: tuple[Path, ...]
    env: tuple[tuple[str, str], ...] = ()
    #: Where this stack's approver listener lives. The isolation cases read it
    #: from the stack rather than a constant, so the same imported case means
    #: the same thing against the reference stack and a re-homed joined one.
    approver_address: str = "172.28.99.10"

    def compose(self, *args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
        flags: list[str] = []
        for path in self.files:
            flags += ["-f", str(path)]
        return _run("compose", "-p", self.project, *flags, *args, check=check, env=dict(self.env))


#: What `deploy/reference/` documents, and what the deployment gate asserts.
REFERENCE_TOPOLOGY = Topology("secondsign-reference", (COMPOSE_FILE,))

#: The same deployment with the agent joined to the rail's network. Used only by
#: the mutation check, which requires the isolation cases to fail against it.
JOINED_TOPOLOGY = Topology("secondsign-reference-joined", (COMPOSE_FILE, JOINED_OVERRIDE))

#: And with the agent joined to the approver's network (CORE-S023). Used only
#: by the approver-channel mutation check, for the same reason. Its approver
#: subnet is re-homed because the rail-joined stack is up at the same time in
#: the mutation session, and two stacks cannot hold one subnet.
APPROVER_JOINED_TOPOLOGY = Topology(
    "secondsign-reference-approver-joined",
    (COMPOSE_FILE, APPROVER_JOINED_OVERRIDE),
    env=(
        ("SECONDSIGN_APPROVERNET_SUBNET", "172.28.100.0/24"),
        ("SECONDSIGN_APPROVERNET_GATEWAY", "172.28.100.10"),
    ),
    approver_address="172.28.100.10",
)


def _wait_for_listener(topology: Topology, service: str, port: int, seconds: float) -> None:
    """Give a best-effort service a bounded chance to bind its listener.

    Returns either way. A service that never binds leaves the cases that need it
    to report that themselves — this removes a race, and cannot mask a failure:
    the question asked here is "is something bound inside your own container",
    and every claim this suite makes is about reachability *across a network
    boundary* from somewhere else.
    """
    deadline = time.monotonic() + seconds
    connect = f"import socket;socket.create_connection(('127.0.0.1',{port}),timeout=2)"
    while time.monotonic() < deadline:
        if topology.compose("exec", "-T", service, "python", "-c", connect).returncode == 0:
            return
        time.sleep(1.0)


@dataclass(frozen=True)
class Stack:
    """A running deployment, and the questions this suite asks of it."""

    topology: Topology

    @property
    def approver_address(self) -> str:
        """Where this stack's approver listener lives (CORE-S023)."""
        return self.topology.approver_address

    def exec(self, service: str, *argv: str) -> subprocess.CompletedProcess[str]:
        """Run a command inside one container. Never raises on non-zero exit.

        A non-zero exit is frequently the assertion — an adversary failing to
        reach the rail is the expected result, not an error in the harness.
        """
        return self.topology.compose("exec", "-T", service, *argv)

    def probe(self, service: str, target: str, port: int) -> dict[str, object]:
        """Run the standard-library adversary against ``target:port``.

        Returns its structured verdict: whether the connection was established,
        and if not, which errno the kernel gave. The distinction matters — a
        refusal from the rail and an absence of any route to it are the same
        exit code and completely different security claims.
        """
        result = self.exec(service, "python", "/adversary/probe.py", target, str(port))
        if not result.stdout.strip():
            pytest.fail(
                f"the adversary produced no verdict in {service!r}.\n"
                f"stdout={result.stdout!r} stderr={result.stderr!r}"
            )
        return dict(json.loads(result.stdout))

    def stop(self, service: str) -> None:
        self.topology.compose("stop", service, check=True)

    def start(self, service: str, *, listen_port: int = GATEWAY_LISTEN_PORT) -> None:
        """Start a stopped service and wait for it to be listening again.

        `compose start` returns when the container is running, which is earlier
        than when the process inside it has bound its socket. Without the wait,
        a case that restores the gateway hands the next case a gateway that is
        up by Docker's definition and absent by the network's.
        """
        self.topology.compose("start", service, check=True)
        _wait_for_listener(self.topology, service, listen_port, GATEWAY_START_SECONDS)

    def rail_requests(self) -> list[dict[str, object]]:
        """What the mock rail recorded, read from the rail container itself.

        Read at the destination on purpose. A bypass that succeeded is visible
        here and nowhere else: the agent-side view can only ever say "my attempt
        failed", which is not the same statement as "nothing arrived".
        """
        result = self.exec(RAIL, "cat", "/var/log/rail/requests.jsonl")
        return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]

    def env_of(self, service: str, variable: str) -> str | None:
        result = self.exec(service, "printenv", variable)
        value = result.stdout.strip()
        return value or None


def _bring_up(topology: Topology):
    """Stand a topology up, hand it over, and tear it down afterwards.

    Services come up in two groups, and the split is deliberate rather than an
    optimisation. `certs`, `rail` and `agent` are brought up and waited for: if
    any of them fails, no case in this suite means anything and the whole
    session should stop.

    `gateway` is started **best-effort**, then waited for with a deadline that
    expiring is not an error. Both halves matter, and they are not the same
    half.

    Best-effort, because a gateway that refuses to start must not abort the
    session: `--wait` would report "the stack did not come up" for every case,
    including the network-isolation ones that are perfectly testable without it.
    Letting it fail per-case gives a far more useful signal — the isolation
    results go green while `TestTheSuiteIsNotVacuous` stays red, which is the
    suite saying exactly the right thing: *the agent could not reach the rail,
    and you may not yet conclude anything from that, because I have not shown
    you it could reach anything at all.*

    Waited for, because `up -d` returns before the listener is bound, and on a
    cold build the vacuity guard would probe an address nothing was on yet — a
    gate that flakes red, which teaches people to re-run gates until they go
    green. That habit is a worse outcome than the failure the guard exists to
    catch, so the race is removed rather than tolerated.
    """
    missing = [str(path.relative_to(REPO_ROOT)) for path in topology.files if not path.exists()]
    if missing:
        pytest.fail(
            f"the {topology.project} topology is missing {missing}.\n"
            "CORE-S019 is not implemented yet; these tests are expected to fail."
        )

    if _run("info").returncode != 0:
        pytest.fail("the Docker daemon is not reachable; this gate cannot run, so it fails.")

    # Generated on the host, not in a container, and checked for output rather
    # than for an exit code.
    #
    # Both halves of that are scar tissue. The first attempt ran generation as a
    # Compose service and trusted `docker compose up certs`, which returns 0 when
    # the container stops — whatever exit code it stopped with. So the check
    # could not fail: generation produced nothing, the fixture reported success,
    # and the failure surfaced four tests later as "the agent cannot read its own
    # client key", which reads like a mount bug.
    #
    # Running it on the host also removed a guess about what a base image ships,
    # and the generator is now Python rather than a shell script for a related
    # reason: it used `openssl x509 -not_after`, which is the only way that CLI
    # expresses a sub-day lifetime and is recent enough to be present on a
    # developer's OpenSSL 3.6 and absent on the runner's 3.0. Its properties are
    # now checked by `test_pki.py` in the ordinary suite, on every platform,
    # without Docker.
    generated = subprocess.run(  # noqa: S603 — fixed path inside the repository
        [sys.executable, str(REFERENCE / "tls" / "generate.py")],
        capture_output=True,
        text=True,
        check=False,
    )
    client_cert = REFERENCE / "tls" / "agent" / "client-cert.pem"
    if generated.returncode != 0 or not client_cert.exists():
        pytest.fail(
            "certificate generation did not produce a client certificate.\n"
            f"exit={generated.returncode}\n{generated.stdout}\n{generated.stderr}"
        )

    ready = topology.compose("up", "-d", "--build", "--wait", RAIL, AGENT, APPROVER)
    if ready.returncode != 0:
        pytest.fail(
            f"the agent, rail and approver containers did not come up, so nothing "
            f"in this suite can be believed:\n{ready.stdout}\n{ready.stderr}"
        )

    # Best-effort. Its absence is reported by the cases that need it.
    topology.compose("up", "-d", "--build", GATEWAY)
    _wait_for_listener(topology, GATEWAY, GATEWAY_LISTEN_PORT, GATEWAY_START_SECONDS)

    try:
        yield Stack(topology)
    finally:
        topology.compose("down", "-v", "--remove-orphans")


@pytest.fixture(scope="session")
def stack() -> Stack:
    """The reference deployment: what `deploy/reference/` documents and ships."""
    yield from _bring_up(REFERENCE_TOPOLOGY)


@pytest.fixture(scope="session")
def joined_stack() -> Stack:
    """The same deployment with the agent joined to the rail's network.

    Stood up only by the mutation check. It is the deployment this project tells
    operators not to build, and its whole purpose is to be caught.
    """
    yield from _bring_up(JOINED_TOPOLOGY)


@pytest.fixture(scope="session")
def approver_joined_stack() -> Stack:
    """The same deployment with the agent joined to the approver's network.

    The second door's counterpart of `joined_stack`, stood up only by
    `test_approver_gate_liveness.py`, and existing only to be caught.
    """
    yield from _bring_up(APPROVER_JOINED_TOPOLOGY)
