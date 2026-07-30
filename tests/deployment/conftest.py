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

#: Services, named once so a rename breaks in one place.
AGENT = "agent"
GATEWAY = "gateway"
RAIL = "rail"

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


def _run(*args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 — resolved executable, fixed arguments
        [_docker(), *args],
        capture_output=True,
        text=True,
        check=check,
    )


@dataclass(frozen=True)
class Topology:
    """One Compose invocation: a project name and the files that define it.

    Two exist. The reference topology is the deployment this project ships; the
    joined one is the same deployment with a single route added, stood up under
    its own project name so the two can never share a container, a network or a
    ledger. Everything else about them is identical by construction, because the
    second is the first plus one override file.
    """

    project: str
    files: tuple[Path, ...]

    def compose(self, *args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
        flags: list[str] = []
        for path in self.files:
            flags += ["-f", str(path)]
        return _run("compose", "-p", self.project, *flags, *args, check=check)


#: What `deploy/reference/` documents, and what the deployment gate asserts.
REFERENCE_TOPOLOGY = Topology("secondsign-reference", (COMPOSE_FILE,))

#: The same deployment with the agent joined to the rail's network. Used only by
#: the mutation check, which requires the isolation cases to fail against it.
JOINED_TOPOLOGY = Topology("secondsign-reference-joined", (COMPOSE_FILE, JOINED_OVERRIDE))


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

    ready = topology.compose("up", "-d", "--build", "--wait", RAIL, AGENT)
    if ready.returncode != 0:
        pytest.fail(
            f"the agent and rail containers did not come up, so nothing in this "
            f"suite can be believed:\n{ready.stdout}\n{ready.stderr}"
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
