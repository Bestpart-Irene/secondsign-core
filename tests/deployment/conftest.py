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
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
REFERENCE = REPO_ROOT / "deploy" / "reference"
COMPOSE_FILE = REFERENCE / "compose.yaml"

#: Services, named once so a rename breaks in one place.
AGENT = "agent"
GATEWAY = "gateway"
RAIL = "rail"


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


def _compose(*args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
    return _run("compose", "-f", str(COMPOSE_FILE), *args, check=check)


@dataclass(frozen=True)
class Stack:
    """A running reference deployment, and the questions this suite asks of it."""

    def exec(self, service: str, *argv: str) -> subprocess.CompletedProcess[str]:
        """Run a command inside one container. Never raises on non-zero exit.

        A non-zero exit is frequently the assertion — an adversary failing to
        reach the rail is the expected result, not an error in the harness.
        """
        return _compose("exec", "-T", service, *argv)

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
        _compose("stop", service, check=True)

    def start(self, service: str) -> None:
        _compose("start", service, check=True)

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


@pytest.fixture(scope="session")
def stack() -> Stack:
    """Bring the reference deployment up for the session, and tear it down.

    Services come up in two groups, and the split is deliberate rather than an
    optimisation. `certs`, `rail` and `agent` are brought up and waited for: if
    any of them fails, no case in this suite means anything and the whole
    session should stop.

    `gateway` is started **best-effort**. While `CORE-S019` is incomplete it
    cannot start at all, and waiting on it would abort the session — reporting
    "the stack did not come up" for every case, including the network-isolation
    ones that are perfectly testable without it.

    Letting it fail per-case gives a far more useful signal. The isolation
    results go green while `TestTheSuiteIsNotVacuous` stays red, which is the
    suite saying exactly the right thing: *the agent could not reach the rail,
    and you may not yet conclude anything from that, because I have not shown
    you it could reach anything at all.*
    """
    if not COMPOSE_FILE.exists():
        pytest.fail(
            f"no reference deployment at {COMPOSE_FILE.relative_to(REPO_ROOT)}.\n"
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

    ready = _compose("up", "-d", "--build", "--wait", RAIL, AGENT)
    if ready.returncode != 0:
        pytest.fail(
            f"the agent and rail containers did not come up, so nothing in this "
            f"suite can be believed:\n{ready.stdout}\n{ready.stderr}"
        )

    # Best-effort. Its absence is reported by the cases that need it.
    _compose("up", "-d", "--build", GATEWAY)

    try:
        yield Stack()
    finally:
        _compose("down", "-v", "--remove-orphans")
