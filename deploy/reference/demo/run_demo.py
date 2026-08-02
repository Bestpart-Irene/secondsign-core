# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The agent's side of the demo: three proposals, three different fates.

    python demo/run_demo.py            # from deploy/reference/

Drives the *shipped* topology — every proposal is made from inside the agent
container, through `secondsign-client`, by a workload holding a client
certificate and no rail credential. This script only narrates.

    $42   → completed        (under the $200 review threshold)
    $300  → awaiting_review  (parked; answer it in the approver panel)
          → completed        (after your approval — same handle, re-sent)
    $900  → refused          (above the $500/hour cap)

The gateway is restarted first so each run starts with an empty spending
window — the reference control plane is deliberately in-memory, and without
the reset a second run within the hour would find $342 already spent and
deny what it parked the first time. Which is the control working, but makes
a confusing demo.
"""

from __future__ import annotations

import json
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

REFERENCE = Path(__file__).resolve().parents[1]
COMPOSE = ["-f", str(REFERENCE / "compose.yaml"), "-f", str(REFERENCE / "compose.demo.yaml")]

REVIEW_POLL_SECONDS = 2.0
REVIEW_WAIT_MINUTES = 10

#: The same driver the deployment suite uses: the sanctioned client, run where
#: the agent lives.
_AUTHORIZE = """
import json
from secondsign_client.transport import GatewayClient
from secondsign_client.wire import AuthorizationRequest

client = GatewayClient(
    host="gateway",
    port=8787,
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
        request_ref="fp:{ref}",
    )
)
print(json.dumps({{"status": outcome.status.value}}))
"""


def _docker() -> str:
    executable = shutil.which("docker")
    if executable is None:
        sys.exit("docker is not on PATH; the demo drives the containerised reference deployment")
    return executable


def _compose(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 — resolved executable, fixed arguments
        [_docker(), "compose", *COMPOSE, *args], capture_output=True, text=True, check=False
    )


def _propose(amount_minor: int, ref: str) -> str:
    script = _AUTHORIZE.format(amount=amount_minor, ref=ref)
    result = _compose("exec", "-T", "agent", "python", "-c", script)
    if not result.stdout.strip():
        sys.exit(f"the agent produced no outcome.\nstderr: {result.stderr}")
    return str(json.loads(result.stdout.splitlines()[-1])["status"])


def _dollars(minor: int) -> str:
    return f"${minor / 100:,.2f}"


def main() -> int:
    print("SecondSign demo — the agent's side. Panel: http://127.0.0.1:8090\n")

    print("resetting the gateway (fresh spending window) …", flush=True)
    _compose("restart", "gateway")
    for _ in range(30):
        probe = _compose(
            "exec",
            "-T",
            "gateway",
            "python",
            "-c",
            "import socket;socket.create_connection(('127.0.0.1',8787),timeout=2)",
        )
        if probe.returncode == 0:
            break
        time.sleep(1)
    print()

    small, held, large = 42_00, 300_00, 900_00

    status = _propose(small, secrets.token_hex(32))
    print(f"[1/3] {_dollars(small)} payment → {status}   (under the $200 review threshold)")

    ref = secrets.token_hex(32)
    status = _propose(held, ref)
    print(f"[2/3] {_dollars(held)} payment → {status}   (parked — decide it in the panel)")
    if status == "awaiting_review":
        deadline = time.monotonic() + REVIEW_WAIT_MINUTES * 60
        while time.monotonic() < deadline:
            time.sleep(REVIEW_POLL_SECONDS)
            status = _propose(held, ref)  # the same handle, re-sent
            if status != "awaiting_review":
                break
            print("      … still waiting for a human", flush=True)
        print(f"      → {status}   (your answer, read back by the agent)")

    status = _propose(large, secrets.token_hex(32))
    print(f"[3/3] {_dollars(large)} payment → {status}   (above the $500/hour cap)")

    print(
        "\nEvery step above is on the rail's ledger and the audit chain — `python demo/watch.py`."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
