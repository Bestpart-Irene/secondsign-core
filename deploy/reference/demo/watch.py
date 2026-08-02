# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The destination's side of the demo: the rail's ledger, live.

    python demo/watch.py               # from deploy/reference/; Ctrl-C to stop

Reads what the mock rail *received*, from inside the rail container — the only
vantage point that can distinguish "the agent's attempt failed" from "nothing
arrived". Every line that appears here is a request that crossed the gateway
holding a credential the agent does not have, over a route the agent does not
have. A refused or parked proposal never shows up, which is the point.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

REFERENCE = Path(__file__).resolve().parents[1]
COMPOSE = ["-f", str(REFERENCE / "compose.yaml"), "-f", str(REFERENCE / "compose.demo.yaml")]

POLL_SECONDS = 1.0


def _docker() -> str:
    executable = shutil.which("docker")
    if executable is None:
        sys.exit("docker is not on PATH; the demo drives the containerised reference deployment")
    return executable


def _ledger() -> list[dict[str, object]]:
    result = subprocess.run(  # noqa: S603 — resolved executable, fixed arguments
        [
            _docker(),
            "compose",
            *COMPOSE,
            "exec",
            "-T",
            "rail",
            "cat",
            "/var/log/rail/requests.jsonl",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]


def main() -> int:
    print("SecondSign demo — the rail's own ledger. Ctrl-C to stop.\n")
    seen = 0
    while True:
        try:
            entries = _ledger()
        except (OSError, ValueError) as exc:
            print(f"  (ledger unreadable: {exc})", flush=True)
            time.sleep(POLL_SECONDS)
            continue
        if len(entries) < seen:
            print(f"  ── ledger reset ({len(entries)} entries) ──", flush=True)
            seen = 0
        for index in range(seen, len(entries)):
            entry = entries[index]
            stamp = time.strftime("%H:%M:%S")
            via = entry.get("via", "?")
            print(f"  {stamp}  request #{index + 1} arrived   via={via}", flush=True)
        seen = len(entries)
        try:
            time.sleep(POLL_SECONDS)
        except KeyboardInterrupt:
            return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
