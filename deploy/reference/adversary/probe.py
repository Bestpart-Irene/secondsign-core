# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Hostile code, standard library only, run inside the agent container.

This file imports nothing from SecondSign. That is the point of it. An agent
that has decided to bypass its authorization boundary does not politely call
`secondsign-client`; it opens a socket. If the only demonstration of no-bypass
is that the sanctioned client behaves correctly, the demonstration covers the
one caller that was never the threat.

It reports a structured verdict rather than an exit code because the interesting
distinction is invisible in an exit code:

- **ECONNREFUSED** — the packet reached the destination network and something
  declined it. That is a control which is running, and which can therefore be
  turned off, misconfigured, or crash.
- **EHOSTUNREACH / ENETUNREACH / ETIMEDOUT** — there is no route. Nothing is
  making a decision, because nothing can be asked.

The second is the claim `deploy/reference/` exists to demonstrate. Collapsing
them into "it failed" would let a deployment pass this suite while running a
firewall rule someone can delete.
"""

from __future__ import annotations

import errno
import json
import socket
import sys

#: Long enough that a slow but present route still connects; short enough that a
#: silently dropping boundary does not stall the suite.
TIMEOUT_SECONDS = 5.0


def probe(host: str, port: int) -> dict[str, object]:
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT_SECONDS):
            return {"connected": True, "errno": None, "errno_name": None, "detail": None}
    except TimeoutError:
        # A drop, not a refusal. Reported as ETIMEDOUT so the caller's
        # no-route set covers it without special-casing the exception type.
        return {
            "connected": False,
            "errno": errno.ETIMEDOUT,
            "errno_name": "ETIMEDOUT",
            "detail": "timed out",
        }
    except socket.gaierror as exc:
        # Name resolution failed: the agent's network has no notion of that
        # host at all. Distinct from an unreachable address, and at least as
        # strong — reported separately so the difference stays visible.
        return {
            "connected": False,
            "errno": errno.ENETUNREACH,
            "errno_name": "EAI_NONAME",
            "detail": str(exc),
        }
    except OSError as exc:
        return {
            "connected": False,
            "errno": exc.errno,
            "errno_name": errno.errorcode.get(exc.errno or 0, "UNKNOWN"),
            "detail": str(exc),
        }


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(json.dumps({"error": "usage: probe.py <host> <port>"}))
        return 2
    print(json.dumps(probe(argv[1], int(argv[2]))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
