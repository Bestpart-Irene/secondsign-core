# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""A payment rail that records what reached it.

The point of this service is **destination-side accounting**. Every other way of
checking no-bypass asks the source: did the agent's attempt fail? That question
has a blind spot precisely where it matters — an attempt that *succeeded* looks,
from the agent's side, like an attempt that was supposed to succeed.

So this records every request that arrives, whatever it is and however
malformed, and the test suite compares that ledger against what the gateway
says it dispatched. A bypass is a line in this file with no matching dispatch.

It records **before** it validates. A rail that only logged well-formed requests
would miss exactly the traffic worth noticing: a raw socket write from hostile
code is not going to be a well-formed payment.

Standard library only, so the rail image needs nothing installed and the
recording path has no dependency that could fail and lose a line.
"""

from __future__ import annotations

import json
import os
import socketserver
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

LEDGER = Path(os.environ.get("RAIL_LEDGER", "/var/log/rail/requests.jsonl"))
PORT = int(os.environ.get("RAIL_PORT", "9000"))

#: The header the gateway sets on every request it dispatches. Its absence is
#: what makes a bypass identifiable: anything arriving without it did not come
#: through the gateway, whatever it claims in its body.
#:
#: Note what this is *not*: a security control. Any client could set it. It is a
#: label for the ledger, and the test that matters asserts the count of gateway
#: dispatches equals the count of recorded requests — a forged label cannot
#: create a matching dispatch on the other side.
VIA_HEADER = "X-SecondSign-Via"

_lock = threading.Lock()


def record(entry: dict[str, object]) -> None:
    """Append one line, flushed and fsynced before the response is sent.

    Durability matters more than throughput here. A test that stops the gateway
    and then reads this file must not race a buffered write, or the suite
    acquires an intermittent false negative — which on this particular
    assertion means "no bypass detected" when there was one.
    """
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry, sort_keys=True)
    with _lock, LEDGER.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
        handle.flush()
        os.fsync(handle.fileno())


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _record_and_reply(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        record(
            {
                "at": datetime.now(timezone.utc).isoformat(),
                "method": self.command,
                "path": self.path,
                "via": self.headers.get(VIA_HEADER),
                "peer": self.client_address[0],
                # Length rather than content: this is a test fixture, and a
                # ledger that stored request bodies would be the one place in
                # this repository that persists whatever an adversary sent.
                "body_bytes": len(body),
            }
        )
        payload = json.dumps({"status": "recorded"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler's naming
        self._record_and_reply()

    def do_POST(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler's naming
        self._record_and_reply()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Send access logs to stdout so `docker compose logs` shows them."""
        sys.stdout.write(f"rail {self.address_string()} {format % args}\n")
        sys.stdout.flush()


class Server(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> int:
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    LEDGER.touch(exist_ok=True)
    # 0.0.0.0 inside a container joined only to the rail network. The isolation
    # is the network topology, not a bind address — binding narrowly here would
    # be security theatre that also broke the gateway's access.
    with Server(("0.0.0.0", PORT), Handler) as server:  # noqa: S104
        sys.stdout.write(f"mock rail listening on {PORT}, ledger at {LEDGER}\n")
        sys.stdout.flush()
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
