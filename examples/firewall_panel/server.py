#!/usr/bin/env python
# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The panel's HTTP surface: a JSON API over one :class:`Session`, plus the page.

Standard library only, bound to loopback, no authentication — the same posture
as ``deploy/reference/approver/panel.py`` and for the same reason: this is a
demonstration aid, not a product surface. Anyone who can reach the port drives
the demo, which is why it is never bound anywhere but ``127.0.0.1``.

    python examples/firewall_panel/server.py      # then open http://127.0.0.1:8099
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
for _path in (str(_REPO), str(_REPO / "src")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from examples.firewall_panel.scenarios import BY_KEY, CATALOGUE  # noqa: E402
from examples.firewall_panel.session import CHECKERS, Session  # noqa: E402
from examples.firewall_panel.trace import GUARD_INVARIANTS  # noqa: E402
from examples.firewall_panel.world import SAFE, TAMPER_LABELS, USDC, Tamper  # noqa: E402

_STATIC = Path(__file__).resolve().parent / "static"
_MIME = {".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript"}

SESSION = Session()


def _state() -> dict:
    """Everything the page re-renders after any action."""
    world = SESSION.world
    return {
        "safe": {
            "address": SAFE,
            "balance": f"{world.balance / USDC:,.2f}",
            "owners": list(world.live.owners),
            "threshold": world.live.threshold,
            "chain_id": world.live.chain_id,
            "attested_chain_id": world.expected.chain_id,
            "safe_version": world.live.safe_version,
            "transaction_guard": world.live.transaction_guard,
            "module_guard": world.live.module_guard,
            "token": world.expected.token,
            "token_implementation": world.live_token.implementation,
            "reader_wired": world.reader_wired,
            "cosigner": SESSION.cosigner_address,
        },
        "tampers": [
            {"key": t.value, "label": TAMPER_LABELS[t], "applied": t in world.applied}
            for t in Tamper
        ],
        "knobs": {
            "approval_cap": SESSION.knobs.approval_cap,
            "approval_cap_usdc": f"{SESSION.knobs.approval_cap / USDC:g}",
            "review_above": SESSION.knobs.review_above or 0,
            "review_above_usdc": f"{(SESSION.knobs.review_above or 0) / USDC:g}",
            "vouched": sorted(SESSION.knobs.approve_spender_allowlist),
        },
        "reviews": list(SESSION.open_reviews()),
        "audit": list(SESSION.audit_tail()),
        "checkers": [{"subject": s, "label": label} for s, label in CHECKERS],
        "scenarios": [
            {"key": s.key, "title": s.title, "detail": s.detail, "claims": s.claims}
            for s in CATALOGUE
        ],
        "guard_invariants": list(GUARD_INVARIANTS),
    }


def _outcome_payload(outcome) -> dict:  # noqa: ANN001 — CosignOutcome
    return {
        "status": outcome.status.value,
        "signature": outcome.signature,
        "approval_id": outcome.approval_id,
        "reasons": [
            f.code.value for f in (outcome.judgement.findings if outcome.judgement else ())
        ],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "SecondSignFirewallPanel/1"

    def log_message(self, *_args) -> None:  # noqa: ANN002 — quiet by default
        pass

    # -- plumbing --------------------------------------------------------

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: dict, status: int = 200) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json")

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length) or b"{}")

    # -- routes ----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler's name
        if self.path in ("/", "/index.html"):
            return self._file("panel.html")
        if self.path.startswith("/static/"):
            return self._file(self.path.removeprefix("/static/"))
        if self.path == "/api/state":
            return self._json(_state())
        self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        try:
            handler = {
                "/api/propose": self._propose,
                "/api/resolve": self._resolve,
                "/api/tamper": self._tamper,
                "/api/reconfigure": self._reconfigure,
                "/api/reset": self._reset,
            }.get(self.path)
            if handler is None:
                return self._send(404, b"not found", "text/plain")
            handler(self._body())
        except Exception as exc:  # noqa: BLE001 — a demo must not fail silently
            # A backend error surfaces as an error, never as a plausible-looking
            # verdict: a panel that invented an answer would be worse than one
            # that broke visibly.
            traceback.print_exc()
            self._json({"error": f"{type(exc).__name__}: {exc}"}, status=500)

    def _file(self, name: str) -> None:
        path = (_STATIC / name).resolve()
        if not path.is_file() or _STATIC not in path.parents:
            return self._send(404, b"not found", "text/plain")
        self._send(200, path.read_bytes(), _MIME.get(path.suffix, "application/octet-stream"))

    def _propose(self, body: dict) -> None:
        key = body.get("scenario")
        if key not in BY_KEY:
            return self._json({"error": f"unknown scenario {key!r}"}, status=400)
        scenario = BY_KEY[key]
        outcome, observed = SESSION.propose(scenario.call)
        self._json(
            {
                "scenario": {
                    "key": scenario.key,
                    "title": scenario.title,
                    "detail": scenario.detail,
                },
                "outcome": _outcome_payload(outcome),
                "stations": [asdict(station) for station in observed.stations],
                "state": _state(),
            }
        )

    def _resolve(self, body: dict) -> None:
        outcome, observed = SESSION.resolve(
            body["approval_id"], checker=body["checker"], approved=bool(body["approved"])
        )
        self._json(
            {
                "outcome": _outcome_payload(outcome),
                "stations": [asdict(station) for station in observed.stations],
                "state": _state(),
            }
        )

    def _tamper(self, body: dict) -> None:
        if body.get("repair"):
            SESSION.repair()
        else:
            SESSION.tamper(Tamper(body["tamper"]))
        self._json({"state": _state()})

    def _reconfigure(self, body: dict) -> None:
        SESSION.reconfigure(
            approval_cap=_usdc(body.get("approval_cap_usdc")),
            review_above=_usdc(body.get("review_above_usdc")),
            vouch_spender=body.get("vouch_spender"),
            unvouch_spender=body.get("unvouch_spender"),
        )
        self._json({"state": _state()})

    def _reset(self, _body: dict) -> None:
        SESSION.reset()
        self._json({"state": _state()})


def _usdc(value) -> int | None:  # noqa: ANN001
    return None if value is None or value == "" else int(round(float(value) * USDC))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8099)
    args = parser.parse_args()
    # Loopback only, always. The panel has no authentication, so the bind
    # address is the whole access control.
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"SecondSign firewall panel → http://127.0.0.1:{args.port}")
    print("the chain is simulated; the judgement and the signature are real")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
