# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The approver's panel: the demo's human, in a browser. Standard library.

Runs inside the approver container (see `compose.demo.yaml`), which is the
only place holding a credential the approver CA ever issued. The browser talks
plain HTTP to this process on a port published to the host's loopback; this
process talks mTLS to the approver channel. The checker credential never
leaves the container, and the panel adds no vocabulary the channel does not
have — list, approve, decline, nothing else.

This is a demo aid, deliberately not a product surface: no login, no users, no
history. Anyone who can reach the panel's port can answer reviews, which is
why `compose.demo.yaml` publishes it to `127.0.0.1` only. A real deployment
puts its approval UI in front of the same two endpoints with its own
authentication — the channel neither knows nor cares what renders it.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
from http.client import HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CERT = "/etc/secondsign/tls/client-cert.pem"
KEY = "/etc/secondsign/tls/client-key.pem"
CA = "/etc/secondsign/tls/approver-ca-cert.pem"

APPROVER_HOST = os.environ.get("PANEL_APPROVER_HOST", "172.28.99.10")
APPROVER_PORT = int(os.environ.get("PANEL_APPROVER_PORT", "8788"))
PANEL_PORT = int(os.environ.get("PANEL_PORT", "8090"))

TIMEOUT_SECONDS = 10.0

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SecondSign — open reviews</title>
<style>
  :root { --bg:#0d1117; --card:#161b22; --line:#30363d; --text:#e6edf3;
          --dim:#8b949e; --green:#2ea043; --red:#da3633; --amber:#d29922; }
  * { box-sizing:border-box; margin:0; }
  body { background:var(--bg); color:var(--text); min-height:100vh;
         font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; padding:2rem; }
  h1 { font-size:1rem; letter-spacing:.12em; text-transform:uppercase; color:var(--dim); }
  h1 b { color:var(--text); }
  #status { color:var(--dim); font-size:.8rem; margin:.4rem 0 1.6rem; }
  .review { background:var(--card); border:1px solid var(--line); border-radius:8px;
            padding:1rem 1.2rem; margin-bottom:1rem; max-width:34rem; }
  .amount { font-size:1.5rem; }
  .meta { color:var(--dim); font-size:.8rem; margin:.5rem 0 1rem; line-height:1.7;
          overflow-wrap:anywhere; }
  .row { display:flex; gap:.75rem; }
  button { font:inherit; padding:.5rem 1.4rem; border-radius:6px; border:1px solid var(--line);
           cursor:pointer; color:#fff; }
  .approve { background:var(--green); border-color:var(--green); }
  .decline { background:transparent; color:var(--red); border-color:var(--red); }
  .empty { color:var(--dim); border:1px dashed var(--line); border-radius:8px;
           padding:2rem; max-width:34rem; text-align:center; }
  #log { margin-top:2rem; color:var(--dim); font-size:.8rem; max-width:34rem; }
  #log .ok { color:var(--green); }  #log .no { color:var(--red); }
</style>
</head>
<body>
<h1><b>SecondSign</b> · approver panel</h1>
<div id="status">connecting…</div>
<div id="reviews"></div>
<div id="log"></div>
<script>
const money = (minor, ccy) =>
  (minor / 100).toLocaleString("en-US", {style:"currency", currency:ccy});
const short = fp => fp.slice(0, 12) + "…";

async function refresh() {
  try {
    const res = await fetch("/api/reviews");
    const data = await res.json();
    if (!res.ok) throw new Error(JSON.stringify(data));
    document.getElementById("status").textContent =
      data.reviews.length + " open review(s) — refreshes every 2s";
    const box = document.getElementById("reviews");
    if (!data.reviews.length) {
      box.innerHTML = '<div class="empty">Nothing waiting for you.</div>';
      return;
    }
    box.innerHTML = data.reviews.map(r => `
      <div class="review">
        <div class="amount">${money(r.amount_minor, r.currency)}
          <span style="color:var(--amber)">· held for review</span></div>
        <div class="meta">
          ${r.action} over ${r.rail} · to ${short(r.counterparty_ref)}<br>
          proposed by ${short(r.principal_ref)} · expires ${r.expires_at ?? "—"}<br>
          proposal ${short(r.proposal)}
        </div>
        <div class="row">
          <button class="approve"
            onclick="answer('${r.approval_id}','${r.proposal}','approve')">Approve</button>
          <button class="decline"
            onclick="answer('${r.approval_id}','${r.proposal}','decline')">Decline</button>
        </div>
      </div>`).join("");
  } catch (e) {
    document.getElementById("status").textContent = "channel unreachable: " + e;
  }
}

async function answer(approval_id, proposal, verdict) {
  const res = await fetch("/api/answer", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({approval_id, proposal, answer: verdict}),
  });
  const data = await res.json();
  const line = document.createElement("div");
  const ok = data.status === "executed";
  line.className = ok ? "ok" : "no";
  line.textContent = `${new Date().toLocaleTimeString()} — ${verdict}d ${short(approval_id)} → ` +
    `${data.status}${data.reason ? " (" + data.reason + ")" : ""}`;
  document.getElementById("log").prepend(line);
  refresh();
}

refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
"""


def _channel() -> HTTPSConnection:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # The listener's leaf names the compose service (`gateway`); the panel
    # dials the approvernet address. The CA pin below is the trust decision.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=CA)
    context.load_cert_chain(CERT, KEY)
    return HTTPSConnection(APPROVER_HOST, APPROVER_PORT, context=context, timeout=TIMEOUT_SECONDS)


def _proxy(method: str, path: str, body: bytes | None = None) -> tuple[int, dict[str, object]]:
    connection = _channel()
    try:
        headers = {"Content-Type": "application/json"} if body is not None else {}
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


class _PanelHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _respond(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _respond_json(self, status: int, payload: dict[str, object]) -> None:
        self._respond(status, json.dumps(payload).encode(), "application/json")

    def do_GET(self) -> None:
        if self.path == "/":
            self._respond(200, PAGE.encode(), "text/html; charset=utf-8")
        elif self.path == "/api/reviews":
            try:
                status, payload = _proxy("GET", "/reviews")
            except OSError as exc:
                self._respond_json(502, {"error": str(exc)})
                return
            self._respond_json(status, payload)
        else:
            self._respond_json(404, {"error": "unknown path"})

    def do_POST(self) -> None:
        if self.path != "/api/answer":
            self._respond_json(404, {"error": "unknown path"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(length))
            approval_id = str(request["approval_id"])
            body = json.dumps(
                {"answer": str(request["answer"]), "proposal": str(request["proposal"])}
            ).encode()
        except (ValueError, KeyError):
            self._respond_json(400, {"error": "malformed request"})
            return
        try:
            status, payload = _proxy("POST", f"/reviews/{approval_id}", body=body)
        except OSError as exc:
            self._respond_json(502, {"error": str(exc)})
            return
        self._respond_json(status, payload)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 — base signature
        pass


def main() -> int:
    server = ThreadingHTTPServer(("0.0.0.0", PANEL_PORT), _PanelHandler)  # noqa: S104 — inside the demo container; the host mapping in compose.demo.yaml is loopback-only
    print(f"approver panel on :{PANEL_PORT}, channel {APPROVER_HOST}:{APPROVER_PORT}", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        return 130
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
