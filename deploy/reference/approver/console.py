# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The approver's console: list held reviews and answer one. Standard library.

    python /approver/console.py list  <host> <port>
    python /approver/console.py answer <host> <port> <approve|decline> <approval_id> <proposal>

Deliberately as small as the wire it speaks. What a real deployment puts here
is a UI; what the *channel* requires is only this: a client certificate under
the approver CA, the digest of what was displayed restated in the answer, and
nothing in the body claiming who is asking — identity is the certificate's job.

Output is one JSON document on stdout, so the deployment suite reads verdicts
rather than scraping text.
"""

from __future__ import annotations

import http.client
import json
import ssl
import sys

CERT = "/etc/secondsign/tls/client-cert.pem"
KEY = "/etc/secondsign/tls/client-key.pem"
CA = "/etc/secondsign/tls/approver-ca-cert.pem"

TIMEOUT_SECONDS = 10.0


def _context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # The listener's leaf names the compose service (`gateway`); the console
    # dials the approvernet address. The CA pin below is the trust decision.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=CA)
    context.load_cert_chain(CERT, KEY)
    return context


def _request(host: str, port: int, method: str, path: str, body: bytes | None = None):
    connection = http.client.HTTPSConnection(
        host, port, context=_context(), timeout=TIMEOUT_SECONDS
    )
    try:
        headers = {"Content-Type": "application/json"} if body is not None else {}
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def main(argv: list[str]) -> int:
    if len(argv) >= 4 and argv[1] == "list":
        status, payload = _request(argv[2], int(argv[3]), "GET", "/reviews")
    elif len(argv) == 7 and argv[1] == "answer" and argv[4] in ("approve", "decline"):
        body = json.dumps({"answer": argv[4], "proposal": argv[6]}).encode()
        status, payload = _request(argv[2], int(argv[3]), "POST", f"/reviews/{argv[5]}", body=body)
    else:
        print(json.dumps({"error": "usage", "detail": __doc__.splitlines()[2].strip()}))
        return 2
    print(json.dumps({"http_status": status, "body": payload}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
