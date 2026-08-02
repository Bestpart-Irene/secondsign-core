# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The smallest client that passes the wire conformance kit.

Standard library only — `http.client` and `json` — because the agent side is
supposed to be thin, and an example that pulled in a framework would argue
against the thing it demonstrates. A client in another language is this file
translated, not extended.

The dialect constants are imported from `secondsign.agent.wire`, the one place
core declares them. They are not re-spelled here: a copy that drifts is worse
than no example.

The shape worth studying is the error handling, because it is the contract:
**every path that is not a well-formed answer from a peer speaking this
dialect returns** ``refused``. Not an exception — an exception is not a verdict
an agent can branch on. Not a guess — a client that turns "we could not tell"
into ``completed`` has authorized something the control plane never decided,
and one that turns it into a retry loop against ambiguity has made the
gateway's idempotency its own problem. One request, one status, and every
failure mode collapses to the same word the gateway itself uses when it
declines (INV-1).
"""

from __future__ import annotations

import http.client
import json

from secondsign.agent.surface import AgentOutcomeStatus
from secondsign.agent.wire import SUPPORTED_WIRE_VERSIONS, WIRE_VERSION

_REFUSED = AgentOutcomeStatus.refused.value
_VOCABULARY = frozenset(status.value for status in AgentOutcomeStatus)


class MinimalWireClient:
    """One verb: propose, and report what the gateway said."""

    def __init__(self, host: str, port: int, timeout: float = 5.0) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout

    def authorize(self, request: dict[str, object]) -> str:
        """POST the proposal, return ``completed`` / ``awaiting_review`` / ``refused``."""
        envelope = json.dumps({"wire_version": WIRE_VERSION, "request": dict(request)})
        try:
            connection = http.client.HTTPConnection(self._host, self._port, timeout=self._timeout)
            try:
                connection.request(
                    "POST",
                    "/authorize",
                    body=envelope.encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                )
                response = connection.getresponse()
                status_code = response.status
                raw = response.read()
            finally:
                connection.close()
        except OSError:
            # Nothing listening, timeout, connection reset: a verdict reached
            # without the gateway would be a verdict the gateway did not make.
            return _REFUSED

        if status_code != 200:
            return _REFUSED
        return self._read_answer(raw)

    @staticmethod
    def _read_answer(raw: bytes) -> str:
        try:
            answer = json.loads(raw)
        except ValueError:
            return _REFUSED  # something answered, and it was not this contract
        if not isinstance(answer, dict):
            return _REFUSED
        if answer.get("wire_version") not in SUPPORTED_WIRE_VERSIONS:
            # A peer speaking a different dialect may mean something different
            # by every word in it, including `refused`.
            return _REFUSED
        outcome = answer.get("outcome")
        if not isinstance(outcome, dict):
            return _REFUSED
        status = outcome.get("status")
        if status not in _VOCABULARY:
            return _REFUSED  # three states exist; there is no fourth for uncertainty
        return str(status)
