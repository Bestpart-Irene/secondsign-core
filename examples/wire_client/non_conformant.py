# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Two clients the kit must refuse to certify, each breaking one promise.

Reading these beside `minimal_client.py` is the point of the example: each is
the minimal client with one check *removed*, which is exactly how real
non-conformance happens — not by malice, but by a client that "works in
testing" because nothing malformed ever answered it there.
"""

from __future__ import annotations

from examples.wire_client.minimal_client import _VOCABULARY, MinimalWireClient
from secondsign.agent.surface import AgentOutcomeStatus


class DialectBlindClient(MinimalWireClient):
    """Ignores the answer's ``wire_version`` — parses any dialect as its own.

    Feels harmless until the contract is versioned: a v2 peer may mean
    something different by every word, including ``refused``, and this client
    would relay v2 words with v1 meanings.
    """

    @staticmethod
    def _read_answer(raw: bytes) -> str:
        import json

        try:
            answer = json.loads(raw)
        except ValueError:
            return AgentOutcomeStatus.refused.value
        if not isinstance(answer, dict):
            return AgentOutcomeStatus.refused.value
        outcome = answer.get("outcome")
        if not isinstance(outcome, dict):  # the version check is gone — that is the defect
            return AgentOutcomeStatus.refused.value
        status = outcome.get("status")
        if status not in _VOCABULARY:
            return AgentOutcomeStatus.refused.value
        return str(status)


class OptimistClient(MinimalWireClient):
    """Treats an unparseable answer as success.

    The equivalent of `except: pass` on the one boundary where it costs money:
    an HTML error page from a proxy reads as an authorized payment.
    """

    @staticmethod
    def _read_answer(raw: bytes) -> str:
        conformant = MinimalWireClient._read_answer(raw)
        if conformant == AgentOutcomeStatus.refused.value:
            return AgentOutcomeStatus.completed.value  # "it probably worked"
        return conformant
