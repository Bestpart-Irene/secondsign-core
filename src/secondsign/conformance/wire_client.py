# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Conformance suite for agent-side clients speaking the wire contract.

A client proves it is safe to put in front of a gateway by inheriting from
:class:`WireClientConformance`, naming the subclass ``Test...``, overriding
``attempt``, and running its own test suite:

.. code-block:: python

    from secondsign.conformance import WireClientConformance
    from my_package import MyClient


    class TestMyClient(WireClientConformance):
        def attempt(self, host, port, request):
            client = MyClient(host=host, port=port)
            return client.authorize(**request).status

The adapter is deliberately the whole of the integration: three arguments in, a
status string out. Nothing about the candidate's API is prescribed, because the
contract being certified is the *wire* — the bytes it sends and how it reads
what comes back — and a kit that required a particular Python shape would be
certifying an implementation rather than a protocol.

What this kit certifies, and why each part is a security property rather than a
convention:

- **It asks.** A client that answers without a request has authorized something
  the control plane never saw. Every other property is downstream of this one.
- **It sends the closed proposal, unaltered.** The envelope carries the dialect
  and the proposal and nothing else; the proposal validates against
  :class:`secondsign.agent.surface.AuthorizationRequest`, whose fields are closed
  enums, integer minor units and opaque fingerprints — so a raw account
  identifier is not representable rather than merely discouraged (A5). The value
  the agent proposed is the value the gateway receives.
- **It carries no identity.** Identity is derived from the authenticated peer.
  A principal in the body is a claim the sender wrote about itself, and the
  gateway refuses it rather than ignoring it — so a client that sends one is
  building against a field that will never be honoured (ADR 0004 §1).
- **It refuses rather than guesses.** An unrecognised dialect, an unparseable
  answer, a status this contract does not define, a gateway that declines, a
  gateway that is not there — every one of them reads as ``refused``, and never
  as a locally computed verdict. An agent that can distinguish "no" from "we
  could not tell" can retry against the second one (INV-1), so gateway
  availability is allowed to become payment availability and is never softened
  here.
- **It relays what it is told.** Refusing everything is as much an invented
  verdict as completing everything: a client that never returns the gateway's
  answer has replaced the decision with its own.

The kit stands up its own :class:`ProbeGateway` — a scriptable stand-in on
loopback, in-process — rather than the real gateway, because half of what a
client must survive is a *malformed* answer, and the real gateway cannot be
asked to produce one. The probe records what it received, so the request-side
checks read the candidate's actual bytes instead of trusting its documentation.

Like the other kits, this imports no test framework; the methods are plain
assertions pytest collects from the subclass.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import TracebackType
from typing import Final, cast

from pydantic import ValidationError

from secondsign.agent.surface import AgentOutcomeStatus, AuthorizationRequest
from secondsign.agent.wire import PRINCIPAL_FIELDS, SUPPORTED_WIRE_VERSIONS, WIRE_VERSION

#: The statuses an agent may be told. A client reporting anything else has
#: widened the vocabulary its agent branches on.
CLOSED_STATUS_VOCABULARY: Final[frozenset[str]] = frozenset(
    status.value for status in AgentOutcomeStatus
)

#: A dialect no peer speaks, derived rather than written down so it stays
#: unspoken when the contract is versioned.
UNSPOKEN_WIRE_VERSION: Final[int] = max(SUPPORTED_WIRE_VERSIONS) + 1

_FINGERPRINT: Final[str] = "fp:" + "ab" * 32

#: The proposal every candidate is handed. Plain JSON values, not model
#: instances: a candidate may be built on anything, and handing it a pydantic
#: object would smuggle this repository's types into the certification.
CERTIFICATION_REQUEST: Final[dict[str, object]] = {
    "action": "payment",
    "rail": "card",
    "currency": "USD",
    "amount_minor": 4_200,
    "reversibility": "irreversible",
    "counterparty_ref": "fp:" + "cd" * 32,
    "source_account_ref": "fp:" + "ef" * 32,
    "request_ref": "fp:" + "12" * 32,
}


def certification_response(
    status: str = AgentOutcomeStatus.completed.value, wire_version: int = WIRE_VERSION
) -> bytes:
    """A response envelope the probe can be scripted with.

    ``status`` and ``wire_version`` are plain values rather than enum members on
    purpose: the kit has to be able to script answers that are *not* valid, and
    a typed constructor would refuse to build exactly the cases a client must
    survive.
    """
    return json.dumps(
        {
            "wire_version": wire_version,
            "outcome": {
                "status": status,
                "decision_ref": _FINGERPRINT,
                "decided_at": "2026-01-01T00:00:00+00:00",
                "reasons": [],
            },
        }
    ).encode()


#: The well-formed authorization the probe answers with unless scripted otherwise.
COMPLETED_RESPONSE: Final[bytes] = certification_response()


@dataclass(frozen=True)
class RecordedRequest:
    """What the probe actually received. Bytes, not an interpretation of them."""

    method: str
    path: str
    body: bytes


class _ProbeServer(ThreadingHTTPServer):
    """Holds the script and the record. One instance per attempt."""

    daemon_threads = True

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler]) -> None:
        super().__init__(address, handler)
        self.received: list[RecordedRequest] = []
        self.scripted: tuple[int, bytes] = (200, COMPLETED_RESPONSE)


class _ProbeHandler(BaseHTTPRequestHandler):
    """Records the request, answers the script. It parses nothing.

    Deliberately not a second implementation of the gateway: a probe that
    validated requests would reject a non-conformant candidate before the kit
    got to see what it sent, and the kit's whole job is to say what was wrong.
    """

    def do_POST(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler's dispatch name
        server = cast("_ProbeServer", self.server)
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        server.received.append(RecordedRequest(method=self.command, path=self.path, body=body))
        status_code, payload = server.scripted
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def version_string(self) -> str:
        return "secondsign-conformance-probe"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 — base signature
        """Silent. The request line is candidate-chosen bytes, and a test run is
        not a place to render them."""


@dataclass
class ProbeGateway:
    """A scriptable stand-in for a gateway, on loopback, in this process.

    Use it as a context manager; it binds an ephemeral port on entry and is
    listening for nothing by the time the block ends. Plaintext, because a
    conformance run on loopback is not carrying an authorization — mutual TLS is
    the deployment's concern and is asserted where it belongs, in the e2e and
    deployment suites.
    """

    _server: _ProbeServer = field(init=False)
    _thread: threading.Thread = field(init=False)

    def __post_init__(self) -> None:
        self._server = _ProbeServer(("127.0.0.1", 0), _ProbeHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> ProbeGateway:
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._server.shutdown()
        self._thread.join(timeout=5.0)
        self._server.server_close()

    @property
    def address(self) -> tuple[str, int]:
        """Host and port, valid once bound — which is before the block starts."""
        host, port = cast("tuple[str, int]", self._server.server_address)
        return host, port

    @property
    def received(self) -> tuple[RecordedRequest, ...]:
        return tuple(self._server.received)

    def script(self, *, status_code: int = 200, body: bytes = COMPLETED_RESPONSE) -> None:
        """What the next request is answered with. Arbitrary bytes on purpose."""
        self._server.scripted = (status_code, body)


class WireClientConformance:
    """Inherit, override ``attempt``, name the subclass ``Test...``."""

    def attempt(self, host: str, port: int, request: dict[str, object]) -> str:
        """Perform exactly one authorization attempt and report the status.

        Override this. ``request`` is the proposal as plain JSON values; the
        return value is the status string the client would hand its agent — one
        of ``completed``, ``refused`` or ``awaiting_review``. A candidate that
        raises instead of returning is not certified by this kit: an exception is
        not a verdict an agent can branch on, and the shape of the refusal is
        part of what makes availability failures unambiguous (INV-1).
        """
        raise AssertionError(
            f"{type(self).__name__} must override `attempt` with an adapter that "
            "drives the candidate client against the given host and port"
        )

    # --- machinery -----------------------------------------------------------

    def _ask(
        self, *, body: bytes = COMPLETED_RESPONSE, status_code: int = 200
    ) -> tuple[str, tuple[RecordedRequest, ...]]:
        """One attempt against a probe scripted to answer this way."""
        with ProbeGateway() as probe:
            probe.script(status_code=status_code, body=body)
            host, port = probe.address
            status = self.attempt(host, port, dict(CERTIFICATION_REQUEST))
        return status, probe.received

    def _sole_request(self, received: tuple[RecordedRequest, ...]) -> RecordedRequest:
        assert received, (
            "the client answered without sending anything — a verdict reached "
            "locally is a verdict the control plane never made"
        )
        assert len(received) == 1, (
            f"one proposal produced {len(received)} requests; a client that asks "
            "more than once has made the gateway's idempotency its own problem"
        )
        return received[0]

    def _sole_envelope(self, received: tuple[RecordedRequest, ...]) -> dict[str, object]:
        recorded = self._sole_request(received)
        try:
            envelope = json.loads(recorded.body)
        except ValueError as exc:
            raise AssertionError(
                "the client sent a body that is not JSON; the wire contract is a "
                "JSON envelope and a gateway will refuse anything else"
            ) from exc
        assert isinstance(envelope, dict), (
            "the client sent a JSON value that is not an object; the envelope "
            "carries a version and a proposal, and neither is optional"
        )
        return envelope

    def _sole_proposal(self, received: tuple[RecordedRequest, ...]) -> dict[str, object]:
        envelope = self._sole_envelope(received)
        assert "request" in envelope, "the envelope carries no `request`"
        proposal = envelope["request"]
        assert isinstance(proposal, dict), "the envelope's `request` is not an object"
        return proposal

    # --- what the client sends -----------------------------------------------

    def test_asks_the_gateway_before_answering(self) -> None:
        """The property every other one rests on."""
        _, received = self._ask()
        self._sole_request(received)

    def test_posts_the_envelope_to_the_authorize_path(self) -> None:
        recorded = self._sole_request(self._ask()[1])
        assert recorded.method == "POST", (
            f"the client used {recorded.method}; an authorization is a proposal "
            "that changes state and is not a safe method"
        )
        assert recorded.path == "/authorize", (
            f"the client posted to {recorded.path!r}; the gateway answers 404 on "
            "any other path, so this client can never be authorized at all"
        )

    def test_the_envelope_carries_the_version_and_the_request_only(self) -> None:
        envelope = self._sole_envelope(self._ask()[1])
        assert set(envelope) == {"wire_version", "request"}, (
            f"the envelope carries {sorted(envelope)}; the wire contract is "
            "closed, and a field the gateway does not define is either ignored — "
            "which teaches the client it was honoured — or refused"
        )

    def test_announces_a_wire_version_this_contract_defines(self) -> None:
        version = self._sole_envelope(self._ask()[1])["wire_version"]
        assert not isinstance(version, bool), (
            "the client announced a boolean version; `true` is not version one, "
            "it is a serializer and a parser disagreeing about what a version is"
        )
        assert isinstance(version, int), (
            f"the client announced {version!r}; the version is an integer, and a "
            "gateway that coerced the string would be best-effort parsing the "
            "one field that says how to parse everything else"
        )
        assert version in SUPPORTED_WIRE_VERSIONS, (
            f"the client announced wire version {version}, which this contract "
            f"does not define; supported: {sorted(SUPPORTED_WIRE_VERSIONS)}"
        )

    def test_the_request_is_the_closed_agent_surface(self) -> None:
        proposal = self._sole_proposal(self._ask()[1])
        amount = proposal.get("amount_minor")
        assert isinstance(amount, int) and not isinstance(amount, bool), (
            f"the client sent {amount!r} as the amount; money crosses this "
            "boundary as integer minor units, never as a float to be rounded "
            "somewhere downstream"
        )
        try:
            AuthorizationRequest.model_validate(proposal)
        except ValidationError as exc:
            raise AssertionError(
                f"the proposal is not a valid AuthorizationRequest: {exc}. The "
                "fields are closed enums, integer minor units and opaque "
                "fingerprints, so a raw account identifier is unrepresentable "
                "rather than merely discouraged"
            ) from exc

    def test_the_request_is_the_one_it_was_handed(self) -> None:
        proposal = self._sole_proposal(self._ask()[1])
        assert proposal == dict(CERTIFICATION_REQUEST), (
            "the client sent a proposal other than the one it was given; the "
            "value an agent proposes and the value the gateway decides on are "
            "the same value, or the decision is about something nobody asked for"
        )

    def test_carries_no_principal_in_either_pocket(self) -> None:
        envelope = self._sole_envelope(self._ask()[1])
        proposal = self._sole_proposal(self._ask()[1])
        for name in PRINCIPAL_FIELDS:
            assert name not in envelope, (
                f"the envelope carries {name!r}; identity comes from the "
                "authenticated peer, and a principal in the body is a claim the "
                "sender wrote about itself — the gateway refuses it, so a client "
                "that sends one is building against a field never honoured"
            )
            assert name not in proposal, (
                f"the proposal carries {name!r}; the same claim in a different "
                "pocket is the same claim, and is refused in both"
            )

    # --- how the client reads the answer -------------------------------------

    def test_relays_the_gateway_answer_unchanged(self) -> None:
        for decided in (AgentOutcomeStatus.completed, AgentOutcomeStatus.awaiting_review):
            status, _ = self._ask(body=certification_response(status=decided.value))
            assert status == decided.value, (
                f"the gateway answered {decided.value!r} and the client reported "
                f"{status!r}; a client that does not relay the answer has "
                "replaced the decision with one of its own"
            )

    def test_a_gateway_that_declines_reads_as_refused(self) -> None:
        status, _ = self._ask(status_code=503, body=b'{"refused": "authorization_unavailable"}')
        assert status == AgentOutcomeStatus.refused.value, (
            f"the gateway declined and the client reported {status!r}; a gateway "
            "that cannot authorize has not authorized"
        )

    def test_an_unparseable_answer_is_refused(self) -> None:
        status, _ = self._ask(body=b"<html><body>504 Gateway Timeout</body></html>")
        assert status == AgentOutcomeStatus.refused.value, (
            f"an unparseable answer read as {status!r}; something answered, and "
            "what answered was demonstrably not this contract"
        )

    def test_an_unknown_status_is_refused(self) -> None:
        status, _ = self._ask(body=certification_response(status="authorized"))
        assert status == AgentOutcomeStatus.refused.value, (
            f"a status outside the contract read as {status!r}; three states "
            "exist and there is no fourth for uncertainty"
        )

    def test_a_foreign_dialect_is_refused_rather_than_parsed(self) -> None:
        status, _ = self._ask(body=certification_response(wire_version=UNSPOKEN_WIRE_VERSION))
        assert status == AgentOutcomeStatus.refused.value, (
            f"a response announcing wire version {UNSPOKEN_WIRE_VERSION} read as "
            f"{status!r}; a peer speaking a different dialect may mean something "
            "different by every word in it, including this one"
        )

    def test_an_unreachable_gateway_yields_refused_not_a_verdict(self) -> None:
        """The case the whole no-bypass claim rests on: stop the gateway and
        authorization becomes impossible, not merely unattested."""
        with ProbeGateway() as probe:
            host, port = probe.address
        status = self.attempt(host, port, dict(CERTIFICATION_REQUEST))
        assert status == AgentOutcomeStatus.refused.value, (
            f"with nothing listening the client reported {status!r}; a verdict "
            "reached without the gateway is a verdict the gateway did not make"
        )

    def test_every_answer_is_in_the_closed_vocabulary(self) -> None:
        answers = (
            self._ask()[0],
            self._ask(status_code=503, body=b'{"refused": "unavailable"}')[0],
            self._ask(body=b"not json at all")[0],
        )
        for answer in answers:
            assert answer in CLOSED_STATUS_VOCABULARY, (
                f"the client reported {answer!r}; an agent branches on this "
                f"string, and the vocabulary is {sorted(CLOSED_STATUS_VOCABULARY)}"
            )
