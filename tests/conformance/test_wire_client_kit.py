# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The wire conformance kit must certify a good client and reject a bad one.

A kit that passes everything certifies nothing, so most of this file is
deliberately non-conformant clients that the kit is required to catch. Each one
breaks exactly one promise and is paired with the check that must notice.

The conformant candidate is `secondsign_client` itself, driven through the same
adapter a third party writes. That is the point of the exercise: the reference
client gets no privileged route through the kit, so a change that made it
non-conformant fails here rather than redefining conformance.

The non-conformant candidates are written against `http.client` rather than
against the reference client, because a candidate that could only send what the
reference client sends could not be non-conformant in the first place.
"""

from __future__ import annotations

import http.client
import json

import pytest
from secondsign_client.transport import GatewayClient
from secondsign_client.wire import AuthorizationRequest as ClientRequest

from secondsign.agent.wire import WIRE_VERSION
from secondsign.conformance import ProbeGateway, WireClientConformance
from secondsign.conformance.wire_client import CERTIFICATION_REQUEST


def _post(host: str, port: int, envelope: dict[str, object], path: str = "/authorize") -> bytes:
    """The bare minimum a candidate does: POST a JSON envelope, read the body."""
    connection = http.client.HTTPConnection(host, port, timeout=5.0)
    try:
        connection.request(
            "POST",
            path,
            body=json.dumps(envelope).encode(),
            headers={"Content-Type": "application/json"},
        )
        return connection.getresponse().read()
    finally:
        connection.close()


def _envelope(**overrides: object) -> dict[str, object]:
    envelope: dict[str, object] = {
        "wire_version": WIRE_VERSION,
        "request": dict(CERTIFICATION_REQUEST),
    }
    envelope.update(overrides)
    return envelope


# --- the conformant candidate ------------------------------------------------


class TestTheReferenceClient(WireClientConformance):
    """Exactly what a third party writes to certify their own client.

    Three lines of adapter, no test framework, no knowledge of the kit: build
    the request, ask, report the status.
    """

    def attempt(self, host: str, port: int, request: dict[str, object]) -> str:
        client = GatewayClient(host=host, port=port)
        return client.request_authorization(ClientRequest(**request)).status.value


# --- the kit must reject these -----------------------------------------------


class AnswersWithoutAsking(WireClientConformance):
    """Decides locally. The gateway is never told a payment was proposed."""

    def attempt(self, host, port, request):
        return "completed"


class PostsToTheWrongPath(WireClientConformance):
    def attempt(self, host, port, request):
        _post(host, port, _envelope(), path="/authorise")
        return "refused"


class AddsAFieldToTheEnvelope(WireClientConformance):
    def attempt(self, host, port, request):
        _post(host, port, _envelope(trace_note="retry after timeout"))
        return "refused"


class AnnouncesTheVersionAsAString(WireClientConformance):
    def attempt(self, host, port, request):
        _post(host, port, _envelope(wire_version=str(WIRE_VERSION)))
        return "refused"


class AnnouncesTheVersionAsTrue(WireClientConformance):
    """`true` is not version one; it is a serializer that lost the type."""

    def attempt(self, host, port, request):
        _post(host, port, _envelope(wire_version=True))
        return "refused"


class SpeaksAnUnknownDialect(WireClientConformance):
    def attempt(self, host, port, request):
        _post(host, port, _envelope(wire_version=WIRE_VERSION + 1))
        return "refused"


class RoundsTheAmount(WireClientConformance):
    """Sends money as a float — the one representation this boundary forbids."""

    def attempt(self, host, port, request):
        proposal = dict(request) | {"amount_minor": float(request["amount_minor"]) + 0.5}
        _post(host, port, _envelope(request=proposal))
        return "refused"


class SendsARawIdentifier(WireClientConformance):
    """A well-formed envelope carrying an account number where a fingerprint
    belongs — the A5 leak the closed field types exist to make impossible."""

    def attempt(self, host, port, request):
        proposal = dict(request) | {"counterparty_ref": "acct_4111111111111111"}
        _post(host, port, _envelope(request=proposal))
        return "refused"


class RestatesTheAmount(WireClientConformance):
    """Sends a well-formed proposal that is not the one it was handed."""

    def attempt(self, host, port, request):
        _post(host, port, _envelope(request=dict(request) | {"amount_minor": 1}))
        return "refused"


class SmugglesAPrincipalInTheEnvelope(WireClientConformance):
    def attempt(self, host, port, request):
        _post(host, port, _envelope(principal="spiffe://example/workload/treasury-agent"))
        return "refused"


class SmugglesAPrincipalInTheProposal(WireClientConformance):
    """The same claim in a different pocket."""

    def attempt(self, host, port, request):
        proposal = dict(request) | {"client_principal": "spiffe://example/workload/treasury"}
        _post(host, port, _envelope(request=proposal))
        return "refused"


class DowngradesEveryAnswer(WireClientConformance):
    """Asks properly, then throws the answer away. Refusing everything is as
    much an invented verdict as completing everything."""

    def attempt(self, host, port, request):
        _post(host, port, _envelope())
        return "refused"


class BestEffortParsesAForeignDialect(WireClientConformance):
    """Reads a verdict out of a response whose dialect it does not speak."""

    def attempt(self, host, port, request):
        return str(json.loads(_post(host, port, _envelope()))["outcome"]["status"])


class AlwaysCompleted(WireClientConformance):
    """Whatever came back — a decline, garbage, nothing at all — reads as money
    moved."""

    def attempt(self, host, port, request):
        try:
            _post(host, port, _envelope())
        except OSError:
            pass
        return "completed"


class ReportsItsOwnVocabulary(WireClientConformance):
    def attempt(self, host, port, request):
        _post(host, port, _envelope())
        return "gateway_error"


class SendsSomethingOtherThanJSON(WireClientConformance):
    def attempt(self, host, port, request):
        connection = http.client.HTTPConnection(host, port, timeout=5.0)
        try:
            connection.request("POST", "/authorize", body=b"amount=4200&action=payment")
            connection.getresponse().read()
        finally:
            connection.close()
        return "refused"


class SendsAJSONArray(WireClientConformance):
    def attempt(self, host, port, request):
        connection = http.client.HTTPConnection(host, port, timeout=5.0)
        try:
            connection.request("POST", "/authorize", body=json.dumps([WIRE_VERSION]).encode())
            connection.getresponse().read()
        finally:
            connection.close()
        return "refused"


class OmitsTheProposal(WireClientConformance):
    def attempt(self, host, port, request):
        connection = http.client.HTTPConnection(host, port, timeout=5.0)
        try:
            connection.request(
                "POST", "/authorize", body=json.dumps({"wire_version": WIRE_VERSION}).encode()
            )
            connection.getresponse().read()
        finally:
            connection.close()
        return "refused"


class SendsTheProposalAsAString(WireClientConformance):
    def attempt(self, host, port, request):
        _post(host, port, _envelope(request=json.dumps(request)))
        return "refused"


class AsksTwice(WireClientConformance):
    """Two proposals for one intent. Whether they are the same proposal is now
    the gateway's problem, and the agent cannot tell which one was decided."""

    def attempt(self, host, port, request):
        _post(host, port, _envelope())
        _post(host, port, _envelope())
        return "completed"


@pytest.mark.parametrize(
    ("candidate", "method"),
    [
        (AnswersWithoutAsking, "test_asks_the_gateway_before_answering"),
        (AsksTwice, "test_asks_the_gateway_before_answering"),
        (PostsToTheWrongPath, "test_posts_the_envelope_to_the_authorize_path"),
        (AddsAFieldToTheEnvelope, "test_the_envelope_carries_the_version_and_the_request_only"),
        (OmitsTheProposal, "test_the_envelope_carries_the_version_and_the_request_only"),
        (SendsSomethingOtherThanJSON, "test_the_envelope_carries_the_version_and_the_request_only"),
        (SendsAJSONArray, "test_the_envelope_carries_the_version_and_the_request_only"),
        (AnnouncesTheVersionAsAString, "test_announces_a_wire_version_this_contract_defines"),
        (AnnouncesTheVersionAsTrue, "test_announces_a_wire_version_this_contract_defines"),
        (SpeaksAnUnknownDialect, "test_announces_a_wire_version_this_contract_defines"),
        (RoundsTheAmount, "test_the_request_is_the_closed_agent_surface"),
        (SendsARawIdentifier, "test_the_request_is_the_closed_agent_surface"),
        (SendsTheProposalAsAString, "test_the_request_is_the_closed_agent_surface"),
        (RestatesTheAmount, "test_the_request_is_the_one_it_was_handed"),
        (SmugglesAPrincipalInTheEnvelope, "test_carries_no_principal_in_either_pocket"),
        (SmugglesAPrincipalInTheProposal, "test_carries_no_principal_in_either_pocket"),
        (DowngradesEveryAnswer, "test_relays_the_gateway_answer_unchanged"),
        (AlwaysCompleted, "test_a_gateway_that_declines_reads_as_refused"),
        (AlwaysCompleted, "test_an_unparseable_answer_is_refused"),
        (AlwaysCompleted, "test_an_unknown_status_is_refused"),
        (BestEffortParsesAForeignDialect, "test_a_foreign_dialect_is_refused_rather_than_parsed"),
        (AlwaysCompleted, "test_an_unreachable_gateway_yields_refused_not_a_verdict"),
        (ReportsItsOwnVocabulary, "test_every_answer_is_in_the_closed_vocabulary"),
    ],
    ids=[
        "answers-without-asking",
        "asks-twice",
        "wrong-path",
        "extra-envelope-field",
        "no-proposal",
        "not-json",
        "json-array",
        "version-as-string",
        "version-as-true",
        "unknown-dialect",
        "amount-as-float",
        "raw-identifier",
        "proposal-as-string",
        "restates-the-amount",
        "principal-in-envelope",
        "principal-in-proposal",
        "downgrades-every-answer",
        "decline-read-as-completed",
        "garbage-read-as-completed",
        "unknown-status-read-as-completed",
        "best-effort-foreign-dialect",
        "unreachable-read-as-completed",
        "own-vocabulary",
    ],
)
def test_kit_rejects_non_conformant_clients(candidate, method) -> None:
    with pytest.raises(AssertionError):
        getattr(candidate(), method)()


def test_kit_refuses_to_certify_nothing() -> None:
    """Forgetting to override `attempt` must fail loudly, not pass vacuously."""
    with pytest.raises(AssertionError, match="must override `attempt`"):
        WireClientConformance().test_asks_the_gateway_before_answering()


def test_the_certification_request_is_a_valid_proposal() -> None:
    """The proposal the kit hands out is not itself malformed — a kit that
    handed candidates an invalid request would be certifying error handling."""
    assert ClientRequest(**CERTIFICATION_REQUEST)


class TestTheProbeGatewayIsHonest:
    """The probe is the kit's instrument, so its own behaviour is asserted here
    rather than assumed. An instrument that recorded nothing would make every
    request-side check pass."""

    def test_it_records_what_it_received(self) -> None:
        with ProbeGateway() as probe:
            host, port = probe.address
            _post(host, port, _envelope())
        assert len(probe.received) == 1
        recorded = probe.received[0]
        assert recorded.method == "POST"
        assert recorded.path == "/authorize"
        assert json.loads(recorded.body)["wire_version"] == WIRE_VERSION

    def test_it_answers_exactly_what_it_was_scripted_to(self) -> None:
        with ProbeGateway() as probe:
            probe.script(status_code=503, body=b'{"refused": "authorization_unavailable"}')
            host, port = probe.address
            body = _post(host, port, _envelope())
        assert json.loads(body) == {"refused": "authorization_unavailable"}

    def test_it_validates_nothing(self) -> None:
        """A probe that rejected a malformed request would reject the candidate
        before the kit could say what was wrong with it."""
        with ProbeGateway() as probe:
            host, port = probe.address
            _post(host, port, {"nonsense": True})
        assert len(probe.received) == 1

    def test_a_stopped_probe_leaves_nothing_listening(self) -> None:
        with ProbeGateway() as probe:
            host, port = probe.address
        with pytest.raises(OSError):
            _post(host, port, _envelope())
