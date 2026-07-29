# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The client on the wire: every failure is `refused`, and nothing is decided
locally.

ADR 0003's consequence, tested: the gateway being unreachable is a new failure
mode, and the client resolves it to `refused` — never to a locally computed
verdict, because an agent that can distinguish "no" from "we could not tell"
can retry against the second one (INV-1). `completed` has exactly one origin: a
well-formed, correctly versioned response from the gateway. Every other path —
nothing listening, a refused handshake, a declining gateway, a malformed body,
a dialect this client does not speak — collapses to the same word the agent
cannot argue with.

The happy-path case at the end is the vacuity guard: a fake gateway that *does*
answer well-formed `completed` proves the parse path works, so the refusals
above it are decisions rather than accidents.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from secondsign_client import GatewayClient, wire
from secondsign_client.transport import TransportRefusal, TransportRefusalReason

from tests.client.test_wire_contract import FINGERPRINT, make_wire_request


def _mtls_client(pki, address) -> GatewayClient:
    # Dial by the name the gateway's certificate carries: the client verifies
    # the server's name and deliberately has no way not to.
    _, port = address
    return GatewayClient(
        "localhost",
        port,
        ca_file=str(pki["ca_cert"]),
        client_cert=str(pki["client_cert"]),
        client_key=str(pki["client_key"]),
        timeout=3.0,
    )


def assert_refused(outcome: object, reason: TransportRefusalReason) -> None:
    assert isinstance(outcome, TransportRefusal), f"expected a refusal, got {outcome!r}"
    assert outcome.status is wire.AgentOutcomeStatus.refused
    assert outcome.reason is reason


class TestAgainstTheRealGateway:
    """The genuine `secondsign.gateway.server`, mTLS on loopback."""

    def test_a_declining_gateway_reads_as_refused(self, gateway, pki) -> None:
        """The gateway cannot authorize yet (503, `authorization_unavailable`);
        the client renders that as refused, not as an error the agent might
        treat as retry-until-yes."""
        outcome = _mtls_client(pki, gateway).request_authorization(make_wire_request())

        assert_refused(outcome, TransportRefusalReason.gateway_declined)

    def test_a_name_the_certificate_does_not_carry_reads_as_refused(self, gateway, pki) -> None:
        """The gateway's leaf names `localhost`; dialling the same listener by
        `127.0.0.1` fails server-name verification. The client has no knob to
        skip that check, so the failure surfaces as a refusal — not as an
        option to configure away."""
        _, port = gateway
        client = GatewayClient(
            "127.0.0.1",
            port,
            ca_file=str(pki["ca_cert"]),
            client_cert=str(pki["client_cert"]),
            client_key=str(pki["client_key"]),
            timeout=3.0,
        )

        outcome = client.request_authorization(make_wire_request())

        assert_refused(outcome, TransportRefusalReason.tls_rejected)

    def test_plaintext_to_the_tls_port_reads_as_refused(self, gateway) -> None:
        host, port = gateway

        outcome = GatewayClient(host, port, timeout=3.0).request_authorization(make_wire_request())

        assert outcome.status is wire.AgentOutcomeStatus.refused


class TestWithTheGatewayGone:
    """The falsification test, client-side: off means no."""

    def test_nothing_listening_reads_as_refused(self, unused_loopback_port) -> None:
        client = GatewayClient("127.0.0.1", unused_loopback_port, timeout=2.0)

        outcome = client.request_authorization(make_wire_request())

        assert_refused(outcome, TransportRefusalReason.gateway_unreachable)

    def test_no_code_path_in_the_client_utters_completed(self) -> None:
        """`completed` enters a client process by parsing a gateway response,
        and no other way. The behavioural cases above show every failure
        reading as refused; this pins the stronger structural fact — the
        transport source never names the word, so a future error branch cannot
        quietly return it."""
        from tests.client.conftest import CLIENT_DIR

        source = (CLIENT_DIR / "src" / "secondsign_client" / "transport.py").read_text()

        assert "completed" not in source, (
            "transport.py names `completed`; the only origin of that status is a "
            "parsed gateway response, and naming it in transport code is how a "
            "fallback branch starts producing it"
        )


@pytest.fixture()
def unused_loopback_port() -> int:
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture()
def scripted_gateway():
    """A plaintext loopback impostor that answers whatever the test scripts.

    Plaintext is fine here — the client permits it on literal loopback only,
    mirroring the gateway's own rule — and these cases are about response
    handling, not the handshake, which the real-gateway cases cover.
    """
    started: list[ThreadingHTTPServer] = []
    threads: list[threading.Thread] = []

    def start(status: int, body: bytes) -> tuple[str, int]:
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        started.append(server)
        threads.append(thread)
        return server.server_address[0], server.server_address[1]

    yield start
    for server in started:
        server.shutdown()
        server.server_close()
    for thread in threads:
        thread.join(timeout=5)


def _outcome_payload(status: str = "completed") -> dict:
    return {
        "wire_version": wire.WIRE_VERSION,
        "outcome": {
            "status": status,
            "decision_ref": FINGERPRINT,
            "decided_at": "2026-07-28T12:00:00+00:00",
            "reasons": [],
        },
    }


class TestResponseHandling:
    def test_an_unrecognised_response_version_reads_as_refused(self, scripted_gateway) -> None:
        """Refused rather than best-effort parsed: a peer speaking a different
        dialect may mean something different by every word in it."""
        payload = _outcome_payload()
        payload["wire_version"] = 99
        address = scripted_gateway(200, json.dumps(payload).encode())

        outcome = GatewayClient(*address, timeout=2.0).request_authorization(make_wire_request())

        assert_refused(outcome, TransportRefusalReason.malformed_response)

    def test_a_malformed_response_reads_as_refused(self, scripted_gateway) -> None:
        address = scripted_gateway(200, b"<html>proxy error</html>")

        outcome = GatewayClient(*address, timeout=2.0).request_authorization(make_wire_request())

        assert_refused(outcome, TransportRefusalReason.malformed_response)

    def test_a_5xx_reads_as_refused(self, scripted_gateway) -> None:
        address = scripted_gateway(500, b'{"anything": true}')

        outcome = GatewayClient(*address, timeout=2.0).request_authorization(make_wire_request())

        assert_refused(outcome, TransportRefusalReason.gateway_declined)

    def test_a_well_formed_outcome_parses(self, scripted_gateway) -> None:
        """The vacuity guard: the one legitimate origin of `completed` works,
        so every refusal above is a decision, not a broken parser."""
        address = scripted_gateway(200, json.dumps(_outcome_payload()).encode())

        outcome = GatewayClient(*address, timeout=2.0).request_authorization(make_wire_request())

        assert isinstance(outcome, wire.AuthorizationOutcome)
        assert outcome.status is wire.AgentOutcomeStatus.completed
        assert outcome.decision_ref == FINGERPRINT

    def test_awaiting_review_parses_too(self, scripted_gateway) -> None:
        address = scripted_gateway(200, json.dumps(_outcome_payload("awaiting_review")).encode())

        outcome = GatewayClient(*address, timeout=2.0).request_authorization(make_wire_request())

        assert isinstance(outcome, wire.AuthorizationOutcome)
        assert outcome.status is wire.AgentOutcomeStatus.awaiting_review


class TestTheClientRefusesUnsafeConfiguration:
    def test_plaintext_off_loopback_is_not_constructible(self) -> None:
        """The client mirrors the gateway's rule: off loopback, mTLS or
        nothing. A client that would POST an authorization request in the
        clear across a network is a client that leaks proposals and invites
        replay."""
        with pytest.raises(ValueError, match="loopback"):
            GatewayClient("203.0.113.9", 8787)

    def test_a_hostname_counts_as_off_loopback(self) -> None:
        with pytest.raises(ValueError, match="loopback"):
            GatewayClient("localhost", 8787)

    def test_partial_tls_is_not_constructible(self, pki) -> None:
        with pytest.raises(ValueError, match="client_cert"):
            GatewayClient("203.0.113.9", 8787, ca_file=str(pki["ca_cert"]))
