# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The approver channel over real mTLS, end to end (CORE-S023).

Two PKIs are stood up, and the fact that there are two is the test: the agent
channel's CA and the approver channel's CA are different roots, so "an
agent-channel credential is refused at the approver channel" is settled by the
handshake rather than by anything this module wrote. The review round-trip is
the acceptance criterion the slice exists for — a proposal parks, a checker
lists it, answers it, and the *agent's* next re-send of its own handle reads
`completed`, with the rail's ledger longer by exactly one.

The PKI is the reference deployment's own generator, run twice into two roots,
plus one approver leaf issued under the second root — same issuer code, same
SAN shape, so what this suite accepts and refuses is what the containerised
deployment accepts and refuses, minus Docker.
"""

from __future__ import annotations

import datetime as dt
import http.client
import importlib.util
import json
import ssl
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

from secondsign.agent.surface import AuthorizationRequest
from secondsign.audit import AuditLog, InMemoryAuditSink
from secondsign.contracts import Currency
from secondsign.controlplane.fingerprint import FingerprintKey
from secondsign.controlplane.window import WindowLedger
from secondsign.decision import DecisionEngine
from secondsign.gateway.approver import (
    ApproverConfig,
    ConfigurationRefusal,
    create_approver_server,
    load_approver_config,
)
from secondsign.gateway.authorization import AuthorizationService
from secondsign.gateway.execution import ExecutionGateway, InMemoryIdempotencyStore
from secondsign.policy import AmountLimit, AmountWindowPolicy
from secondsign.rails.http import HTTPRailExecutor
from tests.deployment.conftest import REFERENCE
from tests.e2e.conftest import NO_SERVICE

AGENT_PRINCIPAL = "spiffe://secondsign.example/agent/reference"
CHECKER_PRINCIPAL = "spiffe://secondsign.example/approver/reference"

#: Above this the reference limit holds the action for a human; the proposal
#: below is sized to land inside the band.
REVIEW_ABOVE = 200_00
CAP = 500_00
PROPOSAL_AMOUNT = 300_00


def _load_generator():
    path = REFERENCE / "tls" / "generate.py"
    spec = importlib.util.spec_from_file_location("secondsign_reference_pki_approver", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def pkis(tmp_path_factory) -> dict[str, Path]:
    """Two independent roots: the agent channel's PKI and the approver's.

    The approver's client leaf is issued under the second root with the checker
    URI SAN. The gateway-side certificate for the approver listener is the
    second root's own server leaf — the separation under test is the *client*
    trust anchor.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import ExtendedKeyUsageOID

    generator = _load_generator()
    agent_root = tmp_path_factory.mktemp("agent-pki")
    approver_root = tmp_path_factory.mktemp("approver-pki")
    generator.generate(root=agent_root)
    generator.generate(root=approver_root)

    ca_key = serialization.load_pem_private_key(
        (approver_root / "ca" / "ca-key.pem").read_bytes(), password=None
    )
    ca_cert = x509.load_pem_x509_certificate((approver_root / "ca" / "ca-cert.pem").read_bytes())
    checker_key, checker_cert = generator.build_leaf(
        common_name="reference-approver",
        san=x509.SubjectAlternativeName([x509.UniformResourceIdentifier(CHECKER_PRINCIPAL)]),
        eku=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
        ca_key=ca_key,
        ca_cert=ca_cert,
        now=dt.datetime.now(dt.timezone.utc).replace(tzinfo=None),
        lifetime=dt.timedelta(minutes=60),
    )
    (approver_root / "checker-key.pem").write_bytes(
        checker_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (approver_root / "checker-cert.pem").write_bytes(
        checker_cert.public_bytes(serialization.Encoding.PEM)
    )
    return {
        "listener_cert": approver_root / "gateway" / "gateway-cert.pem",
        "listener_key": approver_root / "gateway" / "gateway-key.pem",
        "approver_ca": approver_root / "gateway" / "ca-cert.pem",
        "checker_cert": approver_root / "checker-cert.pem",
        "checker_key": approver_root / "checker-key.pem",
        # The other door's material, for the cases that must be refused.
        "agent_ca": agent_root / "gateway" / "ca-cert.pem",
        "agent_client_cert": agent_root / "agent" / "client-cert.pem",
        "agent_client_key": agent_root / "agent" / "client-key.pem",
    }


class _RecordingRail:
    """A loopback rail that records each dispatch, one JSON line at a time."""

    def __init__(self) -> None:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        recorded: list[bytes] = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                recorded.append(body)
                payload = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                pass

        self.recorded = recorded
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


@pytest.fixture()
def stack(pkis):
    """The service with a review band, a recording rail, and the approver
    listener over the second PKI — fresh per test, because the trailing window
    is real state and one test's dispatch would deny the next test's proposal.
    The agent side is driven directly through `service.authorize` — its own
    listener is `test_gateway_process.py`'s subject, and standing it up again
    here would test the same thing twice."""
    rail = _RecordingRail()
    limit = AmountLimit(
        quote_currency=Currency.USD,
        window_seconds=3600,
        max_aggregate_minor=CAP,
        review_above_minor=REVIEW_ABOVE,
    )
    service = AuthorizationService(
        engine=DecisionEngine([AmountWindowPolicy(limit)]),
        gateway=ExecutionGateway(
            HTTPRailExecutor(rail.url, "sk_reference_not_a_real_key"),
            InMemoryIdempotencyStore(),
        ),
        ledger=WindowLedger(window_seconds=limit.window_seconds),
        audit=AuditLog(InMemoryAuditSink()),
        keys=FingerprintKey.generate(),
    )
    config = load_approver_config(
        {
            "SECONDSIGN_APPROVER_BIND": "127.0.0.1:0",
            "SECONDSIGN_APPROVER_TLS_CERT": str(pkis["listener_cert"]),
            "SECONDSIGN_APPROVER_TLS_KEY": str(pkis["listener_key"]),
            "SECONDSIGN_APPROVER_CA": str(pkis["approver_ca"]),
            "SECONDSIGN_APPROVER_ALLOWLIST": CHECKER_PRINCIPAL,
        }
    )
    assert isinstance(config, ApproverConfig)
    listener = create_approver_server(config, authorization=service)
    assert not isinstance(listener, ConfigurationRefusal)
    thread = threading.Thread(target=listener.serve_forever, daemon=True)
    thread.start()
    try:
        yield service, listener.bound_address, rail
    finally:
        listener.shutdown()
        listener.close()
        thread.join(timeout=5)
        rail.stop()


def _checker_context(pkis) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(pkis["approver_ca"]))
    context.load_cert_chain(str(pkis["checker_cert"]), str(pkis["checker_key"]))
    return context


def _request(address, context, method="GET", path="/reviews", body: bytes | None = None):
    connection = http.client.HTTPSConnection(*address, context=context, timeout=5)
    try:
        headers = {"Content-Type": "application/json"} if body is not None else {}
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def _proposal(reference: str = "12" * 32) -> AuthorizationRequest:
    return AuthorizationRequest.model_validate(
        {
            "action": "payment",
            "rail": "card",
            "currency": "USD",
            "amount_minor": PROPOSAL_AMOUNT,
            "reversibility": "irreversible",
            "counterparty_ref": "fp:" + "cd" * 32,
            "source_account_ref": "fp:" + "ef" * 32,
            "request_ref": "fp:" + reference,
        }
    )


class TestTheReviewRoundTrip:
    def test_parked_listed_answered_executed_and_read_back(self, stack, pkis) -> None:
        """The slice's acceptance criterion, in one motion."""
        service, address, rail = stack
        now = datetime.now(tz=timezone.utc)
        dispatched_before = len(rail.recorded)

        first = service.authorize(AGENT_PRINCIPAL, _proposal("aa" * 32), now=now)
        assert first.status.value == "awaiting_review"

        status, listing = _request(address, _checker_context(pkis))
        assert status == 200
        shown = [
            review for review in listing["reviews"] if review["amount_minor"] == PROPOSAL_AMOUNT
        ]
        assert shown, "the parked review is not visible to the checker"
        review = shown[0]

        status, resolution = _request(
            address,
            _checker_context(pkis),
            method="POST",
            path=f"/reviews/{review['approval_id']}",
            body=json.dumps({"answer": "approve", "proposal": review["proposal"]}).encode(),
        )
        assert status == 200
        assert resolution == {"status": "executed", "reason": None}
        assert len(rail.recorded) == dispatched_before + 1, (
            "an approved review must reach the rail exactly once"
        )

        again = service.authorize(AGENT_PRINCIPAL, _proposal("aa" * 32), now=now)
        assert again.status.value == "completed", (
            "the agent re-sending its own handle must read the settled answer"
        )
        assert len(rail.recorded) == dispatched_before + 1, "the re-send must not dispatch again"

    def test_a_declined_review_is_rejected_and_nothing_moves(self, stack, pkis) -> None:
        service, address, rail = stack
        now = datetime.now(tz=timezone.utc)
        dispatched_before = len(rail.recorded)

        held = service.authorize(AGENT_PRINCIPAL, _proposal("bb" * 32), now=now)
        assert held.status.value == "awaiting_review"
        (review,) = [
            item
            for item in _request(address, _checker_context(pkis))[1]["reviews"]
            if item["amount_minor"] == PROPOSAL_AMOUNT
        ]
        status, resolution = _request(
            address,
            _checker_context(pkis),
            method="POST",
            path=f"/reviews/{review['approval_id']}",
            body=json.dumps({"answer": "decline", "proposal": review["proposal"]}).encode(),
        )
        assert status == 200
        assert resolution["status"] == "rejected"
        assert len(rail.recorded) == dispatched_before, "a decline must move nothing"

    def test_an_answer_about_different_content_is_a_digest_mismatch(self, stack, pkis) -> None:
        """B3 end to end: the digest the checker restates is what the verdict
        binds to, so a substitution between display and answer dies here."""
        service, address, rail = stack
        now = datetime.now(tz=timezone.utc)
        dispatched_before = len(rail.recorded)

        held = service.authorize(AGENT_PRINCIPAL, _proposal("cc" * 32), now=now)
        assert held.status.value == "awaiting_review"
        (review,) = [
            item
            for item in _request(address, _checker_context(pkis))[1]["reviews"]
            if item["amount_minor"] == PROPOSAL_AMOUNT
        ]
        status, resolution = _request(
            address,
            _checker_context(pkis),
            method="POST",
            path=f"/reviews/{review['approval_id']}",
            body=json.dumps({"answer": "approve", "proposal": "0" * 64}).encode(),
        )
        assert status == 200
        assert resolution == {"status": "rejected", "reason": "digest_mismatch"}
        assert len(rail.recorded) == dispatched_before


class TestTheDoorIsADifferentDoor:
    def test_an_agent_channel_credential_is_refused_at_the_handshake(self, stack, pkis) -> None:
        """The agent's leaf is valid, current, and signed by a CA this listener
        has never heard of. The handshake settles it — nothing this slice wrote
        is even consulted."""
        _, address, _ = stack
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        # The agent trusts its own channel's CA; it has no reason to trust the
        # approver listener's, and the failure below is the client refusing the
        # server or the server refusing the client — either way, no service.
        context.verify_mode = ssl.CERT_NONE  # noqa: S501 — the refusal under test is the server's
        context.load_cert_chain(str(pkis["agent_client_cert"]), str(pkis["agent_client_key"]))
        with pytest.raises(NO_SERVICE):
            _request(address, context)

    def test_no_certificate_no_service(self, stack, pkis) -> None:
        _, address, _ = stack
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # noqa: S501 — the server's refusal is the assertion
        with pytest.raises(NO_SERVICE):
            _request(address, context)


class TestWhatACheckerMayNotDo:
    def test_an_unknown_path_is_refused(self, stack, pkis) -> None:
        _, address, _ = stack
        assert _request(address, _checker_context(pkis), path="/authorize")[0] == 404
        assert _request(address, _checker_context(pkis), method="POST", path="/reviews/")[0] == 404

    def test_a_smuggled_identity_is_refused(self, stack, pkis) -> None:
        _, address, _ = stack
        status, payload = _request(
            address,
            _checker_context(pkis),
            method="POST",
            path="/reviews/anything",
            body=json.dumps(
                {"answer": "approve", "proposal": "0" * 64, "checker": "someone-else"}
            ).encode(),
        )
        assert (status, payload) == (400, {"refused": "body_supplied_principal"})

    def test_a_malformed_answer_is_refused(self, stack, pkis) -> None:
        _, address, _ = stack
        status, payload = _request(
            address,
            _checker_context(pkis),
            method="POST",
            path="/reviews/anything",
            body=json.dumps({"answer": "maybe", "proposal": "0" * 64}).encode(),
        )
        assert (status, payload) == (400, {"refused": "malformed_answer"})

    def test_a_malformed_proposal_is_refused(self, stack, pkis) -> None:
        _, address, _ = stack
        status, payload = _request(
            address,
            _checker_context(pkis),
            method="POST",
            path="/reviews/anything",
            body=json.dumps({"answer": "approve", "proposal": "not a digest"}).encode(),
        )
        assert (status, payload) == (400, {"refused": "malformed_proposal"})

    def test_a_body_that_is_not_json_is_refused(self, stack, pkis) -> None:
        _, address, _ = stack
        status, payload = _request(
            address,
            _checker_context(pkis),
            method="POST",
            path="/reviews/anything",
            body=b"<not json>",
        )
        assert (status, payload) == (400, {"refused": "malformed_body"})

    def test_an_oversized_body_is_refused_unread(self, stack, pkis) -> None:
        _, address, _ = stack
        status, payload = _request(
            address,
            _checker_context(pkis),
            method="POST",
            path="/reviews/anything",
            body=b"x" * 70_000,
        )
        assert (status, payload) == (413, {"refused": "body_too_large"})

    def test_an_unknown_approval_is_rejected_not_invented(self, stack, pkis) -> None:
        _, address, _ = stack
        status, payload = _request(
            address,
            _checker_context(pkis),
            method="POST",
            path="/reviews/never-existed",
            body=json.dumps({"answer": "approve", "proposal": "0" * 64}).encode(),
        )
        assert (status, payload) == (
            200,
            {"status": "rejected", "reason": "unknown_approval"},
        )

    def test_a_body_that_is_json_but_not_an_object_is_refused(self, stack, pkis) -> None:
        _, address, _ = stack
        status, payload = _request(
            address,
            _checker_context(pkis),
            method="POST",
            path="/reviews/anything",
            body=b'"a string is valid JSON and still not a request"',
        )
        assert (status, payload) == (400, {"refused": "malformed_body"})

    def test_an_unparseable_content_length_is_refused(self, stack, pkis) -> None:
        """`http.client` only writes a Content-Length when it is given a body,
        so a header stated by hand arrives at the server exactly as stated."""
        _, address, _ = stack
        connection = http.client.HTTPSConnection(
            *address, context=_checker_context(pkis), timeout=5
        )
        try:
            connection.request(
                "POST", "/reviews/anything", headers={"Content-Length": "not a number"}
            )
            response = connection.getresponse()
            assert response.status == 400
            assert json.loads(response.read()) == {"refused": "malformed_body"}
        finally:
            connection.close()


class TestAChannelWithNoDecisionPath:
    """A gateway with no rail holds no reviews and answers 503 — availability
    stated as itself, never a verdict, on both verbs."""

    @pytest.fixture()
    def unwired(self, pkis):
        config = load_approver_config(
            {
                "SECONDSIGN_APPROVER_BIND": "127.0.0.1:0",
                "SECONDSIGN_APPROVER_TLS_CERT": str(pkis["listener_cert"]),
                "SECONDSIGN_APPROVER_TLS_KEY": str(pkis["listener_key"]),
                "SECONDSIGN_APPROVER_CA": str(pkis["approver_ca"]),
                "SECONDSIGN_APPROVER_ALLOWLIST": CHECKER_PRINCIPAL,
            }
        )
        assert isinstance(config, ApproverConfig)
        listener = create_approver_server(config, authorization=None)
        assert not isinstance(listener, ConfigurationRefusal)
        thread = threading.Thread(target=listener.serve_forever, daemon=True)
        thread.start()
        try:
            yield listener.bound_address
        finally:
            listener.shutdown()
            listener.close()
            thread.join(timeout=5)

    def test_listing_is_unavailable_not_empty(self, unwired, pkis) -> None:
        status, payload = _request(unwired, _checker_context(pkis))
        assert (status, payload) == (503, {"refused": "authorization_unavailable"})

    def test_answering_is_unavailable_not_rejected(self, unwired, pkis) -> None:
        status, payload = _request(
            unwired,
            _checker_context(pkis),
            method="POST",
            path="/reviews/anything",
            body=json.dumps({"answer": "approve", "proposal": "0" * 64}).encode(),
        )
        assert (status, payload) == (503, {"refused": "authorization_unavailable"})
