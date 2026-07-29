# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The gateway as a process: TLS termination and workload identity, end to end.

The red-team suite attacks the pieces — the startup check, the derivation
function, the wire refusals — over plaintext loopback, where each piece is
cheapest to isolate. This file is the whole assembly: a real listener with a
real ephemeral PKI, spoken to by real TLS clients, including the ones that
should get nothing.

Two gateways are stood up, and the difference between them is the point. The
`gateway` fixture has no rail configured, so its only honest verdict is a
refusal and every case against it pins that. The `wired_gateway` fixture has the
whole decision path behind it and a loopback rail in front of a credential the
caller never sees — so the cases against *that* one are where a decision, a
dispatch, and the absence of a leak are asserted together.

The PKI is the reference deployment's own generator, pointed at a temporary
directory. Same issuer code, same SAN shape, same one-hour lifetime — so what
these cases accept and refuse is what the containerised deployment accepts and
refuses, minus Docker.
"""

from __future__ import annotations

import http.client
import importlib.util
import json
import socket
import ssl
import threading
from pathlib import Path

import pytest

from secondsign.gateway import server as server_module
from secondsign.gateway.server import (
    ConfigurationRefusal,
    GatewayConfig,
    build_authorization,
    create_server,
    load_config,
    main,
)
from tests.deployment.conftest import REFERENCE

PRINCIPAL = "spiffe://secondsign.example/agent/reference"
STRANGER_PRINCIPAL = "spiffe://secondsign.example/agent/stranger"

#: The fake rail credential the wired gateway holds. Asserted absent from every
#: byte the caller receives — this string existing in this file is the point.
RAIL_CREDENTIAL = "sk_reference_not_a_real_key"


def _load_generator():
    """Load `deploy/reference/tls/generate.py`, which is a script, not a package."""
    path = REFERENCE / "tls" / "generate.py"
    spec = importlib.util.spec_from_file_location("secondsign_reference_pki_e2e", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def pki(tmp_path_factory) -> dict[str, Path]:
    """The reference PKI, plus one extra leaf the deployment would never issue:
    a valid certificate, signed by the same CA, for a principal that is not on
    the allowlist. That is the credential of an authenticated stranger, and the
    gateway must refuse it after a completely successful handshake."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import ExtendedKeyUsageOID

    generator = _load_generator()
    root = tmp_path_factory.mktemp("e2e-pki")
    generator.generate(root=root)

    import datetime as dt

    ca_key = serialization.load_pem_private_key(
        (root / "ca" / "ca-key.pem").read_bytes(), password=None
    )
    ca_cert = x509.load_pem_x509_certificate((root / "ca" / "ca-cert.pem").read_bytes())
    stranger_key, stranger_cert = generator.build_leaf(
        common_name="authenticated-stranger",
        san=x509.SubjectAlternativeName([x509.UniformResourceIdentifier(STRANGER_PRINCIPAL)]),
        eku=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
        ca_key=ca_key,
        ca_cert=ca_cert,
        now=dt.datetime.now(dt.timezone.utc).replace(tzinfo=None),
        lifetime=dt.timedelta(minutes=60),
    )
    (root / "stranger-key.pem").write_bytes(
        stranger_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (root / "stranger-cert.pem").write_bytes(stranger_cert.public_bytes(serialization.Encoding.PEM))
    return {
        "gateway_cert": root / "gateway" / "gateway-cert.pem",
        "gateway_key": root / "gateway" / "gateway-key.pem",
        "ca_cert": root / "gateway" / "ca-cert.pem",
        "client_cert": root / "agent" / "client-cert.pem",
        "client_key": root / "agent" / "client-key.pem",
        "stranger_cert": root / "stranger-cert.pem",
        "stranger_key": root / "stranger-key.pem",
    }


@pytest.fixture(scope="module")
def gateway(pki):
    """The gateway process's server, on loopback with the reference PKI."""
    config = load_config(
        {
            "SECONDSIGN_BIND": "127.0.0.1:0",
            "SECONDSIGN_TLS_CERT": str(pki["gateway_cert"]),
            "SECONDSIGN_TLS_KEY": str(pki["gateway_key"]),
            "SECONDSIGN_CLIENT_CA": str(pki["ca_cert"]),
            "SECONDSIGN_CLIENT_ALLOWLIST": PRINCIPAL,
        }
    )
    assert isinstance(config, GatewayConfig)
    server = create_server(config)
    assert not isinstance(server, ConfigurationRefusal), f"gateway refused to start: {server!r}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.bound_address
    finally:
        server.shutdown()
        server.close()
        thread.join(timeout=5)


def _client_context(pki, *, cert: str | None = "client") -> ssl.SSLContext:
    """A TLS client that trusts the test CA and, optionally, presents a leaf.

    `check_hostname` is off because the gateway leaf names the Compose service
    (`gateway`) and these tests dial loopback; server-name verification is the
    client's protection and is not what this suite asserts.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(pki["ca_cert"]))
    if cert is not None:
        context.load_cert_chain(str(pki[f"{cert}_cert"]), str(pki[f"{cert}_key"]))
    return context


def _request(
    address: tuple[str, int],
    context: ssl.SSLContext,
    method: str = "GET",
    path: str = "/healthz",
    body: bytes | None = None,
):
    connection = http.client.HTTPSConnection(*address, context=context, timeout=5)
    try:
        headers = {"Content-Type": "application/json"} if body is not None else {}
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response, response.read()
    finally:
        connection.close()


class TestAnAuthenticatedWorkload:
    def test_reaches_healthz(self, gateway, pki) -> None:
        response, body = _request(gateway, _client_context(pki))

        assert response.status == 200
        assert json.loads(body) == {"gateway": "listening", "authorization": "unavailable"}

    def test_the_response_leaks_no_credential_material(self, gateway, pki) -> None:
        """The deployment suite asserts this from the agent container; here it
        is asserted at the source, including response headers."""
        response, body = _request(gateway, _client_context(pki))

        text = body.decode() + str(response.getheaders())
        assert "sk_" not in text
        assert "SECONDSIGN_RAIL_API_KEY" not in text

    def test_the_server_does_not_announce_python(self, gateway, pki) -> None:
        response, _ = _request(gateway, _client_context(pki))

        assert response.getheader("Server") == "secondsign-gateway"

    def test_gets_no_verdict_when_no_rail_is_configured(self, gateway, pki) -> None:
        """Unavailability, not a verdict. This gateway holds no credential and
        has nowhere to dispatch, and says so."""
        response, body = _request(
            gateway,
            _client_context(pki),
            method="POST",
            path="/authorize",
            body=b'{"wire_version": 1}',
        )

        payload = json.loads(body)
        assert response.status == 503
        assert payload == {"refused": "authorization_unavailable"}

    def test_speaking_an_unknown_dialect_gets_refused_not_guessed_at(self, gateway, pki) -> None:
        response, body = _request(
            gateway,
            _client_context(pki),
            method="POST",
            path="/authorize",
            body=b'{"wire_version": 2}',
        )

        assert response.status == 400
        assert json.loads(body) == {"refused": "wire_version_unrecognised"}

    def test_an_unknown_path_is_refused(self, gateway, pki) -> None:
        response, body = _request(gateway, _client_context(pki), path="/admin")

        assert response.status == 404
        assert json.loads(body) == {"refused": "unknown_path"}


#: The three spellings of one fact: the handshake yielded no service.
#:
#: Under TLS 1.3 the server learns about the missing or untrusted certificate
#: only after its own Finished flight, so it sends an alert and closes while the
#: caller is still mid-exchange. Which error the caller sees is a race it does
#: not get to pick: it reads the alert (`SSLError`), reads the close
#: (`ConnectionResetError`), or loses even that and finds its own write hitting a
#: closed socket (`BrokenPipeError`). CI's Linux runners reliably produce the
#: second; macOS produces the first usually and the third about once in
#: twenty-five runs.
#:
#: Named types, never `OSError`. The broad catch would also swallow
#: `ConnectionRefusedError` — nothing listening at all — and this suite would
#: then report "the gateway refused an anonymous caller" on a machine where the
#: gateway never started.
NO_SERVICE = (ssl.SSLError, ConnectionResetError, BrokenPipeError)


class TestAnUnauthenticatedCaller:
    """No client certificate, or one from a stranger CA, and the connection
    yields nothing: no HTTP request is ever read, so there is no request for a
    handler to refuse. See `NO_SERVICE` for why three exception types are the
    same result."""

    def test_no_client_certificate_no_service(self, gateway, pki) -> None:
        """CERT_REQUIRED means the handshake itself fails; there is no
        anonymous request for a handler to even refuse."""
        with pytest.raises(NO_SERVICE):
            _request(gateway, _client_context(pki, cert=None))

    def test_a_certificate_from_a_stranger_ca_is_refused(self, gateway, pki, tmp_path_factory):
        foreign_root = tmp_path_factory.mktemp("foreign-pki")
        _load_generator().generate(root=foreign_root)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.load_verify_locations(cafile=str(pki["ca_cert"]))
        context.load_cert_chain(
            str(foreign_root / "agent" / "client-cert.pem"),
            str(foreign_root / "agent" / "client-key.pem"),
        )

        with pytest.raises(NO_SERVICE):
            _request(gateway, context)

    def test_plaintext_to_the_tls_port_gets_nothing(self, gateway) -> None:
        """A plaintext caller is dropped mid-handshake. No HTTP response, no
        error page, no banner — the listener yields bytes only to a verified
        peer."""
        with socket.create_connection(gateway, timeout=5) as raw:
            raw.sendall(b"GET /healthz HTTP/1.1\r\nHost: gateway\r\n\r\n")
            raw.settimeout(5)
            try:
                received = raw.recv(1024)
            except OSError:
                received = b""

        assert received == b""


class TestAnAuthenticatedStranger:
    """A successful handshake is not admission. The stranger's certificate is
    valid, current, and signed by the trusted CA; its principal is simply not
    on the allowlist — and that resolves fail-closed (ADR 0004 §5, condition
    seven)."""

    def test_is_refused_on_every_path(self, gateway, pki) -> None:
        response, body = _request(gateway, _client_context(pki, cert="stranger"))

        assert response.status == 403
        assert json.loads(body) == {"refused": "unknown_principal"}

    def test_cannot_reach_authorize_with_a_smuggled_principal(self, gateway, pki) -> None:
        """Identity is settled before the body is looked at: the refusal names
        the unknown principal, not the smuggled field, proving the request body
        was never consulted."""
        smuggled = json.dumps({"client_principal": PRINCIPAL}).encode()

        response, body = _request(
            gateway,
            _client_context(pki, cert="stranger"),
            method="POST",
            path="/authorize",
            body=smuggled,
        )

        assert response.status == 403
        assert json.loads(body) == {"refused": "unknown_principal"}


class TestTheProcessLifecycle:
    """`python -m secondsign.gateway.server`, minus the module trampoline."""

    def test_a_refusing_configuration_exits_2(self, capsys) -> None:
        exit_code = main(environ={"SECONDSIGN_BIND": "not a bind at all"})

        captured = capsys.readouterr()
        assert exit_code == 2
        assert "refusing to start" in captured.err
        assert "malformed_bind" in captured.err

    def test_unloadable_material_exits_2(self, capsys, tmp_path) -> None:
        garbage = tmp_path / "garbage.pem"
        garbage.write_text("not certificate material")

        exit_code = main(
            environ={
                "SECONDSIGN_BIND": "127.0.0.1:0",
                "SECONDSIGN_TLS_CERT": str(garbage),
                "SECONDSIGN_TLS_KEY": str(garbage),
                "SECONDSIGN_CLIENT_CA": str(garbage),
                "SECONDSIGN_CLIENT_ALLOWLIST": PRINCIPAL,
            }
        )

        captured = capsys.readouterr()
        assert exit_code == 2
        assert "unreadable_tls_material" in captured.err

    def test_serves_until_interrupted(self, capsys, monkeypatch) -> None:
        def interrupted(self) -> None:
            raise KeyboardInterrupt

        monkeypatch.setattr(server_module.GatewayServer, "serve_forever", interrupted)

        exit_code = main(environ={"SECONDSIGN_BIND": "127.0.0.1:0"})

        captured = capsys.readouterr()
        assert exit_code == 130
        assert "listening" in captured.out

    def test_returns_0_when_the_server_stops(self, monkeypatch) -> None:
        monkeypatch.setattr(server_module.GatewayServer, "serve_forever", lambda self: None)

        assert main(environ={"SECONDSIGN_BIND": "127.0.0.1:0"}) == 0


@pytest.fixture(scope="module")
def wired_gateway(pki):
    """The whole assembly over real mTLS: a gateway with a rail behind it.

    The rail is a loopback HTTP server that records what it was dispatched, so
    the case that matters — did an authorization actually reach a rail, holding
    a credential the caller never saw — is answered at the destination rather
    than inferred from the response.
    """
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    dispatched: list[bytes] = []

    class _RailHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler's dispatch name
            dispatched.append(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            """Silent."""

    rail = ThreadingHTTPServer(("127.0.0.1", 0), _RailHandler)
    rail.daemon_threads = True
    rail_thread = threading.Thread(target=rail.serve_forever, daemon=True)
    rail_thread.start()
    rail_host, rail_port = rail.server_address[:2]

    config = load_config(
        {
            "SECONDSIGN_BIND": "127.0.0.1:0",
            "SECONDSIGN_TLS_CERT": str(pki["gateway_cert"]),
            "SECONDSIGN_TLS_KEY": str(pki["gateway_key"]),
            "SECONDSIGN_CLIENT_CA": str(pki["ca_cert"]),
            "SECONDSIGN_CLIENT_ALLOWLIST": PRINCIPAL,
        }
    )
    assert isinstance(config, GatewayConfig)
    service = build_authorization(
        {
            "SECONDSIGN_RAIL_URL": f"http://{rail_host}:{rail_port}/dispatch",
            "SECONDSIGN_RAIL_API_KEY": RAIL_CREDENTIAL,
        }
    )
    server = create_server(config, authorization=service)
    assert not isinstance(server, ConfigurationRefusal), f"gateway refused to start: {server!r}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.bound_address, dispatched
    finally:
        server.shutdown()
        server.close()
        thread.join(timeout=5)
        rail.shutdown()
        rail_thread.join(timeout=5)
        rail.server_close()


def _proposal(**overrides) -> dict:
    fingerprint = "fp:" + "ab" * 32
    proposal = {
        "action": "payment",
        "rail": "card",
        "currency": "USD",
        "amount_minor": 4_200,
        "reversibility": "irreversible",
        "counterparty_ref": fingerprint,
        "source_account_ref": fingerprint,
        "request_ref": "fp:" + "cd" * 32,
    }
    proposal.update(overrides)
    return proposal


class TestTheWholeAssembly:
    """An authenticated workload proposes, the gateway decides, and a rail the
    workload cannot reach is the only thing that moves money."""

    def test_an_authorized_payment_reaches_the_rail(self, wired_gateway, pki) -> None:
        address, dispatched = wired_gateway
        before = len(dispatched)

        response, body = _request(
            address,
            _client_context(pki),
            method="POST",
            path="/authorize",
            body=json.dumps({"wire_version": 1, "request": _proposal()}).encode(),
        )

        assert response.status == 200
        payload = json.loads(body)
        assert payload["wire_version"] == 1
        assert payload["outcome"]["status"] == "completed"
        assert len(dispatched) == before + 1

    def test_the_rail_credential_never_appears_on_the_wire(self, wired_gateway, pki) -> None:
        """The claim the whole slice rests on, checked at the one place a leak
        would be invisible: the bytes the caller actually receives."""
        address, _ = wired_gateway

        _, body = _request(
            address,
            _client_context(pki),
            method="POST",
            path="/authorize",
            body=json.dumps(
                {"wire_version": 1, "request": _proposal(request_ref="fp:" + "11" * 32)}
            ).encode(),
        )

        assert RAIL_CREDENTIAL not in body.decode()

    def test_a_denial_moves_nothing(self, wired_gateway, pki) -> None:
        address, dispatched = wired_gateway
        before = len(dispatched)

        _, body = _request(
            address,
            _client_context(pki),
            method="POST",
            path="/authorize",
            body=json.dumps(
                {
                    "wire_version": 1,
                    "request": _proposal(amount_minor=900_000_00, request_ref="fp:" + "22" * 32),
                }
            ).encode(),
        )

        outcome = json.loads(body)["outcome"]
        assert outcome["status"] == "refused"
        assert "value_band_exceeded" in outcome["reasons"]
        assert len(dispatched) == before, "a denied proposal was dispatched anyway"

    def test_an_outcome_carries_no_raw_identity(self, wired_gateway, pki) -> None:
        address, _ = wired_gateway

        _, body = _request(
            address,
            _client_context(pki),
            method="POST",
            path="/authorize",
            body=json.dumps(
                {"wire_version": 1, "request": _proposal(request_ref="fp:" + "33" * 32)}
            ).encode(),
        )

        assert PRINCIPAL not in body.decode()

    def test_a_proposal_that_is_not_the_agent_surface_is_refused(self, wired_gateway, pki) -> None:
        """Refused without explanation: the validator's message quotes the
        input, and the input is attacker-chosen bytes."""
        address, _ = wired_gateway

        response, body = _request(
            address,
            _client_context(pki),
            method="POST",
            path="/authorize",
            body=json.dumps({"wire_version": 1, "request": {"amount_minor": -1}}).encode(),
        )

        assert response.status == 400
        assert json.loads(body) == {"refused": "malformed_request"}

    def test_an_authenticated_stranger_still_gets_nowhere(self, wired_gateway, pki) -> None:
        """A rail behind the gateway does not widen who may reach it."""
        address, dispatched = wired_gateway
        before = len(dispatched)

        response, body = _request(
            address,
            _client_context(pki, cert="stranger"),
            method="POST",
            path="/authorize",
            body=json.dumps({"wire_version": 1, "request": _proposal()}).encode(),
        )

        assert response.status == 403
        assert json.loads(body) == {"refused": "unknown_principal"}
        assert len(dispatched) == before
