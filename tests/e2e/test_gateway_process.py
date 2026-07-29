# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The gateway as a process: TLS termination and workload identity, end to end.

The red-team suite attacks the pieces — the startup check, the derivation
function, the wire refusals — over plaintext loopback, where each piece is
cheapest to isolate. This file is the whole assembly: a real listener with a
real ephemeral PKI, spoken to by real TLS clients, including the ones that
should get nothing.

What is deliberately absent: any case in which the gateway authorizes anything.
The wire contract is a later step of CORE-S019; until it lands the gateway's
only honest verdicts are refusals, and the cases here pin that — a workload
with a perfectly good certificate still gets `authorization_unavailable`, never
a locally invented `completed`.

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
    create_server,
    load_config,
    main,
)
from tests.deployment.conftest import REFERENCE

PRINCIPAL = "spiffe://secondsign.example/agent/reference"
STRANGER_PRINCIPAL = "spiffe://secondsign.example/agent/stranger"


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

    def test_gets_no_verdict_while_authorization_is_unwired(self, gateway, pki) -> None:
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


class TestAnUnauthenticatedCaller:
    """How the refusal surfaces client-side is a race the caller does not get
    to pick. Under TLS 1.3 the server learns about the missing or untrusted
    certificate after its own Finished flight, sends an alert, and closes; the
    caller reads either the alert (`SSLError`) or the close (`ConnectionResetError`)
    depending on timing — CI's Linux runners reliably produce the second, macOS
    the first. Both spellings are the same fact: the handshake yielded no
    service, and no HTTP request was ever read."""

    def test_no_client_certificate_no_service(self, gateway, pki) -> None:
        """CERT_REQUIRED means the handshake itself fails; there is no
        anonymous request for a handler to even refuse."""
        with pytest.raises((ssl.SSLError, ConnectionResetError)):
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

        with pytest.raises((ssl.SSLError, ConnectionResetError)):
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
