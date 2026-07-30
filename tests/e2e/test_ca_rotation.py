# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Rotating the CA, and withdrawing a credential (CORE-S019, ADR 0004 §4).

There is no CRL and no OCSP here. A leaked client certificate stays valid until
it expires, and the whole of the answer is that it expires in an hour. Which
makes two operational questions load-bearing rather than administrative, and ADR
0004 §4 answers both:

**Rotation.** Replacing the CA must not require every agent to re-enrol in the
same instant. The client CA bundle is a bundle: old and new overlap, agents move
across during the overlap, and the old CA is removed once nobody is behind it.
A deployment that could not do this would be one where rotating a CA means an
outage, and a CA that is never rotated because rotating it is an outage is the
real failure this avoids.

**Withdrawal.** With no online revocation, taking a credential out of service is
removing its CA or its principal from what the gateway will accept, and
restarting. That is the emergency path, so it is asserted rather than assumed —
including the part that makes it an answer at all: the certificate itself is
still perfectly valid, and it is refused anyway.

Each case restarts the process, because that is what the operator does. What is
being pinned is the composition — bundle, allowlist, restart — rather than any
single function, so the gateway is stood up for real each time.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import http.client
import importlib.util
import json
import ssl
import threading
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from secondsign.gateway.server import (
    ConfigurationRefusal,
    GatewayConfig,
    PrincipalRefusalReason,
    create_server,
    load_config,
)
from tests.deployment.conftest import REFERENCE
from tests.e2e.conftest import NO_SERVICE

PRINCIPAL = "spiffe://secondsign.example/agent/reference"
OTHER_PRINCIPAL = "spiffe://secondsign.example/agent/successor"

#: What `_attempt` reports when the handshake yielded no service. Which of the
#: three exceptions in `NO_SERVICE` arrives is a race the caller does not pick;
#: that they all mean "refused before any request" is the assertion.
HANDSHAKE_REFUSED = "handshake_refused"


def _load_generator():
    """Load `deploy/reference/tls/generate.py`, which is a script, not a package."""
    path = REFERENCE / "tls" / "generate.py"
    spec = importlib.util.spec_from_file_location("secondsign_reference_pki_rotation", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Authority:
    """One certificate authority and the leaves it signs.

    The reference deployment's own issuer, so a certificate accepted here is one
    the deployment would have minted — the rotation being tested is of the real
    thing rather than of a shape invented for the test.
    """

    def __init__(self, root: Path, name: str) -> None:
        self._generator = _load_generator()
        self.name = name
        self.root = root / name
        self.root.mkdir(parents=True)
        self._now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
        self._key, self.certificate = self._generator.build_ca(self._now)
        self.ca_path = self._write("ca-cert.pem", self.certificate)

    def _write(self, filename: str, certificate: x509.Certificate) -> Path:
        path = self.root / filename
        path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        return path

    def leaf(self, common_name: str, *, principal: str = PRINCIPAL) -> tuple[Path, Path]:
        key, certificate = self._generator.build_leaf(
            common_name=common_name,
            san=x509.SubjectAlternativeName([x509.UniformResourceIdentifier(principal)]),
            eku=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            ca_key=self._key,
            ca_cert=self.certificate,
            now=self._now,
            lifetime=dt.timedelta(minutes=60),
        )
        cert_path = self._write(f"{common_name}-cert.pem", certificate)
        key_path = self.root / f"{common_name}-key.pem"
        key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        return cert_path, key_path

    def server_leaf(self) -> tuple[Path, Path]:
        key, certificate = self._generator.build_leaf(
            common_name="localhost",
            san=x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            eku=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            ca_key=self._key,
            ca_cert=self.certificate,
            now=self._now,
            lifetime=dt.timedelta(minutes=60),
        )
        cert_path = self._write("server-cert.pem", certificate)
        key_path = self.root / "server-key.pem"
        key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        return cert_path, key_path


@pytest.fixture(scope="module")
def estate(tmp_path_factory) -> dict[str, object]:
    """Two unrelated CAs, one agent enrolled under each, and a bundle file.

    `outgoing` and `incoming` share no key and no name: this is a real rotation
    rather than a re-issue, so nothing about the second CA can be reached
    through the first.
    """
    root = tmp_path_factory.mktemp("rotation")
    outgoing = _Authority(root, "outgoing")
    incoming = _Authority(root, "incoming")
    server_cert, server_key = outgoing.server_leaf()
    return {
        "outgoing": outgoing,
        "incoming": incoming,
        "server_cert": server_cert,
        "server_key": server_key,
        "old_agent": outgoing.leaf("agent-under-the-old-ca"),
        "new_agent": incoming.leaf("agent-under-the-new-ca"),
        "root": root,
    }


def _bundle(estate, *authorities: _Authority) -> Path:
    """The client CA bundle, as the operator writes it: certificates in one
    file, in the order they were rolled out."""
    path = estate["root"] / f"bundle-{'-'.join(a.name for a in authorities)}.pem"
    path.write_bytes(b"".join(a.ca_path.read_bytes() for a in authorities))
    return path


@contextlib.contextmanager
def _running(estate, *, bundle: Path, allowlist: str = PRINCIPAL):
    """The gateway, started from an environment and stopped afterwards.

    A context manager because every case here is about the restart: the bundle
    and the allowlist are read once at start-up, which is exactly the property
    that makes "remove it and restart" a complete answer.
    """
    config = load_config(
        {
            "SECONDSIGN_BIND": "127.0.0.1:0",
            "SECONDSIGN_TLS_CERT": str(estate["server_cert"]),
            "SECONDSIGN_TLS_KEY": str(estate["server_key"]),
            "SECONDSIGN_CLIENT_CA": str(bundle),
            "SECONDSIGN_CLIENT_ALLOWLIST": allowlist,
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


def _attempt(estate, address, agent: str) -> str:
    """Present `agent`'s certificate and report what came back."""
    cert, key = estate[agent]
    context = ssl.create_default_context(cafile=str(estate["outgoing"].ca_path))
    context.load_cert_chain(certfile=str(cert), keyfile=str(key))
    host, port = address
    connection = http.client.HTTPSConnection(
        "localhost", port, context=context, source_address=(host, 0), timeout=10
    )
    try:
        connection.request("GET", "/healthz")
        response = connection.getresponse()
        payload = json.loads(response.read())
        return "ok" if response.status == 200 else str(payload["refused"])
    except NO_SERVICE:
        return HANDSHAKE_REFUSED
    finally:
        connection.close()


class TestTheOverlapIsWhatMakesRotationPossible:
    def test_before_the_rotation_only_the_old_ca_is_accepted(self, estate) -> None:
        """The starting state, asserted so the overlap below is a change rather
        than a coincidence."""
        with _running(estate, bundle=_bundle(estate, estate["outgoing"])) as address:
            assert _attempt(estate, address, "old_agent") == "ok"
            assert _attempt(estate, address, "new_agent") == HANDSHAKE_REFUSED

    def test_during_the_overlap_both_cas_are_accepted(self, estate) -> None:
        """The property the rotation rests on. Without it, moving to a new CA
        means every agent re-enrolling in the same instant, which is an outage
        with a schedule."""
        bundle = _bundle(estate, estate["outgoing"], estate["incoming"])
        with _running(estate, bundle=bundle) as address:
            assert _attempt(estate, address, "old_agent") == "ok"
            assert _attempt(estate, address, "new_agent") == "ok"

    def test_after_the_rotation_the_old_ca_is_gone(self, estate) -> None:
        """Removing a CA from the bundle takes effect on restart — and the old
        agent's certificate has not expired, been revoked, or changed in any
        way. It is refused because the gateway no longer trusts what signed it,
        which is the whole of the withdrawal mechanism in v1."""
        with _running(estate, bundle=_bundle(estate, estate["incoming"])) as address:
            assert _attempt(estate, address, "new_agent") == "ok"
            assert _attempt(estate, address, "old_agent") == HANDSHAKE_REFUSED


class TestWithdrawingOnePrincipal:
    def test_removing_the_principal_refuses_it_while_the_ca_stays(self, estate) -> None:
        """The narrower emergency: one workload's credential is suspect, and the
        CA that signed it still serves everyone else. The certificate remains
        valid and the chain still verifies — the refusal is the allowlist's."""
        bundle = _bundle(estate, estate["outgoing"], estate["incoming"])
        with _running(estate, bundle=bundle, allowlist=OTHER_PRINCIPAL) as address:
            assert (
                _attempt(estate, address, "new_agent")
                == PrincipalRefusalReason.unknown_principal.value
            )
            assert (
                _attempt(estate, address, "old_agent")
                == PrincipalRefusalReason.unknown_principal.value
            )

    def test_the_refusal_survives_the_certificate_being_perfectly_good(self, estate) -> None:
        """Stated separately because it is the claim an operator has to believe:
        a withdrawn principal is refused after a completely successful
        handshake, so nothing about the certificate needs to be undone."""
        bundle = _bundle(estate, estate["incoming"])
        with _running(estate, bundle=bundle, allowlist=f"{OTHER_PRINCIPAL} {PRINCIPAL}") as address:
            assert _attempt(estate, address, "new_agent") == "ok"
        with _running(estate, bundle=bundle, allowlist=OTHER_PRINCIPAL) as address:
            assert (
                _attempt(estate, address, "new_agent")
                == PrincipalRefusalReason.unknown_principal.value
            )
