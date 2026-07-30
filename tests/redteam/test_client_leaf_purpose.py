# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Red team: a certificate that authenticates is not therefore a client
certificate (CORE-S019, ADR 0004 §4).

The chain check settles who signed the leaf. It does not settle what the leaf
was issued *for*, and those are different questions. A server certificate, a
code-signing certificate, or a leaf issued for encryption only — each of them
carries a valid signature from the same CA, and each of them is a credential
some other part of a deployment was trusted with, presented here.

OpenSSL already answers part of this: verifying a client, it applies the
`ssl_client` purpose, so an extended key usage that is *present and wrong* fails
the handshake. What it does not do is treat *absence* as a failure — an
unrestricted leaf is, by RFC 5280, good for every purpose. This gateway refuses
it. Between a CA that scopes what it issues and one that does not, the second is
a CA whose every leaf is a gateway credential, and that is not a deployment this
process consents to serve.

Two levels, and both are here on purpose. The handshake cases prove what a real
TLS peer gets. The unit cases drive `verify_client_purpose` against synthesized
bytes, because the refusals OpenSSL happens to reach first today are still this
gateway's own conditions, and a future context change must not be able to drop
them silently.
"""

from __future__ import annotations

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

from secondsign.gateway.leaf import CertificatePurpose, read_client_purpose
from secondsign.gateway.server import (
    ConfigurationRefusal,
    GatewayConfig,
    PrincipalRefusal,
    PrincipalRefusalReason,
    create_server,
    load_config,
    verify_client_purpose,
)
from tests.deployment.conftest import REFERENCE
from tests.e2e.conftest import NO_SERVICE

PRINCIPAL = "spiffe://secondsign.example/agent/reference"

#: Everything a client leaf must carry to be one. `signing` is the key usage
#: that lets the leaf sign its own CertificateVerify; without it the peer is
#: presenting a key it was not issued the right to authenticate with.
SIGNING = x509.KeyUsage(
    digital_signature=True,
    content_commitment=False,
    key_encipherment=False,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=False,
    crl_sign=False,
    encipher_only=False,
    decipher_only=False,
)
ENCIPHERMENT_ONLY = x509.KeyUsage(
    digital_signature=False,
    content_commitment=False,
    key_encipherment=True,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=False,
    crl_sign=False,
    encipher_only=False,
    decipher_only=False,
)
CLIENT_AUTH = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
SERVER_AUTH = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])


#: The two extension OIDs, in their encoded form. A real CA is the wrong tool
#: for the cases below: they are certificates no issuer would produce, so they
#: are built here as bytes, one deviation at a time.
KEY_USAGE = b"\x55\x1d\x0f"
EXTENDED_KEY_USAGE = b"\x55\x1d\x25"


def _tlv(tag: int, *contents: bytes) -> bytes:
    """One DER element around `contents`, in the shortest legal length form."""
    body = b"".join(contents)
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    length = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + body


def _oid_element(encoded: bytes) -> bytes:
    return _tlv(0x06, encoded)


def _certificate(*extensions: bytes) -> bytes:
    """A certificate stripped to exactly what the reader walks.

    Everything the reader skips by length is present but empty. That is the
    point: a stripped certificate proves the walk depends on structure rather
    than on the fields around it.
    """
    tbs = _tlv(0x30, _tlv(0xA3, _tlv(0x30, *extensions)))
    return _tlv(0x30, tbs, _tlv(0x30), _tlv(0x03, b"\x00"))


def _load_generator():
    """Load `deploy/reference/tls/generate.py`, which is a script, not a package."""
    path = REFERENCE / "tls" / "generate.py"
    spec = importlib.util.spec_from_file_location("secondsign_reference_pki_purpose", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Authority:
    """A throwaway CA that will issue anything asked of it.

    Deliberately not the reference generator's `build_leaf`: that function
    issues what the reference deployment issues, and every certificate below is
    one the reference deployment would refuse to mint. A knob on the shipped
    generator for producing non-conformant material would be a knob in the
    deployment.
    """

    def __init__(self, root: Path) -> None:
        generator = _load_generator()
        self.root = root
        now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
        self._key, self._cert = generator.build_ca(now)
        self.ca_path = self._write(
            "ca-cert.pem", self._cert.public_bytes(serialization.Encoding.PEM)
        )
        gateway_key, gateway_cert = generator.build_leaf(
            common_name="localhost",
            san=x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            eku=SERVER_AUTH,
            ca_key=self._key,
            ca_cert=self._cert,
            now=now,
            lifetime=dt.timedelta(minutes=60),
        )
        self.gateway_cert = self._write(
            "gateway-cert.pem", gateway_cert.public_bytes(serialization.Encoding.PEM)
        )
        self.gateway_key = self._write("gateway-key.pem", _pem_key(gateway_key))

    def _write(self, name: str, data: bytes) -> str:
        path = self.root / name
        path.write_bytes(data)
        return str(path)

    def leaf(
        self,
        name: str,
        *,
        eku: x509.ExtendedKeyUsage | None,
        key_usage: x509.KeyUsage | None,
        principal: str = PRINCIPAL,
    ) -> x509.Certificate:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, name)]))
            .issuer_name(self._cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + dt.timedelta(minutes=60))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([x509.UniformResourceIdentifier(principal)]),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._key.public_key()),
                critical=False,
            )
        )
        if eku is not None:
            builder = builder.add_extension(eku, critical=False)
        if key_usage is not None:
            builder = builder.add_extension(key_usage, critical=True)
        certificate = builder.sign(self._key, hashes.SHA256())
        self._write(f"{name}-cert.pem", certificate.public_bytes(serialization.Encoding.PEM))
        self._write(f"{name}-key.pem", _pem_key(key))
        return certificate

    def paths(self, name: str) -> tuple[str, str]:
        return str(self.root / f"{name}-cert.pem"), str(self.root / f"{name}-key.pem")


def _pem_key(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture(scope="module")
def authority(tmp_path_factory) -> _Authority:
    return _Authority(tmp_path_factory.mktemp("purpose-pki"))


@pytest.fixture(scope="module")
def gateway(authority):
    config = load_config(
        {
            "SECONDSIGN_BIND": "127.0.0.1:0",
            "SECONDSIGN_TLS_CERT": authority.gateway_cert,
            "SECONDSIGN_TLS_KEY": authority.gateway_key,
            "SECONDSIGN_CLIENT_CA": authority.ca_path,
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


#: What `_attempt` reports when the handshake yielded no service. Which of the
#: three exceptions in `NO_SERVICE` arrives is a race the caller does not pick;
#: that they all mean "refused before any request" is the assertion.
HANDSHAKE_REFUSED = "handshake_refused"


def _attempt(authority: _Authority, gateway, name: str) -> str:
    """Present `name`'s leaf and report what the gateway did with it.

    Returns the refusal code from the response body, `"ok"` when the gateway
    served the request, or `HANDSHAKE_REFUSED` when TLS never completed.
    """
    cert, key = authority.paths(name)
    context = ssl.create_default_context(cafile=authority.ca_path)
    context.load_cert_chain(certfile=cert, keyfile=key)
    host, port = gateway
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


class TestOnlyAClientCertificateAuthenticates:
    """Four leaves, one CA, one difference each."""

    def test_a_client_leaf_is_served(self, authority, gateway) -> None:
        """The control. Without it every case below could pass because the
        gateway refuses everything, which is an outage rather than a check."""
        authority.leaf("conformant", eku=CLIENT_AUTH, key_usage=SIGNING)
        assert _attempt(authority, gateway, "conformant") == "ok"

    def test_a_leaf_with_no_purpose_at_all_is_refused(self, authority, gateway) -> None:
        """The one OpenSSL accepts. An unrestricted leaf is valid for every
        purpose under RFC 5280, so the chain check passes and the CA has, in
        effect, issued a gateway credential to whoever asked it for anything."""
        authority.leaf("unrestricted", eku=None, key_usage=None)
        assert (
            _attempt(authority, gateway, "unrestricted")
            == PrincipalRefusalReason.not_for_client_authentication.value
        )

    def test_a_server_leaf_is_refused(self, authority, gateway) -> None:
        """A gateway's own certificate, replayed at a gateway."""
        authority.leaf("server-only", eku=SERVER_AUTH, key_usage=SIGNING)
        assert _attempt(authority, gateway, "server-only") in {
            HANDSHAKE_REFUSED,
            PrincipalRefusalReason.not_for_client_authentication.value,
        }

    def test_a_leaf_that_may_not_sign_is_refused(self, authority, gateway) -> None:
        """Client authentication is a signature. A key scoped to encipherment
        cannot make one, and a leaf claiming otherwise is misissued."""
        authority.leaf("no-signing", eku=CLIENT_AUTH, key_usage=ENCIPHERMENT_ONLY)
        assert _attempt(authority, gateway, "no-signing") in {
            HANDSHAKE_REFUSED,
            PrincipalRefusalReason.key_not_for_signing.value,
        }


class TestTheGatewayReachesItsOwnVerdict:
    """`verify_client_purpose` against certificate bytes, with no TLS in the way.

    The two cases above that OpenSSL refuses first are still refusals this
    process makes for itself. Asserted here so that remains true if the
    handshake ever stops reaching them.
    """

    def test_a_client_leaf_passes(self, authority) -> None:
        certificate = authority.leaf("unit-conformant", eku=CLIENT_AUTH, key_usage=SIGNING)
        assert verify_client_purpose(certificate.public_bytes(serialization.Encoding.DER)) is None

    @pytest.mark.parametrize(
        ("eku", "key_usage", "reason"),
        [
            (None, SIGNING, PrincipalRefusalReason.not_for_client_authentication),
            (SERVER_AUTH, SIGNING, PrincipalRefusalReason.not_for_client_authentication),
            (CLIENT_AUTH, None, PrincipalRefusalReason.key_not_for_signing),
            (CLIENT_AUTH, ENCIPHERMENT_ONLY, PrincipalRefusalReason.key_not_for_signing),
        ],
    )
    def test_each_missing_purpose_is_its_own_refusal(
        self, authority, eku, key_usage, reason
    ) -> None:
        name = f"unit-{reason.value}-{eku is None}-{key_usage is None}"
        certificate = authority.leaf(name, eku=eku, key_usage=key_usage)
        refusal = verify_client_purpose(certificate.public_bytes(serialization.Encoding.DER))
        assert isinstance(refusal, PrincipalRefusal)
        assert refusal.reason is reason

    def test_no_certificate_is_a_refusal(self) -> None:
        """A TLS session with no peer certificate reaches nothing to read. The
        handshake makes this unreachable — `CERT_REQUIRED` is a constant — and
        it is a refusal anyway, because "unreachable today" is a property of the
        code around it rather than of this function."""
        refusal = verify_client_purpose(None)
        assert isinstance(refusal, PrincipalRefusal)
        assert refusal.reason is PrincipalRefusalReason.unreadable_certificate

    def test_bytes_that_are_not_a_certificate_are_a_refusal(self) -> None:
        refusal = verify_client_purpose(b"\x30\x82\x04\x00 not a certificate")
        assert isinstance(refusal, PrincipalRefusal)
        assert refusal.reason is PrincipalRefusalReason.unreadable_certificate


class TestTheReaderRefusesWhatItCannotRead:
    """`read_client_purpose` returns None for anything it does not fully
    understand, and the caller turns that into a refusal.

    Every case is bytes an attacker chooses. The reader's only two outcomes are
    a purpose it read completely and `None`; there is no partial answer, because
    a partial answer is where "the extension was there, I just could not reach
    it" becomes an accept.
    """

    @pytest.mark.parametrize(
        ("name", "der"),
        [
            ("empty", b""),
            ("not a sequence", b"\x02\x01\x00"),
            ("truncated header", b"\x30"),
            ("length runs past the end", b"\x30\x0a\x30\x01"),
            ("indefinite length", b"\x30\x80\x30\x00\x00\x00"),
            ("length of a length beyond four bytes", b"\x30\x85\x01\x01\x01\x01\x01"),
            ("truncated long-form length", b"\x30\x83\x01"),
            ("high tag number form", b"\x3f\x01\x00"),
            ("tbs is not a sequence", b"\x30\x03\x02\x01\x00"),
            ("a second certificate after the first", _tlv(0x30, _tlv(0x30)) + b"\x30\x00"),
            ("an extension that is not a sequence", _certificate(_tlv(0x02, b"\x00"))),
            ("an extension with only an oid", _certificate(_tlv(0x30, _oid_element(KEY_USAGE)))),
            (
                "an extension value that is not an octet string",
                _certificate(_tlv(0x30, _oid_element(KEY_USAGE), _tlv(0x02, b"\x00"))),
            ),
            (
                "an extension with no oid at all",
                _certificate(_tlv(0x30, _tlv(0x04, b""), _tlv(0x04, b""))),
            ),
            (
                "an empty object identifier",
                _certificate(_tlv(0x30, _tlv(0x06, b""), _tlv(0x04, b""))),
            ),
            (
                "an object identifier that ends mid-arc",
                _certificate(_tlv(0x30, _tlv(0x06, b"\x55\x80"), _tlv(0x04, b""))),
            ),
        ],
    )
    def test_malformed_input_reads_as_nothing(self, name, der) -> None:
        assert read_client_purpose(der) is None, name


class TestWhatTheReaderReadsAsNoPurpose:
    """The certificates it understands completely, and that grant nothing.

    These are the other half of the pair: `None` means the reader could not
    read, and a purpose of all-False means it read a certificate that says
    nothing. Both end in a refusal, but only the second one is a statement the
    issuer made, and conflating them would hide a malformation behind a policy
    verdict.
    """

    def test_a_certificate_with_no_extensions_at_all(self) -> None:
        purpose = read_client_purpose(_tlv(0x30, _tlv(0x30)))
        assert purpose == CertificatePurpose(client_auth=False, digital_signature=False)

    def test_a_key_usage_that_grants_nothing(self) -> None:
        """A `BIT STRING` carrying its unused-bit count and no bits."""
        extension = _tlv(0x30, _oid_element(KEY_USAGE), _tlv(0x04, _tlv(0x03, b"\x00")))
        purpose = read_client_purpose(_certificate(extension))
        assert purpose == CertificatePurpose(client_auth=False, digital_signature=False)

    def test_an_extension_this_reader_does_not_care_about(self) -> None:
        """A multi-byte arc, which is also the only place the OID decoder's
        continuation path is reachable: no extension it looks for has one."""
        extension = _tlv(0x30, _tlv(0x06, b"\x55\x1d\x81\x00"), _tlv(0x04, b""))
        purpose = read_client_purpose(_certificate(extension))
        assert purpose == CertificatePurpose(client_auth=False, digital_signature=False)

    def test_an_extended_key_usage_holding_something_that_is_not_an_oid(self) -> None:
        value = _tlv(0x04, _tlv(0x30, _tlv(0x02, b"\x00")))
        extension = _tlv(0x30, _oid_element(EXTENDED_KEY_USAGE), value)
        purpose = read_client_purpose(_certificate(extension))
        assert purpose == CertificatePurpose(client_auth=False, digital_signature=False)
