# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The reference deployment's PKI, checked without Docker.

These run in the ordinary suite rather than behind the `deployment` marker, and
that is deliberate. The certificate properties below *are* security properties —
a one-hour lifetime is the entire revocation story when there is no CRL and no
OCSP — and verifying them only inside a container would mean they were checked
by one CI job that needs Docker, on one platform, at the end of a slow build.

The generator's first version made that cost concrete. It shelled out to
`openssl x509 -not_after`, which is the only way that CLI expresses a sub-day
lifetime, and which is recent enough to exist on a developer's OpenSSL 3.6 and
not on the runner's 3.0. Because generation ran inside the containerised gate,
the disagreement took two CI cycles to surface, and surfaced as "the agent
cannot read its own client key" — a mount error, four tests away from the cause.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from tests.deployment.conftest import REFERENCE


def _load_generator():
    """Load `deploy/reference/tls/generate.py`, which is a script, not a package."""
    import importlib.util

    path = REFERENCE / "tls" / "generate.py"
    spec = importlib.util.spec_from_file_location("secondsign_reference_pki", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = _load_generator()


@pytest.fixture(scope="module")
def issued(tmp_path_factory) -> dict[str, x509.Certificate]:
    """Generate a throwaway PKI in a temporary directory."""
    root = tmp_path_factory.mktemp("pki")
    generator.generate(root=root)
    return {
        "ca": _read(root / "ca" / "ca-cert.pem"),
        "gateway": _read(root / "gateway" / "gateway-cert.pem"),
        "client": _read(root / "agent" / "client-cert.pem"),
    }


def _read(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


class TestTheClientCertificateCarriesOneIdentity:
    """ADR 0004 §1. Ambiguous identity is not an identity."""

    def test_exactly_one_uri_san(self, issued) -> None:
        san = issued["client"].extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        uris = san.get_values_for_type(x509.UniformResourceIdentifier)

        assert len(uris) == 1, "the gateway reads one URI SAN; none or several is refused"

    def test_the_identity_is_the_configured_principal(self, issued) -> None:
        san = issued["client"].extensions.get_extension_for_class(x509.SubjectAlternativeName).value

        assert san.get_values_for_type(x509.UniformResourceIdentifier) == [
            generator.DEFAULT_PRINCIPAL
        ]

    def test_it_is_a_client_authentication_certificate(self, issued) -> None:
        eku = issued["client"].extensions.get_extension_for_class(x509.ExtendedKeyUsage).value

        assert list(eku) == [ExtendedKeyUsageOID.CLIENT_AUTH]


class TestLifetimeIsTheRevocationStory:
    """ADR 0004 §4. There is no CRL and no OCSP, so how long a leaked
    certificate stays valid is not a detail — it is the property."""

    def test_the_client_certificate_lasts_exactly_the_configured_hour(self, issued) -> None:
        cert = issued["client"]

        lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc

        assert lifetime == dt.timedelta(minutes=generator.DEFAULT_LIFETIME_MINUTES)

    def test_it_is_far_below_the_gateway_cap(self, issued) -> None:
        """The gateway refuses anything over 24 hours; the reference is 1."""
        cert = issued["client"]

        assert cert.not_valid_after_utc - cert.not_valid_before_utc <= dt.timedelta(hours=24)

    def test_the_start_is_not_backdated(self, issued) -> None:
        """Backdating notBefore would buy validity beyond what is claimed.

        The measured lifetime is notAfter - notBefore, so a generator that
        started an hour early would issue a two-hour certificate while every
        assertion about "one hour" still passed.
        """
        now = dt.datetime.now(dt.timezone.utc)

        assert issued["client"].not_valid_before_utc <= now
        assert issued["client"].not_valid_after_utc > now

    def test_a_shorter_lifetime_is_honoured(self, tmp_path) -> None:
        """The parameter is real, not decorative."""
        generator.generate(root=tmp_path, lifetime_minutes=5)
        cert = _read(tmp_path / "agent" / "client-cert.pem")

        assert cert.not_valid_after_utc - cert.not_valid_before_utc == dt.timedelta(minutes=5)


class TestTheGatewayCertificate:
    def test_it_is_a_server_authentication_certificate(self, issued) -> None:
        eku = issued["gateway"].extensions.get_extension_for_class(x509.ExtendedKeyUsage).value

        assert list(eku) == [ExtendedKeyUsageOID.SERVER_AUTH]

    def test_it_is_named_by_dns_so_hostname_verification_works(self, issued) -> None:
        san = (
            issued["gateway"].extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        )

        assert san.get_values_for_type(x509.DNSName) == [generator.DEFAULT_GATEWAY_DNS]


class TestTheCertificateAuthority:
    def test_the_ca_outlives_the_leaves_it_signs(self, issued) -> None:
        """Rotation and expiry are different operations.

        Giving the CA the same lifetime as a leaf would make CA rotation — an
        overlap of old and new in the bundle — impossible to rehearse.
        """
        ca, client = issued["ca"], issued["client"]

        assert ca.not_valid_after_utc > client.not_valid_after_utc

    def test_leaves_cannot_sign(self, issued) -> None:
        """A leaf that could sign would let its holder mint any principal."""
        for name in ("gateway", "client"):
            constraints = (
                issued[name].extensions.get_extension_for_class(x509.BasicConstraints).value
            )

            assert constraints.ca is False, f"the {name} certificate is a CA"


class TestCustodyLayout:
    """ADR 0004 §3. Which directory a file lands in decides which container
    can read it, so the layout is a security property rather than tidiness."""

    def test_the_signing_key_is_written_only_under_ca(self, tmp_path) -> None:
        generator.generate(root=tmp_path)

        assert (tmp_path / "ca" / "ca-key.pem").exists()
        assert not (tmp_path / "gateway" / "ca-key.pem").exists()
        assert not (tmp_path / "agent" / "ca-key.pem").exists()

    def test_each_side_gets_the_ca_certificate_but_not_the_ca_key(self, tmp_path) -> None:
        generator.generate(root=tmp_path)

        for side in ("gateway", "agent"):
            assert (tmp_path / side / "ca-cert.pem").exists()

    def test_neither_side_receives_the_other_s_private_key(self, tmp_path) -> None:
        generator.generate(root=tmp_path)

        assert not (tmp_path / "agent" / "gateway-key.pem").exists()
        assert not (tmp_path / "gateway" / "client-key.pem").exists()
