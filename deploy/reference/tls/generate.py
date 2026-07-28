# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Generate the ephemeral PKI the reference deployment runs on (ADR 0004 §3).

Everything produced here is thrown away when the stack comes down, and
`.gitignore` refuses to stage any of it rather than trusting anyone to remember.

**Why this is Python and not the openssl CLI.** The first version was a shell
script using `openssl x509 -not_after`, which is the only way that CLI expresses
a sub-day lifetime — `-days` counts whole days. That option is recent: it worked
against OpenSSL 3.6 locally and failed against the 3.0 on the CI runner, with
the error invisible because the script had redirected stderr to /dev/null for
tidiness. Two things were wrong, and the version skew was the less interesting
one: the tooling silently disagreed across machines about a value that *is* the
security property here, since short-lived certificates are the entire revocation
story. Expressing it in code that runs identically everywhere removes the
disagreement instead of papering over it.

The output layout is what the deployment mounts, and the split is the point:

    ca/       the signing key. Mounted into nothing at all. An agent that could
              read it could mint a certificate naming itself any principal, and
              every other control here would be decoration.
    gateway/  server cert + key, and the CA *certificate* to verify clients with.
    agent/    client cert + key, and the CA certificate to verify the gateway.

What this does not provide is a secret-at-rest guarantee. A bind mount is
readable by anyone with access to the host; it demonstrates custody separation
between containers and nothing more. See README.md.
"""

from __future__ import annotations

import argparse
import datetime as dt
import shutil
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HERE = Path(__file__).resolve().parent

#: One hour, well below the 24-hour cap the gateway enforces. This number is a
#: security property rather than a convenience: there is no CRL and no OCSP, so
#: a leaked certificate stays valid until it expires.
DEFAULT_LIFETIME_MINUTES = 60

#: SPIFFE-shaped, and a URI SAN rather than a CN or a DNS name. The gateway reads
#: exactly one URI SAN as the ClientPrincipal; none, or more than one, is refused
#: at connection time, because an ambiguous identity is not an identity.
DEFAULT_PRINCIPAL = "spiffe://secondsign.example/agent/reference"

#: The name the agent resolves. A mismatch fails TLS hostname verification, which
#: is the correct behaviour and a confusing thing to debug, so it is named once.
DEFAULT_GATEWAY_DNS = "gateway"


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            # Unencrypted, deliberately: this is an ephemeral test PKI, and a
            # passphrase here would imply a protection the deployment does not
            # claim. Custody is the mount, not the cipher.
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def build_ca(now: dt.datetime) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """The CA. Longer-lived than the leaves it signs.

    Rotating a CA means overlapping an old and a new one in the bundle, which is
    a different operation from a leaf expiring. Giving them the same lifetime
    would make rotation impossible to rehearse.
    """
    key = _key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecondSign reference CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def build_leaf(
    *,
    common_name: str,
    san: x509.SubjectAlternativeName,
    eku: x509.ExtendedKeyUsage,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    now: dt.datetime,
    lifetime: dt.timedelta,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = _key()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        # `notBefore` is now, not a minute ago. The lifetime the suite measures
        # is notAfter - notBefore, and backdating the start would quietly buy
        # extra validity beyond what this claims to issue.
        .not_valid_before(now)
        .not_valid_after(now + lifetime)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(san, critical=False)
        .add_extension(eku, critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def generate(
    *,
    root: Path = HERE,
    lifetime_minutes: int = DEFAULT_LIFETIME_MINUTES,
    principal: str = DEFAULT_PRINCIPAL,
    gateway_dns: str = DEFAULT_GATEWAY_DNS,
) -> dict[str, Path]:
    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    lifetime = dt.timedelta(minutes=lifetime_minutes)

    ca_dir, gateway_dir, agent_dir = root / "ca", root / "gateway", root / "agent"
    for directory in (ca_dir, gateway_dir, agent_dir):
        shutil.rmtree(directory, ignore_errors=True)
        directory.mkdir(parents=True)

    ca_key, ca_cert = build_ca(now)
    _write_key(ca_dir / "ca-key.pem", ca_key)
    _write_cert(ca_dir / "ca-cert.pem", ca_cert)

    gateway_key, gateway_cert = build_leaf(
        common_name=gateway_dns,
        san=x509.SubjectAlternativeName([x509.DNSName(gateway_dns)]),
        eku=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
        ca_key=ca_key,
        ca_cert=ca_cert,
        now=now,
        lifetime=lifetime,
    )
    _write_key(gateway_dir / "gateway-key.pem", gateway_key)
    _write_cert(gateway_dir / "gateway-cert.pem", gateway_cert)

    client_key, client_cert = build_leaf(
        common_name="reference-agent",
        san=x509.SubjectAlternativeName([x509.UniformResourceIdentifier(principal)]),
        eku=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
        ca_key=ca_key,
        ca_cert=ca_cert,
        now=now,
        lifetime=lifetime,
    )
    _write_key(agent_dir / "client-key.pem", client_key)
    _write_cert(agent_dir / "client-cert.pem", client_cert)

    # The CA *certificate* goes to both sides so each can verify the other. The
    # CA *key* stays in ca/, which compose.yaml mounts into nothing.
    for directory in (gateway_dir, agent_dir):
        _write_cert(directory / "ca-cert.pem", ca_cert)

    return {
        "ca_key": ca_dir / "ca-key.pem",
        "gateway_cert": gateway_dir / "gateway-cert.pem",
        "client_cert": agent_dir / "client-cert.pem",
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lifetime-minutes", type=int, default=DEFAULT_LIFETIME_MINUTES)
    parser.add_argument("--principal", default=DEFAULT_PRINCIPAL)
    parser.add_argument("--gateway-dns", default=DEFAULT_GATEWAY_DNS)
    args = parser.parse_args(argv[1:])

    written = generate(
        lifetime_minutes=args.lifetime_minutes,
        principal=args.principal,
        gateway_dns=args.gateway_dns,
    )
    print(
        f"issued: principal {args.principal}, valid {args.lifetime_minutes}m, "
        f"client cert at {written['client_cert']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
