# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The gateway process: TLS termination and workload identity (CORE-S019).

This module is what `python -m secondsign.gateway.server` runs — the standalone
process that ADR 0003 committed to. It terminates mTLS, derives the caller's
identity, and refuses everything it cannot yet do. What it deliberately is not:
an authorization endpoint. The wire contract is a later step of this slice, and
until it lands the only verdict this process can honestly give is a refusal.

**The seven-condition bind check** (ADR 0004 §5). On loopback, the process
boundary is the authentication and plaintext is permitted. Anywhere else the
gateway starts only when all seven conditions hold, and each is either checked
at startup or true by construction:

1. a server certificate            — checked: named and readable
2. its private key                 — checked: named and readable
3. a client CA bundle              — checked: named and readable; a certificate
                                     without one is an unauthenticated listener
                                     wearing encryption, refused not warned
4. client verification enabled     — by construction: ``CERT_REQUIRED`` is a
                                     constant; no setting reaches it
5. a minimum TLS version           — by construction: TLS 1.3 is a constant
6. a derivable principal           — checked: a non-empty allowlist of
                                     well-formed principal URIs
7. unknown principals fail closed  — by construction: no wildcard is
                                     representable (checked at startup), and an
                                     unlisted principal is refused per
                                     connection

A `SECONDSIGN_`-prefixed setting this module does not recognise is a refusal to
start, not a no-op: the operator who set ``SECONDSIGN_CLIENT_VERIFY=off``
believes it did something, and ignoring it would leave that belief intact. That
is also what keeps "a configuration setting that collapses the boundary"
inexpressible — the knob cannot exist quietly.

**Identity** (ADR 0004 §1). The `ClientPrincipal` is the certificate's single
URI SAN: none, more than one, malformed, over the 24-hour lifetime cap, or not
on the allowlist are all refusals. It is derived from the TLS session and from
nothing else — a request body that carries a principal is refused rather than
ignored, because an accepted-and-ignored field is one a later change can
quietly start honouring.

The rail credential never enters this module's configuration object. It stays
in the environment until the rail executor — a later step — consumes it, so no
repr, log line, or refusal detail can leak what this process was trusted with.
"""

from __future__ import annotations

import ipaddress
import json
import os
import ssl
import sys
from enum import StrEnum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Final, Mapping, cast
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict

from secondsign.agent.wire import PRINCIPAL_FIELDS, SUPPORTED_WIRE_VERSIONS

#: ADR 0004 §4: client leaf validity is capped at 24 hours, enforced rather than
#: recommended. With no CRL and no OCSP, this number is the entire revocation
#: story — a leaked certificate stays valid until it expires.
MAX_CLIENT_LEAF_SECONDS: Final[int] = 24 * 3600

#: An authorization request is small. A body over this is refused before a
#: single byte of it is read.
MAX_AUTHORIZE_BODY_BYTES: Final[int] = 1_048_576

#: Field names whose presence in a request body is a smuggled identity, and the
#: wire dialects this gateway speaks — both re-exported from the boundary's own
#: declaration rather than restated here. The agent-side distribution states the
#: version again in `secondsign_client.wire.WIRE_VERSION` because neither package
#: may import the other, and `tests/client/test_wire_contract.py` holds those two
#: equal; a third copy inside core would be drift with nothing to buy.
_PRINCIPAL_FIELDS: Final[tuple[str, ...]] = PRINCIPAL_FIELDS

#: Every setting this process reads. Anything else under the prefix is a refusal
#: to start. The rail entries are consumed by the rail executor when a later step
#: of CORE-S019 wires it; they are named here so the reference deployment's
#: environment is not refused, but `load_config` never stores their values.
KNOWN_SETTINGS: Final[frozenset[str]] = frozenset(
    {
        "SECONDSIGN_BIND",
        "SECONDSIGN_TLS_CERT",
        "SECONDSIGN_TLS_KEY",
        "SECONDSIGN_CLIENT_CA",
        "SECONDSIGN_CLIENT_ALLOWLIST",
        "SECONDSIGN_RAIL_URL",
        "SECONDSIGN_RAIL_API_KEY",
    }
)

_SETTING_PREFIX: Final[str] = "SECONDSIGN_"
_DEFAULT_BIND: Final[str] = "127.0.0.1:8787"


class StartupRefusalReason(StrEnum):
    """Why the gateway would not start. A closed set."""

    unknown_setting = "unknown_setting"
    malformed_bind = "malformed_bind"
    missing_server_certificate = "missing_server_certificate"
    missing_server_key = "missing_server_key"
    missing_client_ca = "missing_client_ca"
    unreadable_tls_material = "unreadable_tls_material"
    missing_principal_allowlist = "missing_principal_allowlist"
    malformed_principal_entry = "malformed_principal_entry"
    wildcard_principal_entry = "wildcard_principal_entry"


class ConfigurationRefusal(BaseModel):
    """A start that did not happen, and why. Distinct from a crash: nothing ran."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    reason: StartupRefusalReason
    detail: str


class PrincipalRefusalReason(StrEnum):
    """Why a connection's identity was rejected. A closed set."""

    no_identity = "no_identity"
    ambiguous_identity = "ambiguous_identity"
    malformed_identity = "malformed_identity"
    lifetime_beyond_cap = "lifetime_beyond_cap"
    unknown_principal = "unknown_principal"


class PrincipalRefusal(BaseModel):
    """An identity that did not derive. The connection it came from is served
    exactly one answer: a refusal."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    reason: PrincipalRefusalReason


class DerivedPrincipal(BaseModel):
    """An authenticated workload identity — the certificate's single URI SAN.

    Usable for policy scope, idempotency namespacing and audit correlation, and
    for nothing else. It is never an approval identity and never grants
    permission (ADR 0004)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    uri: str


class TLSTermination(BaseModel):
    """The material a non-loopback listener must hold. All three, or no listener."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    certificate: Path
    key: Path
    client_ca: Path


class GatewayConfig(BaseModel):
    """What the process runs with. Never carries a credential value: the rail
    key stays in the environment until the executor consumes it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    host: str
    port: int
    tls: TLSTermination | None
    allowlist: frozenset[str]


def _is_loopback(host: str) -> bool:
    """True only for a literal loopback address.

    A name — even ``localhost`` — is an indirection through a resolver, and the
    plaintext concession is scoped to what the kernel guarantees, not to what
    DNS asserts today. Names therefore fail closed into the non-loopback rules.
    """
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def load_config(environ: Mapping[str, str]) -> GatewayConfig | ConfigurationRefusal:
    """Read the environment into a configuration, or refuse to.

    Refusal-as-value, like every other verdict in this codebase: the caller
    branches on the type, and ``main`` turns a refusal into a non-zero exit.
    """
    settings = {k: v for k, v in environ.items() if k.startswith(_SETTING_PREFIX)}
    unknown = sorted(set(settings) - KNOWN_SETTINGS)
    if unknown:
        return ConfigurationRefusal(
            reason=StartupRefusalReason.unknown_setting,
            detail=(
                f"unrecognised settings: {', '.join(unknown)}. Refused rather than "
                "ignored: whatever these were meant to do, they did not do it."
            ),
        )

    bind = settings.get("SECONDSIGN_BIND", _DEFAULT_BIND)
    host, _, port_text = bind.rpartition(":")
    try:
        port = int(port_text)
    except ValueError:
        port = -1
    if not host or not 0 <= port <= 65535:
        return ConfigurationRefusal(
            reason=StartupRefusalReason.malformed_bind,
            detail=f"cannot parse {bind!r} as host:port",
        )

    certificate = settings.get("SECONDSIGN_TLS_CERT")
    key = settings.get("SECONDSIGN_TLS_KEY")
    client_ca = settings.get("SECONDSIGN_CLIENT_CA")
    allowlist_text = settings.get("SECONDSIGN_CLIENT_ALLOWLIST")

    if _is_loopback(host) and not any((certificate, key, client_ca, allowlist_text)):
        # On loopback the process boundary is the authentication (ADR 0004 §5).
        # Naming any TLS material, or an allowlist, opts into all seven
        # conditions — half a configuration is never quietly ignored.
        return GatewayConfig(host=host, port=port, tls=None, allowlist=frozenset())

    if not certificate:
        return ConfigurationRefusal(
            reason=StartupRefusalReason.missing_server_certificate,
            detail="a non-loopback listener requires a server certificate (SECONDSIGN_TLS_CERT)",
        )
    if not key:
        return ConfigurationRefusal(
            reason=StartupRefusalReason.missing_server_key,
            detail="the server certificate's private key is not named (SECONDSIGN_TLS_KEY)",
        )
    if not client_ca:
        return ConfigurationRefusal(
            reason=StartupRefusalReason.missing_client_ca,
            detail=(
                "no client CA bundle (SECONDSIGN_CLIENT_CA): a server certificate "
                "without client verification is an unauthenticated listener wearing "
                "encryption"
            ),
        )
    for path_text in (certificate, key, client_ca):
        try:
            Path(path_text).read_bytes()
        except OSError as exc:
            return ConfigurationRefusal(
                reason=StartupRefusalReason.unreadable_tls_material,
                detail=f"cannot read {path_text}: {exc}",
            )

    entries = [entry for entry in (allowlist_text or "").replace(",", " ").split() if entry]
    if not entries:
        return ConfigurationRefusal(
            reason=StartupRefusalReason.missing_principal_allowlist,
            detail=(
                "no principal allowlist (SECONDSIGN_CLIENT_ALLOWLIST): a gateway "
                "that can derive no principal has nobody it may serve"
            ),
        )
    for entry in entries:
        if "*" in entry:
            return ConfigurationRefusal(
                reason=StartupRefusalReason.wildcard_principal_entry,
                detail=(
                    f"wildcard entry {entry!r}: with no wildcard representable, "
                    '"unknown principals are allowed" is not an expressible '
                    "configuration"
                ),
            )
        parts = urlsplit(entry)
        if not parts.scheme or not parts.netloc:
            return ConfigurationRefusal(
                reason=StartupRefusalReason.malformed_principal_entry,
                detail=f"{entry!r} is not an absolute URI",
            )

    return GatewayConfig(
        host=host,
        port=port,
        tls=TLSTermination(certificate=Path(certificate), key=Path(key), client_ca=Path(client_ca)),
        allowlist=frozenset(entries),
    )


def build_ssl_context(
    *, cert: str | Path, key: str | Path, client_ca: str | Path
) -> ssl.SSLContext:
    """The listener's TLS parameters. Two of them are conditions of ADR 0004 §5
    and are constants here on purpose: ``CERT_REQUIRED`` and the TLS 1.3 floor
    have no configuration surface, so no setting can reach either."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=str(cert), keyfile=str(key))
    context.load_verify_locations(cafile=str(client_ca))
    return context


def derive_principal(
    peercert: Mapping[str, object] | None, allowlist: frozenset[str]
) -> DerivedPrincipal | PrincipalRefusal:
    """The `ClientPrincipal`, from a verified peer certificate and nothing else.

    ``peercert`` is what ``ssl.SSLSocket.getpeercert`` reports after a
    ``CERT_REQUIRED`` handshake, so the chain and validity dates have already
    been verified; what remains is identity policy. One URI SAN, well formed,
    within the lifetime cap, on the allowlist — ambiguous identity is no
    identity, and an unknown principal resolves fail-closed.
    """
    if not peercert:
        return PrincipalRefusal(reason=PrincipalRefusalReason.no_identity)

    san = cast(tuple[tuple[str, str], ...], peercert.get("subjectAltName", ()))
    uris = [value for kind, value in san if kind == "URI"]
    if not uris:
        return PrincipalRefusal(reason=PrincipalRefusalReason.no_identity)
    if len(uris) > 1:
        return PrincipalRefusal(reason=PrincipalRefusalReason.ambiguous_identity)

    uri = uris[0]
    parts = urlsplit(uri)
    if not parts.scheme or not parts.netloc:
        return PrincipalRefusal(reason=PrincipalRefusalReason.malformed_identity)

    not_before = peercert.get("notBefore")
    not_after = peercert.get("notAfter")
    if not isinstance(not_before, str) or not isinstance(not_after, str):
        return PrincipalRefusal(reason=PrincipalRefusalReason.malformed_identity)
    try:
        lifetime = ssl.cert_time_to_seconds(not_after) - ssl.cert_time_to_seconds(not_before)
    except ValueError:
        return PrincipalRefusal(reason=PrincipalRefusalReason.malformed_identity)
    if lifetime > MAX_CLIENT_LEAF_SECONDS:
        return PrincipalRefusal(reason=PrincipalRefusalReason.lifetime_beyond_cap)

    if uri not in allowlist:
        return PrincipalRefusal(reason=PrincipalRefusalReason.unknown_principal)
    return DerivedPrincipal(uri=uri)


class _GatewayHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], allowlist: frozenset[str]) -> None:
        self.allowlist = allowlist
        super().__init__(address, _RequestHandler)


class _RequestHandler(BaseHTTPRequestHandler):
    """One connection, one identity, decided before any request is routed."""

    protocol_version = "HTTP/1.1"
    #: A connection that stalls mid-request is dropped rather than held.
    timeout = 30

    identity: DerivedPrincipal | PrincipalRefusal | None

    def setup(self) -> None:
        super().setup()
        if isinstance(self.connection, ssl.SSLSocket):
            allowlist = cast(_GatewayHTTPServer, self.server).allowlist
            self.identity = derive_principal(self.connection.getpeercert(), allowlist)
        else:
            # Plaintext exists only on loopback, where the process boundary is
            # the authentication (ADR 0004 §5). There is no principal to derive
            # and no refusal to make.
            self.identity = None

    def version_string(self) -> str:
        return "secondsign-gateway"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 — base class signature
        """Silent. The raw request line is attacker-chosen bytes, and stderr
        must not receive more than the audit trail does — audit, when wired,
        records keyed fingerprints, never raw identifiers (ADR 0004 §1)."""

    def _respond(self, status: int, payload: dict[str, str]) -> None:
        body = json.dumps(payload).encode()
        if status >= 400:
            # A refused request may not have been read; a half-read connection
            # must not be reused.
            self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _refuse_unidentified(self) -> bool:
        """Identity is settled before any path, header or body is considered."""
        if isinstance(self.identity, PrincipalRefusal):
            self._respond(403, {"refused": self.identity.reason.value})
            return True
        return False

    def do_GET(self) -> None:
        if self._refuse_unidentified():
            return
        if self.path == "/healthz":
            # Reachable by a verified peer only, and says nothing a peer could
            # not learn by connecting: the process is up, and it cannot yet
            # authorize. No credential material is in scope here to leak.
            self._respond(200, {"gateway": "listening", "authorization": "unavailable"})
        else:
            self._respond(404, {"refused": "unknown_path"})

    def do_POST(self) -> None:
        if self._refuse_unidentified():
            return
        if self.path != "/authorize":
            self._respond(404, {"refused": "unknown_path"})
            return

        try:
            declared = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            declared = -1
        if declared < 0:
            self._respond(400, {"refused": "malformed_body"})
            return
        if declared > MAX_AUTHORIZE_BODY_BYTES:
            # Checked against the declaration, before any read: an attacker
            # does not get to make this process buffer an arbitrary body.
            self._respond(413, {"refused": "body_too_large"})
            return

        try:
            payload = json.loads(self.rfile.read(declared))
        except ValueError:
            self._respond(400, {"refused": "malformed_body"})
            return
        if not isinstance(payload, dict):
            self._respond(400, {"refused": "malformed_body"})
            return
        if self._carries_a_principal(payload):
            # Refused, never ignored: an accepted-and-ignored field is one a
            # later change can quietly start honouring (ADR 0004 §1). Checked
            # before the dialect, because a smuggled identity is refused as
            # what it is regardless of the version the body claims to speak.
            self._respond(400, {"refused": "body_supplied_principal"})
            return

        version = payload.get("wire_version")
        if isinstance(version, bool) or version not in SUPPORTED_WIRE_VERSIONS:
            # Refused rather than best-effort parsed (ADR 0003 §3). The bool
            # guard is not pedantry: True == 1 in Python, and a peer announcing
            # `true` is not announcing version one — it is announcing that its
            # serializer and this parser disagree about what a version is.
            self._respond(400, {"refused": "wire_version_unrecognised"})
            return

        # The dialect is right; the engine behind it is a later step of
        # CORE-S019. The gateway declares itself unable to authorize — a
        # refusal, stated as unavailability, and never a locally invented
        # verdict.
        self._respond(503, {"refused": "authorization_unavailable"})

    @staticmethod
    def _carries_a_principal(payload: dict[str, object]) -> bool:
        """A principal at the top level, or one level down in the wire
        envelope's ``request`` — the same claim in a different pocket."""
        if any(field in payload for field in _PRINCIPAL_FIELDS):
            return True
        request = payload.get("request")
        return isinstance(request, dict) and any(field in request for field in _PRINCIPAL_FIELDS)


class GatewayServer:
    """A bound listener, not yet serving. The caller owns the loop."""

    def __init__(self, http_server: _GatewayHTTPServer) -> None:
        self._http = http_server

    @property
    def bound_address(self) -> tuple[str, int]:
        host, port = self._http.server_address[:2]
        return str(host), int(port)

    def serve_forever(self) -> None:
        self._http.serve_forever(poll_interval=0.1)

    def shutdown(self) -> None:
        self._http.shutdown()

    def close(self) -> None:
        self._http.server_close()


def create_server(config: GatewayConfig) -> GatewayServer | ConfigurationRefusal:
    """Bind the listener, or refuse.

    `load_config` proved the TLS material readable; this is where it must also
    parse. Garbage material is a refusal to start, never a listener that limps
    up without TLS.
    """
    http_server = _GatewayHTTPServer((config.host, config.port), config.allowlist)
    if config.tls is not None:
        try:
            context = build_ssl_context(
                cert=config.tls.certificate, key=config.tls.key, client_ca=config.tls.client_ca
            )
        except (ssl.SSLError, OSError) as exc:
            http_server.server_close()
            return ConfigurationRefusal(
                reason=StartupRefusalReason.unreadable_tls_material,
                detail=f"TLS material did not load: {exc}",
            )
        http_server.socket = context.wrap_socket(http_server.socket, server_side=True)
    return GatewayServer(http_server)


def main(environ: Mapping[str, str] | None = None) -> int:
    """The process entry point: configure, bind, serve until told to stop."""
    env: Mapping[str, str] = os.environ if environ is None else environ
    config = load_config(env)
    if isinstance(config, ConfigurationRefusal):
        print(f"refusing to start: {config.reason.value}: {config.detail}", file=sys.stderr)
        return 2
    server = create_server(config)
    if isinstance(server, ConfigurationRefusal):
        print(f"refusing to start: {server.reason.value}: {server.detail}", file=sys.stderr)
        return 2

    host, port = server.bound_address
    mode = "mTLS" if config.tls is not None else "plaintext loopback"
    print(f"gateway listening on {host}:{port} ({mode})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 130
    finally:
        server.close()
    return 0


if __name__ == "__main__":  # pragma: no cover — the module trampoline; main() is tested directly
    raise SystemExit(main())
