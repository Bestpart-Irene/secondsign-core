# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The gateway process: TLS termination and workload identity (CORE-S019).

This module is what `python -m secondsign.gateway.server` runs — the standalone
process that ADR 0003 committed to. It terminates mTLS, derives the caller's
identity from the certificate, and hands what survives to
:mod:`secondsign.gateway.authorization`, which is where a proposal becomes a
decided action.

It authorizes nothing on its own. Everything below the identity check is
transport: read a bounded body, refuse a smuggled principal, refuse an
unrecognised dialect, and pass a validated proposal to the decision path. A
deployment with no rail configured has no decision path, and then this process
answers 503 — unavailability, which is a refusal, and never a locally invented
verdict.

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

Before any of that, the leaf must have been issued to be a client at all: a
`keyUsage` permitting signature and an `extendedKeyUsage` naming client
authentication, both present, read from the DER by
:mod:`secondsign.gateway.leaf` because `getpeercert` reports neither. The
handshake would already refuse extensions that are present and wrong; what this
adds is that *absent* is not a pass, and that a purpose check is a condition
this process states rather than one it inherits from a library default.

The rail credential never enters this module's configuration object. It passes
from the environment straight into the rail executor and stops there, so no
repr, log line, or refusal detail can leak what this process was trusted with —
a property a red-team case asserts by grepping the config's repr.
"""

from __future__ import annotations

import ipaddress
import json
import os
import ssl
import sys
import threading
from datetime import datetime, timezone
from enum import StrEnum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Final, Mapping, cast
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, ValidationError

from secondsign.agent.surface import AuthorizationRequest
from secondsign.agent.wire import PRINCIPAL_FIELDS, SUPPORTED_WIRE_VERSIONS, WIRE_VERSION
from secondsign.audit import AuditLog, InMemoryAuditSink
from secondsign.contracts import Currency
from secondsign.controlplane.fingerprint import FingerprintKey
from secondsign.controlplane.window import WindowLedger
from secondsign.decision import DecisionEngine
from secondsign.gateway.authorization import AuthorizationService
from secondsign.gateway.execution import ExecutionGateway, InMemoryIdempotencyStore
from secondsign.gateway.leaf import read_client_purpose
from secondsign.policy import AmountLimit, AmountWindowPolicy, CurrencyCoveragePolicy
from secondsign.rails.http import HTTPRailExecutor

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

#: The approver channel's settings (CORE-S023). Declared here, in the process's
#: one settings registry, and imported by `secondsign.gateway.approver` — the
#: loader and the unknown-setting refusal must agree on this list, and two
#: copies of it would be how they stop agreeing.
APPROVER_SETTINGS: Final[frozenset[str]] = frozenset(
    {
        "SECONDSIGN_APPROVER_BIND",
        "SECONDSIGN_APPROVER_TLS_CERT",
        "SECONDSIGN_APPROVER_TLS_KEY",
        "SECONDSIGN_APPROVER_CA",
        "SECONDSIGN_APPROVER_ALLOWLIST",
    }
)

#: Every setting this process reads. Anything else under the prefix is a refusal
#: to start. The rail entries are read by `build_authorization` and consumed by
#: the rail executor; `load_config` never stores their values, so the credential
#: is not reachable through anything this module renders.
KNOWN_SETTINGS: Final[frozenset[str]] = (
    frozenset(
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
    | APPROVER_SETTINGS
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
    #: The approver channel (CORE-S023) was configured in part. Half a channel
    #: is refused, never defaulted.
    incomplete_approver_channel = "incomplete_approver_channel"
    #: The approver CA and the agent client CA are one certificate (B6).
    shared_trust_anchor = "shared_trust_anchor"
    #: One URI holds credentials for both doors — its own checker (B6).
    principal_on_both_channels = "principal_on_both_channels"


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
    unreadable_certificate = "unreadable_certificate"
    not_for_client_authentication = "not_for_client_authentication"
    key_not_for_signing = "key_not_for_signing"


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


def verify_client_purpose(der: bytes | None) -> PrincipalRefusal | None:
    """Whether the peer's leaf was issued to be a client at all (ADR 0004 §4).

    The chain check settles who signed the certificate; it does not settle what
    the certificate is for. OpenSSL applies its `ssl_client` purpose while
    verifying a peer, so a `keyUsage` or `extendedKeyUsage` that is present and
    wrong already fails the handshake. What it does not do is treat *absence* as
    a failure — an unrestricted leaf is good for every purpose under RFC 5280 —
    and a CA that scopes nothing is a CA whose every leaf is a gateway
    credential. This gateway therefore requires both extensions to be present
    and to say so.

    The two conditions OpenSSL happens to reach first are still checked here.
    They are this process's conditions, and a later change to the listener's
    context must not be able to drop them without a test going red.
    """
    if not der:
        return PrincipalRefusal(reason=PrincipalRefusalReason.unreadable_certificate)
    purpose = read_client_purpose(der)
    if purpose is None:
        return PrincipalRefusal(reason=PrincipalRefusalReason.unreadable_certificate)
    if not purpose.client_auth:
        return PrincipalRefusal(reason=PrincipalRefusalReason.not_for_client_authentication)
    if not purpose.digital_signature:
        return PrincipalRefusal(reason=PrincipalRefusalReason.key_not_for_signing)
    return None


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

    def __init__(
        self,
        address: tuple[str, int],
        allowlist: frozenset[str],
        authorization: AuthorizationService | None = None,
    ) -> None:
        self.allowlist = allowlist
        #: None when the deployment configured no rail. The listener still
        #: authenticates and still refuses — it simply has nothing to authorize
        #: *onto*, and says so rather than inventing a verdict.
        self.authorization = authorization
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
            # Purpose before identity: a leaf that was not issued for client
            # authentication has no identity to derive, it has a misuse to
            # report. Reading the SAN out of it first would name the workload
            # whose credential is being presented for something it is not.
            self.identity = verify_client_purpose(
                self.connection.getpeercert(binary_form=True)
            ) or derive_principal(self.connection.getpeercert(), allowlist)
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

    def _respond(self, status: int, payload: dict[str, object]) -> None:
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

        self._authorize(payload)

    def _authorize(self, payload: dict[str, object]) -> None:
        """The dialect is right and the caller is who they said. Decide.

        Three refusals come before the decision path, and their order is the
        point: a deployment with no rail cannot authorize anything; a caller
        with no derived identity cannot be namespaced, audited or scoped; and a
        proposal that does not validate against the agent surface is not a
        proposal this contract can carry.
        """
        service = cast(_GatewayHTTPServer, self.server).authorization
        if service is None:
            # No rail configured. A refusal stated as unavailability, never a
            # locally invented verdict — the honest answer when this process
            # holds no credential to move anything with.
            self._respond(503, {"refused": "authorization_unavailable"})
            return

        principal = self.identity
        if not isinstance(principal, DerivedPrincipal):
            # Plaintext loopback: the process boundary authenticated the caller,
            # and that is enough to *reach* the gateway and not enough to be
            # one. An authorization needs a principal to namespace idempotency
            # by, scope policy to, and fingerprint into the trail.
            self._respond(403, {"refused": "no_identity"})
            return

        try:
            request = AuthorizationRequest.model_validate(payload.get("request"))
        except ValidationError:
            # The detail is deliberately absent: the validator's message quotes
            # the input, and the input is attacker-chosen bytes.
            self._respond(400, {"refused": "malformed_request"})
            return

        outcome = service.authorize(principal.uri, request, now=datetime.now(tz=timezone.utc))
        self._respond(
            200,
            {"wire_version": WIRE_VERSION, "outcome": outcome.model_dump(mode="json")},
        )

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


#: The reference deployment's demonstration limit: a rolling hour, capped in
#: minor units. It is deliberately a constant and deliberately not a setting.
#:
#: A real deployment's limits are control-plane state under an authority that
#: can be audited and relaxed on record (CORE-S017), not an environment variable
#: on the process that enforces them — an operator who can raise a limit by
#: editing the gateway's environment is an operator whose limit is a suggestion.
#: Until that path is wired, a fixed number that is visibly a demonstration is
#: more honest than a knob that looks like policy.
REFERENCE_WINDOW_SECONDS: Final[int] = 3600
REFERENCE_LIMIT_MINOR: Final[int] = 500_00

#: Above this, the reference deployment holds the action for a human — but only
#: when the approver channel is configured. A deployment that can reach REVIEW
#: with no channel would park proposals where no human can answer them, so the
#: band exists exactly when the door does (CORE-S022 left this deliberately
#: unset; CORE-S023 is the door).
REFERENCE_REVIEW_ABOVE_MINOR: Final[int] = 200_00


def build_authorization(
    environ: Mapping[str, str], *, review_band: bool = False
) -> AuthorizationService | None:
    """Assemble the decision path, if this deployment has a rail to move on.

    Returns None when either rail setting is absent: a gateway with no rail can
    still authenticate, still refuse, and still be stood up for a topology test,
    and it must not pretend to authorize onto a destination it does not have.

    The credential passes from the environment into the executor and stops
    there. It never enters :class:`GatewayConfig`, so no repr, log line or
    refusal detail anywhere in this module can carry it — which is a property a
    red-team case asserts by grepping.
    """
    url = environ.get("SECONDSIGN_RAIL_URL")
    credential = environ.get("SECONDSIGN_RAIL_API_KEY")
    if not url or not credential:
        return None

    limit = AmountLimit(
        quote_currency=Currency.USD,
        window_seconds=REFERENCE_WINDOW_SECONDS,
        max_aggregate_minor=REFERENCE_LIMIT_MINOR,
        review_above_minor=REFERENCE_REVIEW_ABOVE_MINOR if review_band else None,
    )
    # The limit governs USD; nothing else. Without a coverage policy an agent
    # naming any other currency would meet only abstentions and be ALLOWed with
    # no limit at all — permission is the absence of a concern, and an
    # unconfigured currency raised none. The coverage policy is that concern:
    # it denies every currency this deployment did not configure a limit for,
    # so the set here must equal the set of limits above.
    return AuthorizationService(
        engine=DecisionEngine(
            [AmountWindowPolicy(limit), CurrencyCoveragePolicy(covered={limit.quote_currency})]
        ),
        gateway=ExecutionGateway(HTTPRailExecutor(url, credential), InMemoryIdempotencyStore()),
        ledger=WindowLedger(window_seconds=limit.window_seconds),
        audit=AuditLog(InMemoryAuditSink()),
        # Generated per process. A restart therefore renders every earlier
        # reference unresolvable, which is the correct trade for a reference
        # deployment and is exactly what a durable control-plane key store
        # exists to fix (INV-12, CORE-S017).
        keys=FingerprintKey.generate(),
    )


def create_server(
    config: GatewayConfig, *, authorization: AuthorizationService | None = None
) -> GatewayServer | ConfigurationRefusal:
    """Bind the listener, or refuse.

    `load_config` proved the TLS material readable; this is where it must also
    parse. Garbage material is a refusal to start, never a listener that limps
    up without TLS.
    """
    http_server = _GatewayHTTPServer((config.host, config.port), config.allowlist, authorization)
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
    """The process entry point: configure, bind, serve until told to stop.

    One process, up to two listeners. The approver channel (CORE-S023) shares
    the authorization service — it must, because the pending store lives in it —
    and shares nothing else: its own trust anchor, its own allowlist, its own
    bind address. Every refusal below happens before either listener serves a
    byte, so a process that starts is one whose channel separation held.
    """
    # A function-level import, deliberately: `secondsign.gateway.approver`
    # imports this module's helpers, and the settings registry lives here so
    # the two cannot disagree about what is recognised.
    from secondsign.gateway.approver import (
        ApproverServer,
        check_channel_separation,
        create_approver_server,
        load_approver_config,
    )

    env: Mapping[str, str] = os.environ if environ is None else environ
    config = load_config(env)
    if isinstance(config, ConfigurationRefusal):
        print(f"refusing to start: {config.reason.value}: {config.detail}", file=sys.stderr)
        return 2
    approver_config = load_approver_config(env)
    if isinstance(approver_config, ConfigurationRefusal):
        print(
            f"refusing to start: {approver_config.reason.value}: {approver_config.detail}",
            file=sys.stderr,
        )
        return 2
    if approver_config is not None:
        separation = check_channel_separation(
            approver_config,
            agent_client_ca=config.tls.client_ca if config.tls is not None else None,
            agent_allowlist=config.allowlist,
        )
        if separation is not None:
            print(
                f"refusing to start: {separation.reason.value}: {separation.detail}",
                file=sys.stderr,
            )
            return 2

    # The review band exists exactly when the approver channel does: a
    # deployment that can park an action for a human must hold a door a human
    # can answer through, and one that cannot must never park anything.
    authorization = build_authorization(env, review_band=approver_config is not None)
    server = create_server(config, authorization=authorization)
    if isinstance(server, ConfigurationRefusal):
        print(f"refusing to start: {server.reason.value}: {server.detail}", file=sys.stderr)
        return 2

    approver_server: "ApproverServer | None" = None
    if approver_config is not None:
        built = create_approver_server(approver_config, authorization=authorization)
        if isinstance(built, ConfigurationRefusal):
            server.close()
            print(
                f"refusing to start: {built.reason.value}: {built.detail}",
                file=sys.stderr,
            )
            return 2
        approver_server = built

    host, port = server.bound_address
    mode = "mTLS" if config.tls is not None else "plaintext loopback"
    rail = "rail configured" if authorization is not None else "no rail: refusing all"
    print(f"gateway listening on {host}:{port} ({mode}, {rail})", flush=True)
    if approver_server is not None:
        approver_host, approver_port = approver_server.bound_address
        print(
            f"approver channel listening on {approver_host}:{approver_port} (mTLS)",
            flush=True,
        )
    try:
        if approver_server is not None:
            approver_thread = threading.Thread(target=approver_server.serve_forever, daemon=True)
            approver_thread.start()
        server.serve_forever()
    except KeyboardInterrupt:
        return 130
    finally:
        if approver_server is not None:
            approver_server.shutdown()
            approver_server.close()
        server.close()
    return 0


if __name__ == "__main__":  # pragma: no cover — the module trampoline; main() is tested directly
    raise SystemExit(main())
