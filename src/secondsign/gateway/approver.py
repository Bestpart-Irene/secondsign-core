# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The approver's channel: a second listener the agent has no route to (CORE-S023).

`CORE-S022` built the flow — a `REVIEW` verdict parks the proposal in the
control-plane pending store, and a checker's answer re-decides, consumes the
one-shot and dispatches. What it deliberately did not build is the door the
checker walks through. This module is that door, and its whole design is that
it is a *different* door from the agent's:

**Its own trust anchor.** The approver CA is a separate root from the agent
client CA, and the process refuses to start if the two files carry the same
certificate — a CA that can mint an agent credential must not be able to mint
an approver credential, or the compromise of one side is the compromise of
both (B6). Checked by bytes, not by path: two names for one file is the same
trust anchor wearing two hats.

**Its own population.** The approver allowlist and the agent allowlist must be
disjoint, and that is checked at startup rather than trusted. The maker-checker
already refuses self-approval by comparing subjects, but across the two
channels the maker subject is a keyed fingerprint and the checker subject is a
URI — they can never be equal, so that comparison cannot fire here. The
structural rule that replaces it is this one: no principal may hold a
credential for both doors.

**No plaintext, anywhere.** The agent channel's loopback concession (ADR 0004
§5) reasons from a process boundary: on loopback, the kernel authenticated the
caller. A checker is a person, and a person is remote; an approver channel
with no client certificate is an anonymous approver, which is not an approver.
mTLS or no listener.

**The checker never says who they are.** Identity is the certificate's single
URI SAN, derived by the same rules as the agent channel — and a body that
carries a principal field is refused, never ignored, for the same recorded
reason: an accepted-and-ignored field is one a later change can quietly start
honouring.

**An answer binds to what was displayed.** The resolve request restates the
proposal digest the checker was shown, and the verdict is built from *that*,
not from whatever the store currently holds — so a substitution between
display and answer is a `digest_mismatch` from the maker-checker, end to end
(B3).

In the reference deployment this listener binds to the gateway's address on
`approvernet`, a network the agent has no interface on, so "an agent cannot
reach the approval channel" (B6) is a fact about routing tables — and
`compose.approver-joined.yaml` exists so CI can prove the tests that assert it
are able to fail.
"""

from __future__ import annotations

import json
import ssl
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Final, Mapping, cast
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, ValidationError

from secondsign.agent.wire import PRINCIPAL_FIELDS
from secondsign.approval import CheckerIdentity, CheckerVerdict
from secondsign.controlplane.pending import PendingReview
from secondsign.gateway.server import (
    APPROVER_SETTINGS,
    ConfigurationRefusal,
    DerivedPrincipal,
    PrincipalRefusal,
    PrincipalRefusalReason,
    StartupRefusalReason,
    TLSTermination,
    build_ssl_context,
    derive_principal,
    verify_client_purpose,
)
from secondsign.intent import ProposalDigest

if TYPE_CHECKING:
    from secondsign.gateway.authorization import AuthorizationService

#: A resolve request is one digest and one word. A body over this is refused
#: before a byte of it is read.
MAX_RESOLVE_BODY_BYTES: Final[int] = 65_536

#: The two answers a checker can give. A closed set: there is no "escalate",
#: no "later", no third word that would let an answer be ambiguous.
_ANSWERS: Final[frozenset[str]] = frozenset({"approve", "decline"})


class ApproverConfig(BaseModel):
    """What the approver listener runs with. All of it, or no listener."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    host: str
    port: int
    tls: TLSTermination
    allowlist: frozenset[str]


def load_approver_config(
    environ: Mapping[str, str],
) -> ApproverConfig | ConfigurationRefusal | None:
    """Read the approver channel's settings, refuse them, or find none.

    ``None`` means the channel is not configured, which is a legitimate
    deployment: reviews are then held but unanswerable, and the reference
    deployment pairs that state with a limit that has no review band, so no
    action is ever parked where no human can reach it.

    A *partial* configuration is a refusal, not a channel that limps up with
    defaults — the operator who set two of five settings believes the other
    three did something.
    """
    present = {name: environ[name] for name in APPROVER_SETTINGS if environ.get(name)}
    if not present:
        return None
    missing = sorted(APPROVER_SETTINGS - set(present))
    if missing:
        return ConfigurationRefusal(
            reason=StartupRefusalReason.incomplete_approver_channel,
            detail=(
                f"approver channel configured in part: missing {', '.join(missing)}. "
                "Refused rather than defaulted: half a channel is not a channel."
            ),
        )

    bind = present["SECONDSIGN_APPROVER_BIND"]
    host, _, port_text = bind.rpartition(":")
    try:
        port = int(port_text)
    except ValueError:
        port = -1
    if not host or not 0 <= port <= 65535:
        return ConfigurationRefusal(
            reason=StartupRefusalReason.malformed_bind,
            detail=f"cannot parse {bind!r} as host:port (SECONDSIGN_APPROVER_BIND)",
        )

    certificate = present["SECONDSIGN_APPROVER_TLS_CERT"]
    key = present["SECONDSIGN_APPROVER_TLS_KEY"]
    approver_ca = present["SECONDSIGN_APPROVER_CA"]
    for path_text in (certificate, key, approver_ca):
        try:
            Path(path_text).read_bytes()
        except OSError as exc:
            return ConfigurationRefusal(
                reason=StartupRefusalReason.unreadable_tls_material,
                detail=f"cannot read {path_text}: {exc}",
            )

    entries = [
        entry
        for entry in present["SECONDSIGN_APPROVER_ALLOWLIST"].replace(",", " ").split()
        if entry
    ]
    if not entries:
        return ConfigurationRefusal(
            reason=StartupRefusalReason.missing_principal_allowlist,
            detail=(
                "no approver allowlist entries (SECONDSIGN_APPROVER_ALLOWLIST): a "
                "channel that can derive no checker has nobody it may serve"
            ),
        )
    for entry in entries:
        if "*" in entry:
            return ConfigurationRefusal(
                reason=StartupRefusalReason.wildcard_principal_entry,
                detail=f"wildcard entry {entry!r} in the approver allowlist",
            )
        parts = urlsplit(entry)
        if not parts.scheme or not parts.netloc:
            return ConfigurationRefusal(
                reason=StartupRefusalReason.malformed_principal_entry,
                detail=f"{entry!r} is not an absolute URI",
            )

    return ApproverConfig(
        host=host,
        port=port,
        tls=TLSTermination(
            certificate=Path(certificate), key=Path(key), client_ca=Path(approver_ca)
        ),
        allowlist=frozenset(entries),
    )


def check_channel_separation(
    approver: ApproverConfig, *, agent_client_ca: Path | None, agent_allowlist: frozenset[str]
) -> ConfigurationRefusal | None:
    """The two structural rules that make this a *second* channel (B6).

    Compared by content, not by configuration: two paths naming one CA file is
    one trust anchor, and one URI on both allowlists is one principal holding
    both credentials. Either way the separation the topology claims does not
    exist, and the process must not start claiming it.
    """
    if agent_client_ca is not None:
        try:
            same = agent_client_ca.read_bytes() == approver.tls.client_ca.read_bytes()
        except OSError as exc:
            return ConfigurationRefusal(
                reason=StartupRefusalReason.unreadable_tls_material,
                detail=f"cannot compare trust anchors: {exc}",
            )
        if same:
            return ConfigurationRefusal(
                reason=StartupRefusalReason.shared_trust_anchor,
                detail=(
                    "the approver CA and the agent client CA are the same "
                    "certificate: a CA that can mint an agent credential must "
                    "not be able to mint an approver credential"
                ),
            )
    overlap = sorted(approver.allowlist & agent_allowlist)
    if overlap:
        return ConfigurationRefusal(
            reason=StartupRefusalReason.principal_on_both_channels,
            detail=(
                f"{', '.join(overlap)} appears on both the agent and approver "
                "allowlists: a workload that can propose and approve is its own "
                "checker, which maker-checker exists to forbid"
            ),
        )
    return None


def render_review(review: PendingReview) -> dict[str, object]:
    """What a checker is shown about one held review.

    Everything here is already redacted upstream — fingerprints, minor units,
    closed enums, a digest — and nothing is added: the display is a projection
    of the stored review, never a second copy of anything.
    """
    request = review.request
    approval = review.approval
    return {
        "approval_id": review.approval_id,
        "proposal": approval.proposal.value,
        "action": request.action.value,
        "rail": request.rail.value,
        "amount_minor": request.amount_minor,
        "currency": request.currency.value,
        "counterparty_ref": request.counterparty_ref,
        "principal_ref": review.principal_ref,
        "reasons": [reason.value for reason in approval.decision.reasons],
        "expires_at": (
            approval.expires_at.isoformat() if approval.expires_at is not None else None
        ),
    }


class _ApproverHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        allowlist: frozenset[str],
        authorization: "AuthorizationService | None",
    ) -> None:
        self.allowlist = allowlist
        self.authorization = authorization
        super().__init__(address, _ApproverRequestHandler)


class _ApproverRequestHandler(BaseHTTPRequestHandler):
    """One connection, one checker, decided before any request is routed."""

    protocol_version = "HTTP/1.1"
    timeout = 30

    identity: DerivedPrincipal | PrincipalRefusal | None

    def setup(self) -> None:
        super().setup()
        if isinstance(self.connection, ssl.SSLSocket):
            allowlist = cast(_ApproverHTTPServer, self.server).allowlist
            self.identity = verify_client_purpose(
                self.connection.getpeercert(binary_form=True)
            ) or derive_principal(self.connection.getpeercert(), allowlist)
        else:
            # This channel is never plaintext (`load_approver_config` will not
            # produce a TLS-less listener), so this branch is reachable only if
            # a later change breaks that. It refuses rather than trusting the
            # claim above.
            self.identity = PrincipalRefusal(reason=PrincipalRefusalReason.no_identity)

    def version_string(self) -> str:
        return "secondsign-approver"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 — base class signature
        """Silent, for the same reason as the agent channel: the request line
        is caller-chosen bytes, and stderr must not out-record the audit trail."""

    def _respond(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload).encode()
        if status >= 400:
            self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _checker(self) -> DerivedPrincipal | None:
        if isinstance(self.identity, DerivedPrincipal):
            return self.identity
        reason = (
            self.identity.reason.value
            if isinstance(self.identity, PrincipalRefusal)
            else "no_identity"
        )
        self._respond(403, {"refused": reason})
        return None

    def _service(self) -> "AuthorizationService | None":
        service = cast(_ApproverHTTPServer, self.server).authorization
        if service is None:
            # No rail, no decision path, no reviews to hold. Unavailability,
            # stated as itself.
            self._respond(503, {"refused": "authorization_unavailable"})
            return None
        return service

    def do_GET(self) -> None:
        if self._checker() is None:
            return
        if self.path != "/reviews":
            self._respond(404, {"refused": "unknown_path"})
            return
        service = self._service()
        if service is None:
            return
        self._respond(
            200,
            {"reviews": [render_review(review) for review in service.open_reviews()]},
        )

    def do_POST(self) -> None:
        checker = self._checker()
        if checker is None:
            return
        prefix = "/reviews/"
        if not self.path.startswith(prefix) or len(self.path) <= len(prefix):
            self._respond(404, {"refused": "unknown_path"})
            return
        approval_id = self.path[len(prefix) :]

        try:
            declared = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            declared = -1
        if declared < 0:
            self._respond(400, {"refused": "malformed_body"})
            return
        if declared > MAX_RESOLVE_BODY_BYTES:
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
        if any(field in payload for field in PRINCIPAL_FIELDS) or "checker" in payload:
            # The checker is the certificate. A body that says otherwise is
            # refused as what it is, never ignored.
            self._respond(400, {"refused": "body_supplied_principal"})
            return

        answer = payload.get("answer")
        if answer not in _ANSWERS:
            self._respond(400, {"refused": "malformed_answer"})
            return
        try:
            proposal = ProposalDigest.model_validate({"value": payload.get("proposal")})
        except ValidationError:
            # The digest the checker claims to have seen must at least be a
            # digest. Whether it matches the held review is the maker-checker's
            # question, answered as `digest_mismatch` rather than here.
            self._respond(400, {"refused": "malformed_proposal"})
            return

        service = self._service()
        if service is None:
            return
        verdict = CheckerVerdict(
            checker=CheckerIdentity(subject=checker.uri),
            approval_id=approval_id,
            proposal=proposal,
            approved=answer == "approve",
        )
        resolution = service.resolve(approval_id, verdict, now=datetime.now(tz=timezone.utc))
        self._respond(
            200,
            {
                "status": resolution.status.value,
                "reason": resolution.reason.value if resolution.reason else None,
            },
        )


class ApproverServer:
    """A bound approver listener, not yet serving. The caller owns the loop."""

    def __init__(self, http_server: _ApproverHTTPServer) -> None:
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


def create_approver_server(
    config: ApproverConfig, *, authorization: "AuthorizationService | None"
) -> ApproverServer | ConfigurationRefusal:
    """Bind the approver listener under mTLS, or refuse. Never plaintext."""
    http_server = _ApproverHTTPServer((config.host, config.port), config.allowlist, authorization)
    try:
        context = build_ssl_context(
            cert=config.tls.certificate, key=config.tls.key, client_ca=config.tls.client_ca
        )
    except (ssl.SSLError, OSError) as exc:
        http_server.server_close()
        return ConfigurationRefusal(
            reason=StartupRefusalReason.unreadable_tls_material,
            detail=f"approver TLS material did not load: {exc}",
        )
    http_server.socket = context.wrap_socket(http_server.socket, server_side=True)
    return ApproverServer(http_server)
