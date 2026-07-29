# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The client's one verb, on the wire — and every failure reading as refused.

The success status has exactly one origin in this process: a well-formed,
correctly versioned response parsed by `secondsign_client.wire`. This module
never names that status. Everything that can go wrong on the way — nothing
listening, a refused handshake, a declining gateway, an unparseable body, a
dialect this client does not speak — collapses to a :class:`TransportRefusal`,
whose ``status`` is ``refused`` by construction and cannot be anything else.

Why so blunt: an agent that can distinguish "no" from "we could not tell" can
retry against the second one (INV-1). Gateway availability therefore becomes
payment availability, and the honest place to surface that is operator health
signals — never a softer verdict here (ADR 0003, consequences).

Plaintext exists only on literal loopback, mirroring the gateway's own rule: an
authorization request is exactly the message an attacker most wants to read or
replay, and off-host it travels under mutual TLS with the gateway's name
verified, or it does not travel. There is no setting that relaxes this.
"""

from __future__ import annotations

import http.client
import ipaddress
import ssl
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from secondsign_client.wire import (
    AgentOutcomeStatus,
    AuthorizationOutcome,
    AuthorizationRequest,
    WireRequest,
    WireResponse,
)


class TransportRefusalReason(StrEnum):
    """Why the client refused without an answer from the gateway. A closed set."""

    #: Nothing reachable at the configured address.
    gateway_unreachable = "gateway_unreachable"
    #: The TLS layer declined — a failed handshake, a rejected certificate.
    tls_rejected = "tls_rejected"
    #: The gateway answered, and the answer was not authorization.
    gateway_declined = "gateway_declined"
    #: The gateway answered something this dialect does not parse.
    malformed_response = "malformed_response"


class TransportRefusal(BaseModel):
    """A request that yielded no authorization. The status is ``refused`` by
    type, not by convention — there is no way to construct this carrying
    anything else."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: Literal[AgentOutcomeStatus.refused] = AgentOutcomeStatus.refused
    reason: TransportRefusalReason
    detail: str = ""


def _is_literal_loopback(host: str) -> bool:
    """True only for a literal loopback address. A name — even ``localhost`` —
    is an indirection through a resolver, and the plaintext concession is
    scoped to what the kernel guarantees."""
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class GatewayClient:
    """Speaks to one gateway. Holds a certificate, never a credential."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        ca_file: str | None = None,
        client_cert: str | None = None,
        client_key: str | None = None,
        timeout: float = 5.0,
    ) -> None:
        tls_parts = (ca_file, client_cert, client_key)
        if any(tls_parts) and not all(tls_parts):
            raise ValueError(
                "partial TLS configuration: ca_file, client_cert and client_key "
                "travel together or not at all"
            )
        if not all(tls_parts) and not _is_literal_loopback(host):
            raise ValueError(
                "plaintext is permitted on literal loopback only; off loopback "
                "this client requires mutual TLS"
            )
        self._host = host
        self._port = port
        self._timeout = timeout
        self._context: ssl.SSLContext | None = None
        if all(tls_parts):
            # Server-name verification stays on. The gateway's certificate
            # names the host the deployment dials; a client that skipped the
            # check would accept any holder of any leaf from the CA.
            context = ssl.create_default_context(cafile=ca_file)
            context.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
            self._context = context

    def request_authorization(
        self, request: AuthorizationRequest
    ) -> AuthorizationOutcome | TransportRefusal:
        """Ask, and read the answer. Never raises for a transport failure —
        the refusal is the answer."""
        body = WireRequest(request=request).model_dump_json().encode()
        connection: http.client.HTTPConnection
        if self._context is not None:
            connection = http.client.HTTPSConnection(
                self._host, self._port, context=self._context, timeout=self._timeout
            )
        else:
            connection = http.client.HTTPConnection(self._host, self._port, timeout=self._timeout)
        try:
            connection.request(
                "POST", "/authorize", body=body, headers={"Content-Type": "application/json"}
            )
            response = connection.getresponse()
            payload = response.read()
            status_code = response.status
        except ssl.SSLError as exc:
            return TransportRefusal(reason=TransportRefusalReason.tls_rejected, detail=str(exc))
        except (OSError, http.client.HTTPException) as exc:
            return TransportRefusal(
                reason=TransportRefusalReason.gateway_unreachable, detail=str(exc)
            )
        finally:
            connection.close()

        if status_code != 200:
            return TransportRefusal(
                reason=TransportRefusalReason.gateway_declined,
                detail=f"HTTP {status_code}",
            )
        try:
            parsed = WireResponse.model_validate_json(payload)
        except ValidationError:
            # The detail deliberately excludes the body: an unparseable answer
            # from the wrong listener is not something to echo into agent logs.
            return TransportRefusal(
                reason=TransportRefusalReason.malformed_response,
                detail="the response did not parse as this wire version",
            )
        return parsed.outcome
