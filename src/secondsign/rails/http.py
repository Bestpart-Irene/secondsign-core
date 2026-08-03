# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""An HTTP rail executor — the generic credential-holding driver.

The Stripe executor speaks one vendor's SDK. This one speaks HTTP to whatever
endpoint a deployment points it at, which is what the reference deployment's
mock rail needs and what an operator with an internal payments service needs. It
holds the credential and makes the outbound call, so it lives on the trusted
side: the gateway injects it, and the managed agent has no path to it.

The three-state outcome is the whole reason this is not four lines of `urlopen`.
What the caller must never be told is "it failed" when the truth is "we do not
know":

- **success** — a 2xx. The rail accepted it.
- **failure** — a 4xx. A definite rejection; the request was understood and
  declined, and money did not move.
- **unknown** — a 5xx, a timeout, a connection error, an unparseable answer.
  The request may have been processed. Reconciled through the same idempotency
  key, never re-dispatched, and never recorded as a failure (B8).

The credential goes in a header and nowhere else — not in the URL, which is
logged by every proxy in the path, and not in the body, which the rail may echo.
It is never rendered: this object's ``repr`` does not include it, and no refusal
or error return carries it.
"""

from __future__ import annotations

import http.client
import json
import urllib.error
import urllib.request
from typing import Final

from secondsign.gateway.execution import ExecutionStatus, RailResult
from secondsign.intent import TransactionIntent


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect handler that never redirects.

    The default opener follows 3xx and re-sends the request — with the
    ``Authorization`` header intact — to the ``Location`` target, across hosts
    and across an https→http downgrade. For a component whose whole job is
    holding a credential, that is credential exfiltration one misconfigured
    rail away; and a redirect whose target answers 200 would be read as
    ``success`` for a payment the real rail never processed. Returning ``None``
    from ``redirect_request`` leaves the 3xx response in place, so
    :func:`_status_for` reads it as ``unknown`` — the rail's state genuinely is
    unknowable through a redirect this side refuses to follow.
    """

    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


#: One opener, built once, with redirects refused. The credential travels only
#: to the configured URL and to nowhere a 3xx would send it.
_OPENER: Final = urllib.request.build_opener(_NoRedirect())

#: The header the gateway stamps on every request it dispatches. A label for
#: reconciliation, not a control: anything could set it. What makes it useful is
#: the *other* side of the comparison — a request bearing it with no matching
#: dispatch on the gateway's side is the shape of a forgery, and a request
#: without it is the shape of a bypass.
VIA_HEADER: Final[str] = "X-SecondSign-Via"

#: Bounded, because a rail that never answers must not hold an authorization
#: open. Timing out is `unknown`, not failure.
TIMEOUT_SECONDS: Final[float] = 10.0


class HTTPRailExecutor:
    """Dispatches an intent to an HTTP endpoint, holding the credential."""

    __slots__ = ("_url", "_credential")

    def __init__(self, url: str, credential: str) -> None:
        self._url = url
        self._credential = credential

    def dispatch(self, intent: TransactionIntent) -> RailResult:
        body = json.dumps(
            {
                # Already-redacted values only. The rail is told what to move and
                # between which opaque references; it is not told who asked, and
                # nothing here is free text.
                "amount_minor": intent.dimensions.value_upper_minor,
                "currency": intent.dimensions.quote_currency.value,
                "counterparty_ref": intent.dimensions.counterparty_ref,
                "source_account_ref": intent.dimensions.source_account_ref,
                "idempotency_key": intent.idempotency_key,
            }
        ).encode()
        request = urllib.request.Request(  # noqa: S310 — the URL is operator configuration
            self._url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._credential}",
                "Idempotency-Key": intent.idempotency_key,
                VIA_HEADER: "gateway",
            },
        )
        try:
            with _OPENER.open(request, timeout=TIMEOUT_SECONDS) as response:
                return RailResult(status=_status_for(response.status), reference=None)
        except urllib.error.HTTPError as exc:
            # An HTTP error still carries a status, and the status is the whole
            # distinction between a decline and a maybe.
            return RailResult(status=_status_for(exc.code), reference=None)
        except (OSError, http.client.HTTPException):
            # Connection refused, DNS failure, timeout, a reset mid-response
            # (OSError); or a non-HTTP answer — a garbage status line, a wrong
            # service on the port — which raises `http.client.HTTPException`,
            # *not* an OSError. The request may have been processed either way,
            # so dispatch must answer rather than let the exception escape into
            # a money-moving path with no receipt written (INV-11): `unknown` is
            # the honest state, reconciled through the idempotency key.
            return RailResult(status=ExecutionStatus.unknown, reference=None)

    def __repr__(self) -> str:
        """Names the endpoint, never the credential."""
        return f"HTTPRailExecutor(url={self._url!r})"


def _status_for(code: int) -> ExecutionStatus:
    if 200 <= code < 300:
        return ExecutionStatus.success
    if 400 <= code < 500:
        return ExecutionStatus.failure
    # 5xx, and anything outside the ranges above: the rail's own state is not
    # something this side can conclude, so it is reconciled rather than judged.
    return ExecutionStatus.unknown
