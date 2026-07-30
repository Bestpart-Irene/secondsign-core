# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The HTTP rail executor: three states, and a credential that does not travel.

The interesting cases here are all about the boundary between "declined" and
"we do not know". Getting that wrong in the safe-looking direction — calling an
indeterminate dispatch a failure — is how a retry becomes a double-spend.

Driven against a real loopback HTTP server rather than a mocked `urlopen`: what
is being asserted is how this code reads a *rail's* answer, and a mock of the
transport would let the test and the code agree about a status neither ever
produced.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from secondsign.contracts import Currency, RailClass, Reversibility, SourceTrust
from secondsign.gateway import ExecutionStatus
from secondsign.intent import (
    DecisionDimensions,
    PaymentPayload,
    PaymentTargetKind,
    SettlementPriority,
    TransactionIntent,
)
from secondsign.rails.http import VIA_HEADER, HTTPRailExecutor

CREDENTIAL = "sk_reference_not_a_real_key"
NOW = datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc)


def make_intent(amount_minor: int = 4_200) -> TransactionIntent:
    return TransactionIntent(
        dimensions=DecisionDimensions(
            value_lower_minor=amount_minor,
            value_upper_minor=amount_minor,
            quote_currency=Currency.USD,
            counterparty_ref="fp:" + "a1" * 32,
            source_account_ref="fp:" + "b2" * 32,
            rail_class=RailClass.card,
            not_before=NOW,
            not_after=NOW + timedelta(minutes=5),
            reversibility=Reversibility.irreversible,
            source_trust=SourceTrust.untrusted_data,
            scope_count=1,
        ),
        payload=PaymentPayload(
            target_kind=PaymentTargetKind.card,
            new_beneficiary=True,
            cross_border=True,
            settlement_priority=SettlementPriority.standard,
        ),
        idempotency_key="reservation-1",
    )


class _Rail(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler, status: int) -> None:
        self.status = status
        self.received: list[dict[str, object]] = []
        super().__init__(address, handler)


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler's dispatch name
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        # Lower-cased on the way in, because header names are case-insensitive
        # and urllib re-capitalises what it is given: `X-SecondSign-Via` leaves
        # this process as `X-secondsign-via`. Any conforming server matches it
        # either way; a test indexing a plain dict would not.
        self.server.received.append(
            {
                "headers": {name.lower(): value for name, value in self.headers.items()},
                "body": body,
            }
        )
        payload = b'{"status": "recorded"}'
        self.send_response(self.server.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Silent."""


@pytest.fixture
def rail():
    """A loopback rail that answers with whatever status it is built for."""

    def _build(status: int = 200):
        server = _Rail(("127.0.0.1", 0), _Handler, status)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address[:2]
        _build.servers.append((server, thread))
        return server, f"http://{host}:{port}/dispatch"

    _build.servers = []
    yield _build
    for server, thread in _build.servers:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


class TestTheThreeStates:
    @pytest.mark.parametrize(
        ("code", "expected"),
        [
            (200, ExecutionStatus.success),
            (201, ExecutionStatus.success),
            (400, ExecutionStatus.failure),
            (402, ExecutionStatus.failure),
            (409, ExecutionStatus.failure),
            (500, ExecutionStatus.unknown),
            (503, ExecutionStatus.unknown),
        ],
    )
    def test_the_status_decides_the_outcome(self, rail, code, expected) -> None:
        _, url = rail(code)

        result = HTTPRailExecutor(url, CREDENTIAL).dispatch(make_intent())

        assert result.status is expected

    def test_nothing_listening_is_unknown_not_failure(self, rail) -> None:
        """The request may have been processed. Assuming failure is how a retry
        becomes a second payment."""
        server, url = rail(200)
        server.shutdown()
        server.server_close()

        result = HTTPRailExecutor(url, CREDENTIAL).dispatch(make_intent())

        assert result.status is ExecutionStatus.unknown

    def test_an_unroutable_host_is_unknown(self) -> None:
        executor = HTTPRailExecutor("http://rail.invalid.example:9/dispatch", CREDENTIAL)

        assert executor.dispatch(make_intent()).status is ExecutionStatus.unknown

    def test_no_rail_reference_is_invented(self, rail) -> None:
        _, url = rail(200)

        assert HTTPRailExecutor(url, CREDENTIAL).dispatch(make_intent()).reference is None


class TestWhatTravels:
    def test_the_credential_goes_in_a_header_and_nowhere_else(self, rail) -> None:
        server, url = rail(200)

        HTTPRailExecutor(url, CREDENTIAL).dispatch(make_intent())

        sent = server.received[0]
        assert sent["headers"]["authorization"] == f"Bearer {CREDENTIAL}"
        assert CREDENTIAL not in sent["body"].decode(), "the credential was in the body"
        assert CREDENTIAL not in url, "the credential was in the URL, where proxies log it"

    def test_the_dispatch_is_labelled_for_reconciliation(self, rail) -> None:
        server, url = rail(200)

        HTTPRailExecutor(url, CREDENTIAL).dispatch(make_intent())

        assert server.received[0]["headers"][VIA_HEADER.lower()] == "gateway"

    def test_the_idempotency_key_travels_so_the_rail_can_deduplicate(self, rail) -> None:
        server, url = rail(200)

        HTTPRailExecutor(url, CREDENTIAL).dispatch(make_intent())

        sent = server.received[0]
        assert sent["headers"]["idempotency-key"] == "reservation-1"
        assert json.loads(sent["body"])["idempotency_key"] == "reservation-1"

    def test_only_redacted_values_are_sent(self, rail) -> None:
        server, url = rail(200)

        HTTPRailExecutor(url, CREDENTIAL).dispatch(make_intent())

        body = json.loads(server.received[0]["body"])
        assert set(body) == {
            "amount_minor",
            "currency",
            "counterparty_ref",
            "source_account_ref",
            "idempotency_key",
        }
        assert body["counterparty_ref"].startswith("fp:")

    def test_the_repr_names_the_endpoint_and_not_the_credential(self) -> None:
        executor = HTTPRailExecutor("http://rail:9000/dispatch", CREDENTIAL)

        assert CREDENTIAL not in repr(executor)
        assert "rail:9000" in repr(executor)
