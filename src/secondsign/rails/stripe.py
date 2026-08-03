# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The Stripe rail executor — the credential-holding driver behind the gateway.

This is the one component that holds a Stripe key and makes an outbound call, so
it lives on the trusted side: the gateway injects it, and the managed agent has
no path to it (credential custody). It implements the S012 ``RailExecutor``
contract — ``dispatch(intent) -> RailResult`` — by moving money with a single
idempotent Stripe PaymentIntent, keyed on the adapter-derived idempotency key so
a retry can never double-spend (B2).

The whole reason the gateway's outcome is three-state lives here. Stripe's own
guidance is that a connection error is *indeterminate* — "don't assume it
succeeded or that it failed" — which is exactly ``unknown``:

- **success** — the PaymentIntent came back ``succeeded``.
- **failure** — a definite rejection that moved no money: a card decline, a bad
  request, a bad key, a rate limit.
- **unknown** — a network error or a Stripe server (5xx) error, where money may
  or may not have moved. Never treated as failure; reconciled via the same
  idempotency key or a retrieve (B8).

``stripe`` is an optional dependency (``secondsign[stripe]``); it is imported
lazily so the rest of core neither needs nor loads a payment SDK.
"""

from __future__ import annotations

from typing import Any

from secondsign.contracts import RailClass
from secondsign.gateway import ExecutionStatus, RailResult
from secondsign.intent import TransactionIntent

#: PaymentIntent statuses that mean money moved. Anything else terminal is a
#: failure; anything pending/ambiguous is reconciled as unknown.
_SUCCESS_STATUSES = frozenset({"succeeded"})
_FAILURE_STATUSES = frozenset({"canceled", "requires_payment_method"})


class StripePaymentExecutor:
    """Moves money via a Stripe PaymentIntent. Holds the key; agent never sees it."""

    rail_class: RailClass = RailClass.card

    def __init__(
        self,
        api_key: str,
        *,
        client: Any = None,
        payment_method: str = "pm_card_visa",
    ) -> None:
        # `client` defaults to the real stripe module (resolved lazily in
        # dispatch); tests inject a fake. `payment_method` is a Stripe test
        # PaymentMethod token by default, overridden in production.
        #
        # A missing optional SDK surfaces as an `ImportError` here in dispatch,
        # not an escaping crash: `ExecutionGateway.execute` catches any executor
        # exception and answers `unknown`, so a StripePaymentExecutor built
        # without the `stripe` extra fails closed rather than taking down a
        # money-moving path with no receipt (INV-11).
        self._api_key = api_key
        self._client = client
        self._payment_method = payment_method

    def dispatch(self, intent: TransactionIntent) -> RailResult:
        import stripe

        client = self._client if self._client is not None else stripe
        try:
            payment_intent = client.PaymentIntent.create(
                amount=intent.dimensions.value_upper_minor,
                currency=intent.dimensions.quote_currency.value.lower(),
                payment_method=self._payment_method,
                confirm=True,
                idempotency_key=intent.idempotency_key,
                api_key=self._api_key,
            )
        except (stripe.APIConnectionError, stripe.APIError):
            # Indeterminate: the request may have been processed. Reconcile via
            # the idempotency key; never a second dispatch, never a failure.
            return RailResult(status=ExecutionStatus.unknown, reference=None)
        except (
            stripe.CardError,
            stripe.InvalidRequestError,
            stripe.AuthenticationError,
            stripe.RateLimitError,
            stripe.IdempotencyError,
        ):
            # Definite rejection: money did not move.
            return RailResult(status=ExecutionStatus.failure, reference=None)
        except stripe.StripeError:
            # An unclassified Stripe error is fail-safe unknown, not failure —
            # assuming failure risks a double-spend if money in fact moved.
            return RailResult(status=ExecutionStatus.unknown, reference=None)

        return RailResult(
            status=_map_status(getattr(payment_intent, "status", None)),
            reference=getattr(payment_intent, "id", None),
        )


def _map_status(status: str | None) -> ExecutionStatus:
    if status in _SUCCESS_STATUSES:
        return ExecutionStatus.success
    if status in _FAILURE_STATUSES:
        return ExecutionStatus.failure
    # Pending or unrecognised (processing, requires_action, …): we do not yet
    # know the money moved, so reconcile rather than claim either outcome.
    return ExecutionStatus.unknown
