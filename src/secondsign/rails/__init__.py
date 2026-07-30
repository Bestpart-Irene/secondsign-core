# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Rail executors — the credential-holding drivers the gateway dispatches to.

Unlike the pure adapters (which only map a tool call to an intent, with no I/O),
an executor holds a rail's credential and makes the outbound call.

Two exist. :class:`~secondsign.rails.stripe.StripePaymentExecutor` (CORE-S014)
speaks one vendor's SDK and requires the optional ``stripe`` dependency
(``secondsign[stripe]``). :class:`~secondsign.rails.http.HTTPRailExecutor`
(CORE-S019) speaks HTTP to whatever endpoint a deployment configures, on the
standard library alone.

`stripe` is imported lazily inside its executor, so importing this package does
not require the SDK.
"""

from secondsign.rails.http import HTTPRailExecutor
from secondsign.rails.stripe import StripePaymentExecutor

__all__ = ["HTTPRailExecutor", "StripePaymentExecutor"]
