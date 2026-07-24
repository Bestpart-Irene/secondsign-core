# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Rail executors — the credential-holding drivers the gateway dispatches to.

Unlike the pure adapters (which only map a tool call to an intent, with no I/O),
an executor holds a rail's credential and makes the outbound call. The first is
the Stripe payment executor (CORE-S014); it requires the optional ``stripe``
dependency (``secondsign[stripe]``).
"""

from secondsign.rails.stripe import StripePaymentExecutor

__all__ = ["StripePaymentExecutor"]
