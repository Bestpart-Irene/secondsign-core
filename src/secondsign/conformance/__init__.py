# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Conformance suites — how an extension proves it is safe to install.

Inherit the suite for the extension point you implement, name your subclass
``Test...``, and run your own test suite. Passing is what "compatible with
SecondSign" means; it is mechanical on purpose, so nobody has to re-argue the
security principles in review each time a rail or a rule is added.

Available today:

- :class:`PolicyPluginConformance`
- :class:`RailAdapterConformance`
- :class:`ApprovalProviderConformance`
- :class:`AuditSinkConformance`
- :class:`WireClientConformance` — for an agent-side client rather than an
  extension. It certifies the *wire*, so it prescribes nothing about the
  candidate's API and stands up its own :class:`ProbeGateway` to script the
  answers a real gateway cannot be asked to give.

Forthcoming: compliance providers. That contract does not exist yet, and
shipping an empty suite would imply a guarantee that is not being made.
"""

from secondsign.conformance.approval_provider import ApprovalProviderConformance
from secondsign.conformance.audit_sink import AuditSinkConformance
from secondsign.conformance.policy_plugin import PolicyPluginConformance, conformance_corpus
from secondsign.conformance.rail_adapter import RailAdapterConformance
from secondsign.conformance.wire_client import ProbeGateway, WireClientConformance

__all__ = [
    "ApprovalProviderConformance",
    "AuditSinkConformance",
    "PolicyPluginConformance",
    "ProbeGateway",
    "RailAdapterConformance",
    "WireClientConformance",
    "conformance_corpus",
]
