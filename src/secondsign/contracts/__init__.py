# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The plugin contract — the only surface an extension speaks through.

This package is a leaf: it imports nothing else from the core, so a plugin
gains no reach into policy, decision, gateway, or adapter internals. The
boundary is enforced in CI by an import contract, not by convention.
"""

from secondsign.contracts.combine import combine, neutral
from secondsign.contracts.render import render, render_finding
from secondsign.contracts.runner import PolicyPlugin, run_plugins
from secondsign.contracts.types import (
    CONTRACT_VERSION,
    FINGERPRINT_PATTERN,
    MAX_DETAIL_MAGNITUDE,
    ActionClass,
    Currency,
    Finding,
    Fingerprint,
    MarketSession,
    PluginJudgement,
    PluginVerdict,
    PolicyView,
    RailClass,
    ReasonCode,
    Reversibility,
    RiskBand,
    SourceTrust,
)

__all__ = [
    "CONTRACT_VERSION",
    "FINGERPRINT_PATTERN",
    "MAX_DETAIL_MAGNITUDE",
    "ActionClass",
    "Currency",
    "Finding",
    "Fingerprint",
    "MarketSession",
    "PluginJudgement",
    "PluginVerdict",
    "PolicyPlugin",
    "PolicyView",
    "RailClass",
    "ReasonCode",
    "Reversibility",
    "RiskBand",
    "SourceTrust",
    "combine",
    "neutral",
    "render",
    "render_finding",
    "run_plugins",
]
