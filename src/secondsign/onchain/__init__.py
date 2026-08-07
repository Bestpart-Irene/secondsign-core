# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Experimental, **unfrozen** on-chain surface (ONCHAIN-S002).

Not part of the frozen v1 contract (:mod:`secondsign.contracts`). Carries its own
version constant (``ONCHAIN_CONTRACT_VERSION == 0``); no v1 module imports it; it
is not re-exported from the top-level ``secondsign`` package. See
:mod:`secondsign.onchain.types` for the surface and why it is kept separate.
"""

from secondsign.onchain.effect import (
    EffectKind,
    OnchainEffect,
    SafeAdapter,
    SafeCall,
    SafeOperation,
)
from secondsign.onchain.types import (
    ONCHAIN_CONTRACT_VERSION,
    RED_TEAM_COVERAGE,
    OnchainFinding,
    OnchainJudgement,
    OnchainReasonCode,
    OnchainVerdict,
)

__all__ = [
    "ONCHAIN_CONTRACT_VERSION",
    "RED_TEAM_COVERAGE",
    "EffectKind",
    "OnchainEffect",
    "OnchainFinding",
    "OnchainJudgement",
    "OnchainReasonCode",
    "OnchainVerdict",
    "SafeAdapter",
    "SafeCall",
    "SafeOperation",
]
