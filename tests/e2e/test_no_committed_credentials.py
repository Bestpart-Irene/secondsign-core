# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Enforce the CORE-S014 forbidden rule: no committed credentials.

A Stripe key (test or live) must never land in the tree — not in a fixture, a
doc, or a config. This scans the repository for anything shaped like a Stripe
secret/restricted/publishable key and fails if it finds one.
"""

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_SCANNED_SUFFIXES = {".py", ".toml", ".md", ".yaml", ".yml", ".cfg", ".txt", ".json", ".sh"}
_SKIP_DIRS = {".venv", ".git", "__pycache__", ".ruff_cache", ".hypothesis"}

# Built from parts so this test file does not itself contain a full key prefix.
_KEY_PREFIXES = tuple(f"{kind}_{mode}_" for kind in ("sk", "rk", "pk") for mode in ("live", "test"))
# A real key has a long run of base62 after the prefix; a bare prefix in prose is fine.
_KEY_PATTERN = re.compile("|".join(re.escape(p) + r"[A-Za-z0-9]{8,}" for p in _KEY_PREFIXES))


def _scanned_files():
    for path in _ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in _SCANNED_SUFFIXES:
            continue
        if _SKIP_DIRS & set(path.parts):
            continue
        yield path


def test_no_stripe_key_literal_is_committed():
    this_file = Path(__file__).resolve()
    offenders = []
    for path in _scanned_files():
        if path.resolve() == this_file:
            continue
        match = _KEY_PATTERN.search(path.read_text(encoding="utf-8", errors="ignore"))
        if match:
            offenders.append(f"{path.relative_to(_ROOT)}: {match.group()[:12]}…")
    assert not offenders, f"committed Stripe-key-shaped strings found: {offenders}"


def test_the_scanner_would_catch_a_real_key():
    """Guard the guard: the pattern must match a key-shaped string."""
    assert _KEY_PATTERN.search("rk_" + "test_" + "abcdEFGH1234")
    assert not _KEY_PATTERN.search("rk_test_ and rk_test_ mentioned in prose")
