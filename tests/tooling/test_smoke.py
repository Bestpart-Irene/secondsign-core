# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""`tools/smoke.py` is executed by CI, so it cannot rot.

A smoke test that is never run is a file that quietly stops matching the code
it claims to smoke-test. This loads it as a module and runs its `main`,
asserting a clean exit — which is the same thing a developer gets from
`python tools/smoke.py`, minus remembering to.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_smoke():
    path = REPO_ROOT / "tools" / "smoke.py"
    spec = importlib.util.spec_from_file_location("secondsign_smoke", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_smoke_test_passes(capsys) -> None:
    exit_code = _load_smoke().main()
    printed = capsys.readouterr().out
    assert exit_code == 0, f"smoke test failed:\n{printed}"
    assert "SMOKE OK" in printed
    # Not vacuous: it must have actually run its checks, not printed a header
    # and exited. Every line the check writes is either `[ok  ]` or `[FAIL]`.
    assert printed.count("[ok  ]") >= 10, "the smoke test ran fewer checks than expected"
