# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Run the whole local gate — every default CI check, unfiltered, in one command.

The gate CI enforces is a *sequence*, and running it by hand is how a step gets
skipped or a filtered ``grep`` hides a failure. This runs the same sequence CI's
Preflight and Tests jobs run — no Docker, no network — and prints each gate's
result. It exits non-zero if any gate fails.

    python tools/check.py            # the static + test gates (what runs on every push)
    python tools/check.py --diff     # also the PR-diff gates: declared slice scope, DCO

Every gate's own output is passed straight through, never captured or filtered:
the point of this script is that you see exactly what CI will see. The command
set is pinned against ``.github/workflows/ci.yml``; if CI's Preflight or Tests
commands change, this must change with them or it is giving false confidence.

Run it inside the dev environment (``pip install -e ".[dev]" && pip install -e
client/``). Tools are resolved from the running interpreter's directory, so
``.venv/bin/python tools/check.py`` works whether or not the venv is activated.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time

#: The static + unit gates that run on every push, mirroring ci.yml's Preflight
#: and Tests jobs. No Docker, no network — a contributor can run all of these.
CORE_GATES: list[tuple[str, list[str]]] = [
    ("ruff lint", ["ruff", "check", "."]),
    ("ruff format", ["ruff", "format", "--check", "."]),
    ("mypy", ["mypy", "src", "client/src"]),
    ("import boundaries", ["lint-imports"]),
    ("slice manifests", ["python", "tools/validate_slice.py", "docs/slices/roadmap.yaml"]),
    ("doc links", ["python", "tools/check_doc_links.py"]),
    (
        "tests + 100% coverage",
        [
            "pytest",
            "--cov=secondsign",
            "--cov=secondsign_client",
            "--cov-report=term-missing",
            "--cov-fail-under=100",
        ],
    ),
]

#: Gates that only mean something against a base ref — CI runs them on pull
#: requests. Off by default so a run on ``main`` does not fail spuriously.
DIFF_GATES: list[tuple[str, list[str]]] = [
    ("declared slice scope", ["python", "tools/check_slice_scope.py"]),
    ("DCO sign-off", ["python", "tools/check_dco.py", "origin/main..HEAD"]),
]


def _search_path() -> str:
    """PATH with the running interpreter's directory first, so ``ruff``/``mypy``/
    ``pytest``/``lint-imports`` resolve to this environment's copies whether or
    not the venv is activated."""
    bindir = os.path.dirname(sys.executable)
    return bindir + os.pathsep + os.environ.get("PATH", "")


def _run(name: str, argv: list[str], path: str, env: dict[str, str]) -> tuple[str, bool, float]:
    print(f"\n=== {name}: {' '.join(argv)} ===", flush=True)
    start = time.monotonic()
    executable = shutil.which(argv[0], path=path)
    if executable is None:
        print(f"  ! {argv[0]} not found — is the dev environment installed?", flush=True)
        return name, False, time.monotonic() - start
    # Resolved absolute executable, fixed literal arguments — output flows straight
    # through, never captured or filtered.
    completed = subprocess.run(  # noqa: S603 — resolved executable, fixed arguments
        [executable, *argv[1:]], env=env, check=False
    )
    return name, completed.returncode == 0, time.monotonic() - start


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="tools/check.py", description="Run the full local gate, unfiltered."
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="also run the PR-diff gates (declared slice scope, DCO) against origin/main",
    )
    args = parser.parse_args(argv)

    gates = list(CORE_GATES)
    if args.diff:
        gates += DIFF_GATES

    path = _search_path()
    env = {**os.environ, "PATH": path}
    results = [_run(name, cmd, path, env) for name, cmd in gates]

    print("\n" + "=" * 52)
    for name, ok, dur in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name:26} {dur:6.1f}s")
    print("=" * 52)

    failed = [name for name, ok, _ in results if not ok]
    if failed:
        print(f"\n{len(failed)} gate(s) failed: {', '.join(failed)}")
        return 1
    print("\nAll gates passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
