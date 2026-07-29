# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""What the published source distribution actually carries.

Reading `[tool.hatch.build.targets.sdist].include` would not settle this. The
entries there are gitignore-style patterns, so a bare filename matches at every
depth: `"README.md"` alone already pulled `examples/policy_plugin/README.md`
into the artefact while both of that directory's modules stayed out of it. The
sdist then documented two files it did not contain.

Nothing failed. `testpaths` entries that match nothing are skipped in silence,
so `pytest` inside the unpacked sdist ran to green with the example's
certification simply absent — continuous in a checkout, non-existent in what we
publish. This builds the real artefact and looks inside it, because the list is
not the thing being shipped.
"""

from __future__ import annotations

import subprocess
import sys
import tarfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Modules whose absence would be silent. Each one is imported or collected by
#: something that reports nothing when it is missing.
REQUIRED_MEMBERS = (
    "examples/__init__.py",
    "examples/policy_plugin/__init__.py",
    "examples/policy_plugin/counterparty_allowlist.py",
    "examples/policy_plugin/test_conformance.py",
    "examples/policy_plugin/README.md",
)


def _build_sdist(destination: Path) -> Path:
    subprocess.run(  # noqa: S603 — fixed arguments, interpreter from sys.executable
        [
            sys.executable,
            "-m",
            "build",
            "--sdist",
            "--no-isolation",
            "--outdir",
            str(destination),
            str(REPO_ROOT),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    built = sorted(destination.glob("*.tar.gz"))
    assert len(built) == 1, f"expected one sdist, got {[p.name for p in built]}"
    return built[0]


def test_sdist_carries_the_worked_example(tmp_path):
    with tarfile.open(_build_sdist(tmp_path)) as archive:
        names = archive.getnames()

    root = names[0].split("/", 1)[0]
    missing = [member for member in REQUIRED_MEMBERS if f"{root}/{member}" not in names]

    assert not missing, (
        "the source distribution is missing files the example needs to be "
        f"runnable: {missing}. An sdist that ships the README without the "
        "modules documents files it does not contain, and the certification "
        "inside it is skipped in silence."
    )


def test_sdist_carries_no_compiled_artefacts(tmp_path):
    with tarfile.open(_build_sdist(tmp_path)) as archive:
        names = archive.getnames()

    polluted = [name for name in names if name.endswith(".pyc") or "__pycache__" in name]

    assert not polluted, f"build by-products shipped in the sdist: {polluted}"
