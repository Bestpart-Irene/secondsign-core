# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The experimental on-chain package must stay quarantined from v1.

Two properties keep the candidate surface from leaking into the frozen contract:
it is not re-exported from the top level, and nothing in v1 imports it. The
second is discovered by parsing every v1 source file, so a new module that
imports the on-chain package fails here rather than silently coupling the frozen
surface to an unfrozen one.
"""

import ast
import pathlib

import secondsign
import secondsign.contracts


def test_the_onchain_package_is_not_exported_from_the_top_level():
    assert not any("Onchain" in name for name in getattr(secondsign, "__all__", []))
    assert not hasattr(secondsign, "OnchainVerdict")
    # And it never enters the frozen v1 contract surface.
    assert not any("nchain" in name.lower() for name in secondsign.contracts.__all__)


def _imports_onchain(source: str) -> bool:
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if (node.module or "").startswith("secondsign.onchain"):
                return True
        elif isinstance(node, ast.Import):
            if any(alias.name.startswith("secondsign.onchain") for alias in node.names):
                return True
    return False


def test_no_v1_module_imports_the_experimental_onchain_package():
    root = pathlib.Path(secondsign.__file__).parent
    offenders = [
        str(path.relative_to(root))
        for path in root.rglob("*.py")
        if "onchain" not in path.relative_to(root).parts
        and _imports_onchain(path.read_text(encoding="utf-8"))
    ]
    assert not offenders, f"v1 modules import the experimental on-chain package: {offenders}"
