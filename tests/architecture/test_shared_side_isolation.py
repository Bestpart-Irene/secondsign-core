# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""INV-12, third side — `shared` means what its docstring says.

Two of the classification's three sides were enforced from the start: the
agent surface cannot reach the control plane, and every module must classify.
The third side was a comment. A module classified `shared` — *"safe for both
sides"* — could import the control plane and nothing said otherwise, and the
failure mode is quiet by construction: the breach only surfaces when an
agent-surface module later imports the tainted shared module, in a pull
request that did not create it.

The cases here close that side: every module whose classification is `shared`
must have an import closure free of control-plane modules. The shared list is
*discovered from the classification*, never repeated here, so a new shared
prefix is covered the moment `secondsign.isolation` declares it.

The check itself is a function of a package root, and that is deliberate: the
mutation cases run the same function over a *copy* of the package with a
control-plane import added to a shared module — directly, and then one level
down — and require it to report the breach. A gate that cannot fail is not a
gate, and this suite has already once held a test that passed by having
nothing to check.
"""

from __future__ import annotations

import ast
import shutil
from pathlib import Path

import pytest

import secondsign
from secondsign.isolation import Side, classify, is_control_plane

REAL_PACKAGE_ROOT = Path(secondsign.__file__).parent


def _modules_under(package_root: Path) -> list[str]:
    """Every module under a package root, discovered from the filesystem.

    The same discovery `test_control_plane_isolation` uses, for the same
    recorded reason: an import-based walk swallows a broken import and
    truncates the list, which empties the closures, which passes everything.
    """
    found = {secondsign.__name__}
    for path in package_root.rglob("*.py"):
        relative = path.relative_to(package_root)
        parts = list(relative.parts[:-1]) + (
            [] if relative.name == "__init__.py" else [relative.stem]
        )
        if any(part.startswith((".", "_")) and part != "__init__.py" for part in parts):
            continue
        found.add(".".join([secondsign.__name__, *parts]) if parts else secondsign.__name__)
    return sorted(found)


def _module_path(package_root: Path, name: str) -> Path:
    relative = name.removeprefix(f"{secondsign.__name__}.")
    if name == secondsign.__name__:
        return package_root / "__init__.py"
    candidate = package_root / Path(*relative.split("."))
    return candidate / "__init__.py" if candidate.is_dir() else candidate.with_suffix(".py")


def _direct_imports(package_root: Path, name: str, module_set: frozenset[str]) -> set[str]:
    tree = ast.parse(_module_path(package_root, name).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names if a.name.startswith("secondsign"))
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            if node.module.startswith("secondsign"):
                imported.add(node.module)
                imported.update(f"{node.module}.{a.name}" for a in node.names)
    return {m for m in imported if m in module_set}


def _closure(package_root: Path, root: str, module_set: frozenset[str]) -> set[str]:
    seen: set[str] = set()
    queue = [root]
    while queue:
        current = queue.pop()
        for target in _direct_imports(package_root, current, module_set):
            if target not in seen:
                seen.add(target)
                queue.append(target)
    return seen


def shared_side_breaches(package_root: Path) -> dict[str, list[str]]:
    """Every shared module that can reach the control plane, and how far.

    The single source of truth for this property. The real test calls it on
    the installed package; the mutation tests call it on a tampered copy and
    require it to complain. Classification comes from `secondsign.isolation`
    by module *name*, so the same judgement applies to both trees.
    """
    modules = _modules_under(package_root)
    module_set = frozenset(modules)
    breaches: dict[str, list[str]] = {}
    for module in modules:
        if classify(module) is not Side.shared:
            continue
        tainted = sorted(
            m for m in _closure(package_root, module, module_set) if is_control_plane(m)
        )
        if tainted:
            breaches[module] = tainted
    return breaches


SHARED_MODULES = [m for m in _modules_under(REAL_PACKAGE_ROOT) if classify(m) is Side.shared]


# --------------------------------------------------------------------------
# The discovery has to work, or everything below is vacuous.
# --------------------------------------------------------------------------


def test_the_shared_side_exists_and_is_discovered():
    """A shared list that came back empty would pass every case below."""
    assert SHARED_MODULES, "no module classifies as shared — the discovery is broken"
    assert "secondsign.contracts" in SHARED_MODULES, (
        "the plugin contract is not in the discovered shared list; either the "
        "classification moved or the discovery is not reading it"
    )
    assert "secondsign.adapters" in SHARED_MODULES


# --------------------------------------------------------------------------
# The property.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("module", SHARED_MODULES)
def test_inv12_a_shared_module_cannot_reach_the_control_plane(module):
    """Safe for both sides has to mean safe for both sides.

    Transitive on purpose: nobody imports the ledger into a boundary model
    directly — they import a helper that happens to. `CORE-S019` came within
    one import of exactly that, through the conformance kit; the dialect was
    moved to `secondsign.agent.wire` by choice, and this is the gate the next
    person gets instead of a choice.
    """
    module_set = frozenset(_modules_under(REAL_PACKAGE_ROOT))
    tainted = sorted(
        m for m in _closure(REAL_PACKAGE_ROOT, module, module_set) if is_control_plane(m)
    )
    assert not tainted, (
        f"{module} is classified shared but can reach control-plane modules "
        f"{tainted} — either the import is wrong or the classification is"
    )


# --------------------------------------------------------------------------
# The gate can fail. Proven on a mutated copy, not asserted in prose.
# --------------------------------------------------------------------------


def _mutated_copy(tmp_path: Path, target_module: str, injected_import: str) -> Path:
    """A copy of the package with one import appended to one module."""
    copy_root = tmp_path / "secondsign"
    shutil.copytree(REAL_PACKAGE_ROOT, copy_root, ignore=shutil.ignore_patterns("__pycache__"))
    target = _module_path(copy_root, target_module)
    before = target.read_text(encoding="utf-8")
    target.write_text(before + f"\n{injected_import}\n", encoding="utf-8")
    # The recorded lesson from the deployment gate: verify the mutation took
    # effect before concluding anything from it.
    assert target.read_text(encoding="utf-8") != before, "the mutation did not take effect"
    return copy_root


def test_the_check_catches_a_direct_control_plane_import(tmp_path):
    copy_root = _mutated_copy(tmp_path, "secondsign.adapters", "import secondsign.policy")
    breaches = shared_side_breaches(copy_root)
    assert "secondsign.adapters" in breaches, (
        "a shared module importing the control plane directly went unreported — "
        "the gate cannot fail, so it is not a gate"
    )
    assert "secondsign.policy" in breaches["secondsign.adapters"]


def test_the_check_catches_a_transitive_control_plane_import(tmp_path):
    """The realistic breach: the import lands one level down.

    `secondsign.intent.dimensions` is imported by the adapters, so poisoning
    it must indict every shared module that reaches it — proving the walk is
    a closure and not a glance at direct imports.
    """
    copy_root = _mutated_copy(
        tmp_path, "secondsign.intent.dimensions", "import secondsign.audit"
    )
    breaches = shared_side_breaches(copy_root)
    assert "secondsign.intent" in breaches
    assert "secondsign.adapters" in breaches, (
        "a control-plane import one level below a shared module went unreported "
        "for the importer — the check reads direct imports, not the closure"
    )


def test_the_real_package_is_what_the_parametrized_cases_saw():
    """One aggregate answer, so a future refactor of the parametrization
    cannot quietly stop covering the property."""
    assert shared_side_breaches(REAL_PACKAGE_ROOT) == {}
