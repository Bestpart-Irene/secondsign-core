# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""INV-12 — the control plane is unreachable from the managed agent.

Every other invariant guards a path the agent could otherwise decline to take.
This one guards the limits themselves: an agent that can raise its own limit has
no limit, so the five control-plane assets — limits, approver roster, idempotency
store, audit ledger, fingerprint keys — must be out of reach by *structure*, not
by a rule someone remembers to follow.

Three properties, and the third is the one that makes the other two mean
something:

*Unreachability is transitive.* Checking the agent surface's direct imports would
pass a surface that imports a helper that imports the ledger. These tests walk
the whole closure.

*Classification is discovered, not listed.* A test naming the control-plane
modules would go stale the moment a slice adds one. These tests find modules that
*hold* a control-plane concern and require the classification to already cover
them, so an undeclared limits module fails the suite rather than silently
widening reach.

*The judgement reads no setting.* A control that a configuration value can switch
off is not this control. Nothing here may be answerable differently by changing
an environment variable, and relaxing any setting below its strictest default
requires a matching, unexpired, approved record — with a missing expiry counting
as expired, because "no expiry" is how a temporary exception becomes permanent.
"""

from __future__ import annotations

import ast
import importlib
import pkgutil
from pathlib import Path

import pytest

import secondsign
from secondsign.isolation import (
    AGENT_SURFACE,
    CONTROL_PLANE_CONCERNS,
    classify,
    control_plane_modules,
    is_control_plane,
)

PACKAGE_ROOT = Path(secondsign.__file__).parent


def _all_modules() -> list[str]:
    """Every module in the package, discovered from the filesystem.

    Deliberately *not* `pkgutil.walk_packages`, which imports each package to walk
    into it and swallows an ImportError by default. An earlier version of this file
    used it, and a mutation that introduced a circular import truncated the module
    list, which made `_direct_imports` filter away real imports, which made the
    agent surface's closure come back **empty** — so the central isolation test
    passed by having nothing to check.

    That is the fail-open direction, in the suite that exists to prevent exactly
    this shape of failure. Reading the directory cannot be broken by a broken
    import, and it also covers modules whose import needs an optional rail SDK.
    """
    found = {secondsign.__name__}
    for path in PACKAGE_ROOT.rglob("*.py"):
        relative = path.relative_to(PACKAGE_ROOT)
        parts = list(relative.parts[:-1]) + (
            [] if relative.name == "__init__.py" else [relative.stem]
        )
        if any(part.startswith((".", "_")) and part != "__init__.py" for part in parts):
            continue
        found.add(".".join([secondsign.__name__, *parts]) if parts else secondsign.__name__)
    return sorted(found)


MODULES = _all_modules()
MODULE_SET = frozenset(MODULES)


def _module_path(name: str) -> Path:
    """The source file for a module name, without importing it."""
    relative = name.removeprefix(f"{secondsign.__name__}.")
    if relative == secondsign.__name__:
        return PACKAGE_ROOT / "__init__.py"
    candidate = PACKAGE_ROOT / Path(*relative.split("."))
    return candidate / "__init__.py" if candidate.is_dir() else candidate.with_suffix(".py")


def _direct_imports(name: str) -> set[str]:
    """The `secondsign.*` modules a module imports, read from its source.

    Parsed rather than introspected on purpose: `sys.modules` after a test run
    reflects what the whole suite imported, which would make every module look
    like it imports everything.
    """
    tree = ast.parse(_module_path(name).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names if a.name.startswith("secondsign"))
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            if node.module.startswith("secondsign"):
                imported.add(node.module)
                # `from secondsign.gateway import execution` names a submodule.
                imported.update(f"{node.module}.{a.name}" for a in node.names)
    return {m for m in imported if m in MODULE_SET}


def _defined_names(name: str) -> frozenset[str]:
    """The top-level names a module defines, read from its source.

    Lives here rather than in `secondsign.isolation` because it reads files, and
    that module has to be able to claim it reads nothing. An earlier draft had
    this logic there and `test_inv12_the_isolation_module_reads_no_configuration`
    failed it — correctly.
    """
    tree = ast.parse(_module_path(name).read_text(encoding="utf-8"))
    defined: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ClassDef | ast.FunctionDef):
            defined.add(node.name)
        elif isinstance(node, ast.Assign):
            defined.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            defined.add(node.target.id)
    return frozenset(defined)


def _import_closure(root: str) -> set[str]:
    """Everything `root` can reach through imports, at any depth."""
    seen: set[str] = set()
    queue = [root]
    while queue:
        current = queue.pop()
        for target in _direct_imports(current):
            if target not in seen:
                seen.add(target)
                queue.append(target)
    return seen


# --------------------------------------------------------------------------
# The discovery has to work, or every test below is vacuous.
# --------------------------------------------------------------------------


def test_the_discovery_itself_works():
    assert MODULES, "no modules discovered — this suite is not testing anything"
    assert AGENT_SURFACE in MODULES, f"the agent surface {AGENT_SURFACE} does not exist"
    assert control_plane_modules(), "no control-plane module classified — nothing is protected"


def test_the_closure_walk_itself_works():
    """A closure that came back empty would pass every isolation test below.

    This is not a paranoid extra. It is the guard on a failure this suite actually
    had: a truncated module list silently emptied the agent surface's closure, and
    the isolation test passed with nothing to check. Assert on the closure that
    matters, and assert it reaches past its own direct imports.
    """
    agent_closure = _import_closure(AGENT_SURFACE)
    assert agent_closure, (
        f"{AGENT_SURFACE}'s import closure is empty — the walk is broken, and every "
        "isolation assertion below is vacuous"
    )
    assert "secondsign.contracts" in agent_closure, (
        "the agent surface does not reach the plugin contract; either the surface "
        "changed shape or the walk stopped early"
    )
    # Depth: `contracts.types` is reached only through `contracts/__init__`, so
    # finding it proves the walk is transitive rather than one level deep.
    assert "secondsign.contracts.types" in agent_closure, (
        "the closure walk is not transitive — it would miss a control-plane module "
        "reached through an intermediate import, which is the realistic breach"
    )


def test_every_module_on_disk_is_reachable_by_name():
    """Discovery must agree with what Python can actually import.

    Filesystem discovery is robust to a broken import, but it would also happily
    invent a module name that does not resolve. Checking the two agree keeps the
    robustness without letting the list drift into fiction.
    """
    walked = {secondsign.__name__} | {
        info.name for info in pkgutil.walk_packages(secondsign.__path__, "secondsign.")
    }
    invented = sorted(m for m in MODULES if m not in walked and _module_path(m).exists() is False)
    assert not invented, f"discovered names that are not modules: {invented}"
    assert walked <= MODULE_SET, (
        f"walk found modules the filesystem scan missed: {walked - MODULE_SET}"
    )


# --------------------------------------------------------------------------
# INV-12, first half: unreachable by import structure.
# --------------------------------------------------------------------------


def test_inv12_agent_surface_cannot_reach_the_control_plane():
    """The whole invariant, stated once: no path of any length."""
    reachable = _import_closure(AGENT_SURFACE)
    breaches = sorted(m for m in reachable if is_control_plane(m))
    assert not breaches, (
        f"{AGENT_SURFACE} can reach control-plane modules {breaches} — "
        "an agent that can reach its own limits has no limits"
    )


def test_inv12_the_agent_surface_is_not_itself_control_plane():
    assert not is_control_plane(AGENT_SURFACE), (
        "the agent surface is classified as control plane; the classification is inverted"
    )


def test_an_unclassified_module_classifies_as_none_and_not_as_safe():
    """The fail-closed branch, exercised directly.

    Every module in the package is classified, so this path is unreachable through
    real code — which is exactly why it needs a test rather than a comment. Two
    properties matter and they pull in opposite directions: an unknown module must
    not silently classify as `shared` (that would let a new file be importable from
    the agent surface by default), and it must not report as control plane either
    (that would let it hide behind `is_control_plane` instead of failing
    `test_inv12_every_module_is_classified`, which is the error a contributor can
    act on).
    """
    unknown = "secondsign.a_module_no_slice_has_written"
    assert unknown not in MODULE_SET, "pick a name that really does not exist"
    assert classify(unknown) is None
    assert not is_control_plane(unknown)


@pytest.mark.parametrize("module", MODULES)
def test_inv12_every_module_is_classified(module):
    """No module sits outside the classification.

    An unclassified module is the gap the invariant dies in: it is neither
    guarded as control plane nor proven safe for the agent surface to import.
    """
    assert classify(module) is not None, f"{module} has no isolation classification"


@pytest.mark.parametrize("concern", sorted(CONTROL_PLANE_CONCERNS))
def test_inv12_each_named_asset_is_actually_held_somewhere(concern):
    """The five assets INV-12 names are real, and classified.

    This is what stops the classification from being satisfied by declaring
    nothing: each concern must be found in a module, by inspecting what the
    module defines rather than by trusting a list.
    """
    holders = [m for m in MODULES if CONTROL_PLANE_CONCERNS[concern].is_held_by(_defined_names(m))]
    assert holders, f"no module holds the {concern} concern — INV-12 names an asset that is absent"
    unguarded = sorted(m for m in holders if not is_control_plane(m))
    assert not unguarded, (
        f"{concern} is held by unguarded modules {unguarded} — "
        "a control-plane asset outside the control plane"
    )


# --------------------------------------------------------------------------
# INV-12, second half: the judgement depends on no configurable policy.
# --------------------------------------------------------------------------


def test_inv12_classification_reads_no_environment(monkeypatch):
    """No environment variable can move a module out of the control plane."""
    before = control_plane_modules()
    for guess in (
        "SECONDSIGN_CONTROL_PLANE",
        "SECONDSIGN_ISOLATION",
        "SECONDSIGN_AGENT_SURFACE",
        "SECONDSIGN_ALLOW",
        "SECONDSIGN_DEBUG",
    ):
        monkeypatch.setenv(guess, "")
        monkeypatch.setenv(guess.lower(), "off")
    importlib.reload(importlib.import_module("secondsign.isolation"))
    assert control_plane_modules() == before, "the classification changed with the environment"


def test_inv12_the_isolation_module_reads_no_configuration_at_all():
    """Structural, not behavioural: the source reaches for no configuration.

    The environment test above can only disprove the variable names it guesses.
    This one holds the whole file to the stronger rule — an isolation judgement
    that reads any external input is a judgement someone can answer differently.
    """
    source = _module_path("secondsign.isolation").read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden = {"os", "sys", "pathlib", "json", "tomllib", "configparser", "dotenv"}
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not (imported & forbidden), (
        f"secondsign.isolation imports {sorted(imported & forbidden)} — "
        "the isolation judgement must not be able to read anything"
    )
