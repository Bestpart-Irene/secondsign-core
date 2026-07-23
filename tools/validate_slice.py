#!/usr/bin/env python3
# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Validate slice manifests.

A slice manifest is a promise about scope. This checks the promise is
well-formed before anyone starts work on it: required keys present, threats
that actually exist, dependencies that resolve, no cycles, and a stated reason
whenever a slice claims a human checkpoint.

    python tools/validate_slice.py docs/slices/roadmap.yaml
    python tools/validate_slice.py docs/slices/my-slice.yaml

Exits non-zero on the first manifest that fails, and prints every problem it
found rather than only the first.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
THREAT_MODEL = REPO_ROOT / "docs" / "THREAT_MODEL.md"

REQUIRED_KEYS = {
    "id",
    "title",
    "depends_on",
    "threats",
    "scope",
    "acceptance",
    "gates",
    "stop_for_human",
}
OPTIONAL_KEYS = {"forbidden", "required_tests", "checkpoint_reason", "rationale"}

KNOWN_GATES = {
    "ruff_check",
    "ruff_format",
    "pytest",
    "lint_imports",
    "validate_slices",
    "build",
    "dco",
}
KNOWN_TEST_CATEGORIES = {
    "unit",
    "properties",
    "contracts",
    "conformance",
    "architecture",
    "redteam",
    "e2e",
}

ID_PATTERN = re.compile(r"^[A-Z]+-S\d{3}$")
THREAT_PATTERN = re.compile(r"^[AB]\d{1,2}$")


def known_threats() -> set[str]:
    """Threat ids the threat model actually defines."""
    if not THREAT_MODEL.exists():
        return set()
    text = THREAT_MODEL.read_text(encoding="utf-8")
    return set(re.findall(r"^###\s+([AB]\d{1,2})\b", text, flags=re.MULTILINE))


def check_slice(entry: dict, threats_available: set[str], all_ids: set[str]) -> list[str]:
    problems: list[str] = []
    slice_id = entry.get("id", "<missing id>")

    missing = REQUIRED_KEYS - set(entry)
    if missing:
        problems.append(f"{slice_id}: missing required keys: {', '.join(sorted(missing))}")

    unknown = set(entry) - REQUIRED_KEYS - OPTIONAL_KEYS
    if unknown:
        problems.append(f"{slice_id}: unrecognised keys: {', '.join(sorted(unknown))}")

    if not ID_PATTERN.match(str(slice_id)):
        problems.append(f"{slice_id}: id must look like AREA-SNNN")

    if not str(entry.get("title", "")).strip():
        problems.append(f"{slice_id}: title is empty")

    for dependency in entry.get("depends_on", []) or []:
        if dependency not in all_ids:
            problems.append(f"{slice_id}: depends on unknown slice {dependency}")

    for threat in entry.get("threats", []) or []:
        if not THREAT_PATTERN.match(str(threat)):
            problems.append(f"{slice_id}: malformed threat id {threat!r}")
        elif threats_available and threat not in threats_available:
            problems.append(f"{slice_id}: threat {threat} is not defined in the threat model")

    if not entry.get("scope"):
        problems.append(f"{slice_id}: scope must list at least one path pattern")
    if not entry.get("acceptance"):
        problems.append(f"{slice_id}: acceptance must state at least one testable condition")

    for gate in entry.get("gates", []) or []:
        if gate not in KNOWN_GATES:
            problems.append(f"{slice_id}: unknown gate {gate!r}")

    for category in entry.get("required_tests", []) or []:
        if category not in KNOWN_TEST_CATEGORIES:
            problems.append(f"{slice_id}: unknown test category {category!r}")

    stop = entry.get("stop_for_human")
    if not isinstance(stop, bool):
        problems.append(f"{slice_id}: stop_for_human must be true or false")
    elif stop and not str(entry.get("checkpoint_reason", "")).strip():
        problems.append(f"{slice_id}: a human checkpoint must state checkpoint_reason")
    elif not stop and str(entry.get("checkpoint_reason", "")).strip():
        problems.append(f"{slice_id}: checkpoint_reason set but stop_for_human is false")

    return problems


def find_cycle(entries: list[dict]) -> list[str]:
    graph = {e["id"]: list(e.get("depends_on") or []) for e in entries if "id" in e}
    state: dict[str, int] = {}

    def visit(node: str, trail: list[str]) -> list[str]:
        if state.get(node) == 1:
            return [f"dependency cycle: {' -> '.join([*trail, node])}"]
        if state.get(node) == 2:
            return []
        state[node] = 1
        for parent in graph.get(node, []):
            if parent in graph:
                found = visit(parent, [*trail, node])
                if found:
                    return found
        state[node] = 2
        return []

    for node in graph:
        found = visit(node, [])
        if found:
            return found
    return []


def validate(path: Path) -> list[str]:
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        return [f"{path}: not valid YAML: {error}"]

    if not isinstance(document, dict):
        return [f"{path}: expected a mapping at the top level"]

    entries = document.get("slices")
    if entries is None:
        entries = [document]  # a single-slice manifest
    if not isinstance(entries, list) or not entries:
        return [f"{path}: no slices found"]

    ids = [e.get("id") for e in entries if isinstance(e, dict)]
    duplicates = {i for i in ids if ids.count(i) > 1}
    problems = [f"{path}: duplicate slice id {d}" for d in sorted(duplicates)]

    threats_available = known_threats()
    all_ids = set(ids)
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(f"{path}: slice entries must be mappings")
            continue
        problems.extend(check_slice(entry, threats_available, all_ids))

    problems.extend(find_cycle([e for e in entries if isinstance(e, dict)]))
    return problems


def main(argv: list[str]) -> int:
    paths = [Path(a) for a in argv[1:]] or [REPO_ROOT / "docs" / "slices" / "roadmap.yaml"]
    failed = False
    for path in paths:
        if path.name == "TEMPLATE.yaml":
            continue
        if not path.exists():
            print(f"no such manifest: {path}", file=sys.stderr)
            failed = True
            continue
        problems = validate(path)
        if problems:
            failed = True
            print(f"{path}: {len(problems)} problem(s)", file=sys.stderr)
            for problem in problems:
                print(f"  {problem}", file=sys.stderr)
        else:
            print(f"{path}: ok")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
