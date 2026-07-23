#!/usr/bin/env python3
# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Check that a branch changed only the files its slice declared it would.

Every slice manifest already promises a `scope`: the glob patterns that slice
may touch. Until now that promise was prose — a reviewer could notice a change
that wandered outside it, or could fail to. This turns it into a gate.

Scope creep is not a tidiness problem here. A slice is the unit that carries
threat coverage, acceptance criteria and a review decision; a change that
arrives outside the declared scope arrives without any of those, inside a pull
request whose title says something else. That is precisely how an unreviewed
line lands on a decision path.

The slice id comes from the first of these that is set:

    python tools/check_slice_scope.py CORE-S006      # argument
    SLICE_ID=CORE-S006 python tools/check_slice_scope.py
    # the current branch name: feat/CORE-S006/intent-model

Comparison is against `origin/main` when it exists, otherwise `main`, otherwise
the merge base of `HEAD~1`. Exits 0 when every changed file is in scope.

`forbidden` in a manifest describes shapes ("free-form mappings"), not paths,
so it is not checked here — `tests/architecture/` is where those are enforced.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
ROADMAP = REPO_ROOT / "docs" / "slices" / "roadmap.yaml"

SLICE_ID_PATTERN = re.compile(r"[A-Z][A-Z0-9]*-S\d{3}")

# Branch prefixes that carry a slice, per AGENTS.md §6. `docs/` and `chore/`
# branches deliberately have no slice id — repository housekeeping is not a
# change to the decision path and has no threat coverage to declare. Requiring
# an id there would push contributors to invent one, which is worse than no
# gate: it makes the manifest a formality instead of a promise.
SLICE_BRANCH_PREFIXES = ("feat/", "fix/")

# Declaring scope is itself part of doing a slice, so a branch may always add or
# amend a manifest. Everything else must be listed.
ALWAYS_IN_SCOPE = ("docs/slices/**",)


def git(*args: str) -> subprocess.CompletedProcess[str]:
    executable = shutil.which("git")
    if executable is None:
        raise RuntimeError("git executable not found")
    return subprocess.run(  # noqa: S603 — resolved executable, fixed arguments
        [executable, "-C", str(REPO_ROOT), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def current_branch() -> str:
    # In GitHub Actions on a pull request, HEAD is detached and the branch name
    # only survives in the event payload.
    for name in ("GITHUB_HEAD_REF", "GITHUB_REF_NAME"):
        value = os.environ.get(name)
        if value:
            return value
    result = git("rev-parse", "--abbrev-ref", "HEAD")
    return result.stdout.strip()


def resolve_slice_id(argv: list[str]) -> str | None:
    if len(argv) > 1:
        return argv[1]
    from_env = os.environ.get("SLICE_ID")
    if from_env:
        return from_env
    match = SLICE_ID_PATTERN.search(current_branch())
    return match.group(0) if match else None


def resolve_base() -> str | None:
    for candidate in ("origin/main", "main"):
        if git("rev-parse", "--verify", "--quiet", candidate).returncode == 0:
            return candidate
    return None


def changed_files(base: str) -> list[str]:
    merge_base = git("merge-base", base, "HEAD").stdout.strip()
    if not merge_base:
        merge_base = base
    result = git("diff", "--name-only", f"{merge_base}..HEAD")
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    return [line for line in result.stdout.splitlines() if line.strip()]


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a manifest glob to a regex.

    `**` crosses directory separators, `*` and `?` do not — the usual reading,
    and the one a contributor writing `src/secondsign/area/**` expects.
    """
    out: list[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if pattern.startswith("**", index):
            out.append(".*")
            index += 2
            if pattern.startswith("/", index):  # `a/**/b` should also match `a/b`
                out.append("/?")
                index += 1
            continue
        if char == "*":
            out.append("[^/]*")
        elif char == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(char))
        index += 1
    return re.compile(f"^{''.join(out)}$")


def in_scope(path: str, patterns: list[re.Pattern[str]]) -> bool:
    return any(pattern.match(path) for pattern in patterns)


def load_slice(slice_id: str) -> dict[str, object] | None:
    document = yaml.safe_load(ROADMAP.read_text(encoding="utf-8")) or {}
    for entry in document.get("slices", []):
        if entry.get("id") == slice_id:
            return entry

    # A slice being introduced by this branch lives in its own manifest file.
    for candidate in sorted((REPO_ROOT / "docs" / "slices").glob("*.yaml")):
        if candidate.name in {"roadmap.yaml", "TEMPLATE.yaml"}:
            continue
        loaded = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
        entries = loaded.get("slices", [loaded])
        for entry in entries:
            if isinstance(entry, dict) and entry.get("id") == slice_id:
                return entry
    return None


def main(argv: list[str]) -> int:
    slice_id = resolve_slice_id(argv)
    if slice_id is None:
        branch = current_branch()
        if not branch.startswith(SLICE_BRANCH_PREFIXES):
            print(f"ok: {branch or 'this branch'} carries no slice; nothing to check")
            return 0
        print(
            f"FAIL: {branch} is a slice branch with no slice id.\n"
            "Name it feat/<SLICE-ID>/<slug>, pass the id as an argument, or set\n"
            "SLICE_ID. A change to the decision path with no declared scope is\n"
            "not a slice."
        )
        return 1

    manifest = load_slice(slice_id)
    if manifest is None:
        print(f"FAIL: no manifest for {slice_id} in {ROADMAP.relative_to(REPO_ROOT)}")
        print("Add it to the roadmap, or commit its own manifest first.")
        return 1

    scope = list(manifest.get("scope") or [])
    if "*" in scope:
        print(f"ok: {slice_id} declares unrestricted scope ('*'); nothing to check")
        return 0

    base = resolve_base()
    if base is None:
        print("note: no main branch to compare against; nothing to check")
        return 0

    try:
        files = changed_files(base)
    except RuntimeError as exc:
        print(f"FAIL: could not determine changed files: {exc}")
        return 1

    if not files:
        print(f"ok: {slice_id} changed no files against {base}")
        return 0

    patterns = [glob_to_regex(item) for item in (*scope, *ALWAYS_IN_SCOPE)]
    violations = [path for path in files if not in_scope(path, patterns)]

    print(f"{slice_id}: {len(files)} changed file(s) against {base}")
    for item in scope:
        print(f"  scope: {item}")

    if violations:
        print("\nFAIL: changed outside the declared scope:")
        for path in violations:
            print(f"  {path}")
        print(
            "\nEither the change belongs in a different slice, or the manifest is\n"
            "wrong. Widening scope is a decision to make deliberately in the\n"
            "manifest, in its own commit — not a side effect of an implementation."
        )
        return 1

    print("\nok: every changed file is inside the declared scope")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
