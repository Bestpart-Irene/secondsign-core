#!/usr/bin/env python3
# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Render the slice queue as a table a person can read.

`docs/slices/roadmap.yaml` is the queue, and it is written for the validator:
scope globs, forbidden shapes, acceptance criteria, threat ids. That is the
right shape for a gate and the wrong shape for someone deciding what to pick
up. This renders the same file as `docs/slices/STATUS.md` — what is done, what
is available now, and what is waiting on something else.

**Status is still not stored.** The roadmap deliberately records no `status:`
key, because a stored status drifts from the repository the moment someone
forgets to update it, and a security project whose documents disagree with its
own history has given away the thing it was selling. So status is derived here,
every time, from two facts:

1. **Git attribution.** A slice is complete when the trunk's first-parent
   history contains the merge of a branch named for it — `feat/<ID>/…`,
   `fix/<ID>/…`, or the older `Merge slice <ID>` form.

2. **Dependency closure.** A slice that a complete slice depends on is itself
   complete. This is an inference, not a guess: the protocol forbids starting a
   slice before its dependencies land, so a completed slice is proof its whole
   dependency set completed. It is what lets this tool attribute CORE-S001
   through CORE-S003, which were built before the branch-naming convention
   existed and are therefore invisible to signal 1.

`STATUS.md` is committed so it renders on GitHub, and CI runs `--check` to
require that the committed copy matches what this tool produces. That keeps it
a derived artefact — like a lockfile — rather than a second place to maintain
the truth.

The rendered text names no ref and carries no timestamp, so the same repository
state produces the same bytes everywhere. An earlier draft printed which ref the
history came from, which made the output differ between a developer's checkout
(`origin/main`) and a shallow CI one (`HEAD`) — a check that fails on the
environment rather than on the content teaches people to ignore it.

`--check` therefore refuses to answer at all when the checkout is too shallow to
attribute any slice, rather than reporting everything as unbuilt. Judging
staleness from a history you cannot see is the fail-open version of this gate.

    python tools/render_roadmap.py            # write docs/slices/STATUS.md
    python tools/render_roadmap.py --check    # fail if the committed copy is stale
    python tools/render_roadmap.py --stdout   # print, write nothing
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
ROADMAP = REPO_ROOT / "docs" / "slices" / "roadmap.yaml"
STATUS = REPO_ROOT / "docs" / "slices" / "STATUS.md"

# The two branch conventions the trunk has carried. The second is how slices
# were merged before pull requests were the route in; dropping it would report
# the project's earliest slices as unbuilt.
MERGE_PATTERNS = (
    re.compile(r"(?:feat|fix)/([A-Z][A-Z0-9]*-S\d{3})/"),
    re.compile(r"Merge slice ([A-Z][A-Z0-9]*-S\d{3})"),
)


def display(path: Path) -> str:
    """A path to show a human, without assuming it sits inside the repository.

    `relative_to` raises when it does not, which would turn a clear "this file
    is stale" message into a traceback from the reporting code itself.
    """
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def git(*args: str) -> str:
    executable = shutil.which("git")
    if executable is None:
        raise RuntimeError("git executable not found")
    result = subprocess.run(  # noqa: S603 — resolved executable, fixed arguments
        [executable, "-C", str(REPO_ROOT), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout if result.returncode == 0 else ""


def trunk() -> str:
    """The ref to read history from.

    `origin/main` first: on a pull request checkout the local `main` may be
    absent or stale, and reading a stale trunk would silently report a merged
    slice as still queued.
    """
    for candidate in ("origin/main", "main", "HEAD"):
        if git("rev-parse", "--verify", "--quiet", candidate).strip():
            return candidate
    return "HEAD"


def attributed_to_git(ref: str) -> set[str]:
    log = git("log", "--first-parent", "--format=%s%n%b", ref)
    found: set[str] = set()
    for pattern in MERGE_PATTERNS:
        found.update(pattern.findall(log))
    return found


def close_over_dependencies(complete: set[str], slices: dict[str, dict[str, Any]]) -> set[str]:
    """Add every slice a complete slice depends on, transitively.

    Sound because the protocol will not start a slice whose dependencies have
    not landed: the existence of a completed slice is evidence about its whole
    dependency set, not merely about itself.
    """
    closed = set(complete)
    pending = list(closed)
    while pending:
        current = pending.pop()
        for dependency in slices.get(current, {}).get("depends_on") or []:
            if dependency in slices and dependency not in closed:
                closed.add(dependency)
                pending.append(dependency)
    return closed


def classify(slices: dict[str, dict[str, Any]], complete: set[str]) -> dict[str, str]:
    status: dict[str, str] = {}
    for slice_id, manifest in slices.items():
        if slice_id in complete:
            status[slice_id] = "complete"
            continue
        dependencies = manifest.get("depends_on") or []
        unmet = [item for item in dependencies if item not in complete]
        status[slice_id] = "blocked" if unmet else "ready"
    return status


def row(manifest: dict[str, Any], status: dict[str, str]) -> str:
    slice_id = str(manifest["id"])
    title = str(manifest.get("title", "")).replace("|", r"\|")
    checkpoint = " ⚑" if manifest.get("stop_for_human") else ""
    blockers = [
        item for item in (manifest.get("depends_on") or []) if status.get(item) != "complete"
    ]
    waiting = ", ".join(blockers) if blockers else "—"
    return f"| `{slice_id}`{checkpoint} | {title} | {waiting} |"


def render(slices: dict[str, dict[str, Any]], status: dict[str, str]) -> str:
    groups: dict[str, list[dict[str, Any]]] = {"complete": [], "ready": [], "blocked": []}
    for slice_id, manifest in slices.items():
        groups[status[slice_id]].append(manifest)

    lines = [
        "<!-- Generated by tools/render_roadmap.py. Do not edit by hand. -->",
        "<!-- Regenerate with: python tools/render_roadmap.py -->",
        "",
        "# Slice status",
        "",
        "The human-readable view of [`roadmap.yaml`](roadmap.yaml), which stays the",
        "queue of record. Nothing here is stored: status is derived from Git each time",
        "this file is generated, and CI fails if the committed copy has drifted from",
        "what the tool produces.",
        "",
        "A slice is **complete** when the trunk carries the merge of a branch named for",
        "it, or when a complete slice depends on it. It is **ready** when every",
        "dependency is complete and it is not. It is **blocked** otherwise. ⚑ marks a",
        "slice that stops for a human before it is marked done.",
        "",
    ]

    sections = (
        ("Ready to pick up", "ready", "Nothing is unblocked right now."),
        ("Blocked", "blocked", "Nothing is waiting on anything."),
        ("Complete", "complete", "Nothing has landed yet."),
    )
    for heading, key, empty in sections:
        entries = sorted(groups[key], key=lambda item: str(item["id"]))
        lines.append(f"## {heading} ({len(entries)})")
        lines.append("")
        if not entries:
            lines.extend([empty, ""])
            continue
        lines.append("| Slice | Title | Waiting on |")
        lines.append("|---|---|---|")
        lines.extend(row(manifest, status) for manifest in entries)
        lines.append("")

    lines.extend(
        [
            "---",
            "",
            "Picking one up: comment on the tracking issue first so two people do not",
            "build it twice, then follow [`CONTRIBUTING.md`](../../CONTRIBUTING.md).",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the committed copy is stale")
    parser.add_argument("--stdout", action="store_true", help="print instead of writing")
    args = parser.parse_args(argv[1:])

    document = yaml.safe_load(ROADMAP.read_text(encoding="utf-8")) or {}
    slices = {str(entry["id"]): entry for entry in document.get("slices", [])}
    if not slices:
        print(f"FAIL: no slices in {display(ROADMAP)}")
        return 1

    attributed = attributed_to_git(trunk()) & slices.keys()
    complete = close_over_dependencies(attributed, slices)
    rendered = render(slices, classify(slices, complete))

    if args.stdout:
        print(rendered, end="")
        return 0

    if args.check:
        # A shallow checkout can see no merge commits at all, which would render
        # every slice as unbuilt and report the committed file as stale for a
        # reason that has nothing to do with it. Refusing to answer is the honest
        # outcome: the caller must deepen the history, which is what the CI step
        # does before running this.
        if not attributed:
            print(
                "FAIL: no slice is attributable from this checkout, so staleness\n"
                "cannot be judged. Deepen the history first:\n"
                "  git fetch --no-tags --depth=200 origin main:refs/remotes/origin/main"
            )
            return 1
        current = STATUS.read_text(encoding="utf-8") if STATUS.exists() else ""
        if current == rendered:
            print(f"ok: {display(STATUS)} matches the roadmap")
            return 0
        print(f"FAIL: {display(STATUS)} is stale.\nRegenerate it: python tools/render_roadmap.py")
        return 1

    STATUS.write_text(rendered, encoding="utf-8")
    print(f"wrote {display(STATUS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
