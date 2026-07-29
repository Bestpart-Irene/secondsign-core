#!/usr/bin/env python3
# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Decide which conditional CI jobs a change needs, and prove they ran.

    python tools/ci_gates.py decide     # which conditional jobs must run
    python tools/ci_gates.py verify     # every job that had to run, ran and passed

Some jobs are expensive and only sometimes relevant. The on-chain job downloads
a pinned Foundry release and an npm tree to read `.sol` files, and a change to a
Python policy module has no use for either. Skipping it there is obviously
right, and it introduces the one failure mode that matters: **a gate that should
have run and silently did not.** A skipped job renders as a grey tick. Nothing
in a workflow's `if:` expression is tested, nothing reports when it evaluates
wrongly, and a required check that quietly stops running is indistinguishable
from one that passes.

So the decision is made here, in a file with tests, and it is checked here too:

- `decide` reads the changed files and the branch's slice manifest and answers,
  for each conditional job, run or skip — with the reason. The workflow's `if:`
  expressions carry no logic of their own; they read this answer.
- `verify` runs last, sees every job's result, and fails unless each one either
  succeeded or was skipped *and* `decide` had said it could be. That closes the
  loop: a wrong decision, a mis-evaluated `if:`, a cancelled job, or a job that
  never started fails the build instead of disappearing into a grey tick.

**Every uncertainty runs the job.** No base to diff against, an unreadable diff,
a slice id whose manifest cannot be found — each of those means the same thing:
this tool does not know, and the honest response to not knowing is to pay for
the job. The reverse default would make "the tool got confused" and "the change
was irrelevant" produce the same silent skip.

`verify` is the one required status check on `main`. That is deliberate: the
matrix underneath it can gain a Python version or split a job without anybody
editing branch protection, and a protection rule listing job names is otherwise
a second place the build definition has to be maintained — one that fails open,
because a required check that no longer exists is simply never reported.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ROADMAP = REPO_ROOT / "docs" / "slices" / "roadmap.yaml"

SLICE_ID_PATTERN = re.compile(r"[A-Z][A-Z0-9]*-S\d{3}")
SLICE_BRANCH_PREFIXES = ("feat/", "fix/")


@dataclass(frozen=True)
class Conditional:
    """A job that runs only when the change calls for it.

    Two independent triggers, because either alone fails open. Paths alone miss
    a slice that declares a Solidity gate and lands its first commit elsewhere;
    the manifest alone misses a change to `onchain/` made under a `chore/`
    branch, which carries no slice at all.
    """

    #: The workflow job id, which is also the key in the `needs` context.
    job: str
    #: Directory prefixes whose change requires this job.
    paths: tuple[str, ...]
    #: Manifest `gates:` entries that require this job.
    manifest_gates: tuple[str, ...]


CONDITIONAL = (
    Conditional(
        job="onchain",
        paths=("onchain/",),
        manifest_gates=("forge_fmt", "forge_test"),
    ),
    Conditional(
        job="deployment",
        # Wider than it looks, deliberately. The deployment gate asserts a
        # property of an *assembled system*, so anything that changes what runs
        # in one of those containers changes what it is asserting — the gateway
        # process, the client the agent container installs, the compose topology
        # and the suite itself. `src/secondsign/` whole rather than the gateway
        # package alone, because the gateway's answer is the decision path's.
        paths=(
            "deploy/",
            "src/secondsign/",
            "client/",
            "tests/deployment/",
        ),
        manifest_gates=("deployment_topology",),
    ),
)

#: Jobs that run for every change. Listed so `verify` fails when one is missing
#: from the `needs` context — a job deleted from the workflow, or renamed and
#: not re-listed, would otherwise stop being checked without any check failing.
UNCONDITIONAL = ("preflight", "tests", "independence", "package")


@dataclass(frozen=True)
class Decision:
    run: bool
    reason: str


def git(*args: str) -> tuple[int, str]:
    executable = shutil.which("git")
    if executable is None:
        raise RuntimeError("git executable not found")
    result = subprocess.run(  # noqa: S603 — resolved executable, fixed arguments
        [executable, "-C", str(REPO_ROOT), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode, (result.stdout + result.stderr).strip()


def current_branch() -> str:
    for name in ("GITHUB_HEAD_REF", "GITHUB_REF_NAME"):
        value = os.environ.get(name)
        if value:
            return value
    return git("rev-parse", "--abbrev-ref", "HEAD")[1]


def resolve_base() -> str | None:
    for candidate in ("origin/main", "main"):
        if git("rev-parse", "--verify", "--quiet", candidate)[0] == 0:
            return candidate
    return None


def changed_files() -> list[str] | None:
    """The paths this branch touches, or None when that cannot be established.

    None is not an empty list. An empty list means the branch changed nothing;
    None means the question could not be answered, and the two must not lead to
    the same decision.
    """
    base = resolve_base()
    if base is None:
        return None
    merge_base = git("merge-base", base, "HEAD")[1] or base
    code, output = git("diff", "--name-only", f"{merge_base}..HEAD")
    if code != 0:
        return None
    return [line for line in output.splitlines() if line.strip()]


def manifest_gates(branch: str) -> tuple[list[str] | None, str]:
    """The `gates:` a branch's slice declares, and how that was established.

    `(None, reason)` when a slice branch names an id with no manifest behind it
    — which is a genuine unknown, not an absence.
    """
    if not branch.startswith(SLICE_BRANCH_PREFIXES):
        return [], "this branch carries no slice"

    match = SLICE_ID_PATTERN.search(branch)
    if match is None:
        return None, f"{branch} is a slice branch naming no slice"

    # Imported here, not at module scope, so `verify` needs nothing installed.
    # It is the last check standing between a silent skip and a merge, and it
    # should not be able to fail on a dependency that has nothing to do with it.
    import yaml

    slice_id = match.group(0)
    document = yaml.safe_load(ROADMAP.read_text(encoding="utf-8")) or {}
    for entry in document.get("slices", []):
        if entry.get("id") == slice_id:
            return [str(gate) for gate in entry.get("gates") or []], slice_id
    return None, f"{slice_id} has no manifest in the roadmap"


def decide(files: list[str] | None, gates: list[str] | None, source: str) -> dict[str, Decision]:
    """Run or skip, per conditional job, with the reason it will be printed by."""
    decisions: dict[str, Decision] = {}
    for job in CONDITIONAL:
        if files is None:
            decisions[job.job] = Decision(True, "the changed files could not be determined")
            continue
        if gates is None:
            decisions[job.job] = Decision(True, source)
            continue

        touched = [path for path in files if path.startswith(job.paths)]
        if touched:
            decisions[job.job] = Decision(True, f"{touched[0]} changed")
            continue

        declared = [gate for gate in gates if gate in job.manifest_gates]
        if declared:
            decisions[job.job] = Decision(True, f"{source} declares {declared[0]}")
            continue

        decisions[job.job] = Decision(
            False,
            f"nothing under {', '.join(job.paths)} changed, "
            f"and no {' or '.join(job.manifest_gates)} gate is declared",
        )
    return decisions


def verify(needs: dict[str, dict[str, object]], required: dict[str, bool]) -> list[str]:
    """Every reason this build has not been shown to be green.

    `needs` is the workflow's `needs` context: one entry per job this depends
    on, each carrying a `result` of success, failure, cancelled or skipped.
    """
    if not needs:
        return ["no job results were reported, so nothing has been verified"]

    problems: list[str] = []
    conditional = {job.job for job in CONDITIONAL}

    for name in (*UNCONDITIONAL, *sorted(conditional)):
        if name not in needs:
            problems.append(f"{name}: no result reported — was the job renamed or removed?")

    for name, outcome in sorted(needs.items()):
        result = str(outcome.get("result", ""))
        if result == "success":
            continue
        if result != "skipped":
            problems.append(f"{name}: {result or 'no result'}")
            continue
        if name not in conditional:
            problems.append(f"{name}: skipped, and it is not a job that may be skipped")
        elif name not in required:
            problems.append(f"{name}: skipped, but no decision was recorded for it")
        elif required[name]:
            problems.append(f"{name}: skipped, but it was required to run")

    return problems


def emit(decisions: dict[str, Decision]) -> None:
    """Hand the decision to the workflow, which carries no logic of its own."""
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    payload = json.dumps({job: decision.run for job, decision in decisions.items()})
    with Path(path).open("a", encoding="utf-8") as handle:
        handle.write(f"decisions={payload}\n")


def run_decide() -> int:
    branch = current_branch()
    gates, source = manifest_gates(branch)
    decisions = decide(changed_files(), gates, source)

    print(f"Conditional jobs for {branch or 'this branch'} — {source}:\n")
    for job, decision in sorted(decisions.items()):
        print(f"  {'run ' if decision.run else 'skip'}  {job:<10} {decision.reason}")
    emit(decisions)
    return 0


def run_verify() -> int:
    try:
        needs = json.loads(os.environ.get("NEEDS", "") or "{}")
        required = json.loads(os.environ.get("DECISIONS", "") or "{}")
    except json.JSONDecodeError as exc:
        print(f"FAIL: the job results could not be read, so nothing is verified: {exc}")
        return 1

    problems = verify(needs, required)
    for name, outcome in sorted(needs.items()):
        print(f"  {str(outcome.get('result', '?')):<9} {name}")

    if problems:
        print("\nFAIL: this build has not been shown to be green.\n")
        for problem in problems:
            print(f"  {problem}")
        print(
            "\nA skipped job is only acceptable when tools/ci_gates.py decided it\n"
            "could be skipped, and that decision is recorded in the preflight job's\n"
            "output. Anything else — a failure, a cancellation, a job that never\n"
            "reported — is a build that was not verified."
        )
        return 1

    print("\nok: every job that had to run, ran and passed")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("decide", "verify"))
    args = parser.parse_args(argv[1:])
    return run_decide() if args.command == "decide" else run_verify()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
