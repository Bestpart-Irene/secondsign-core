#!/usr/bin/env python3
# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Everything CI will say about your branch, said here first.

    python tools/contributor_check.py

A contributor's first pull request here has failed on the same four things
every time, and never on the code: a sign-off carrying a template address, a
branch name CI could not read a slice id out of, a file changed outside the
declared scope, and a `STATUS.md` that is derived and had been hand-edited.
Each is a one-command fix. Each was discovered on a remote runner, minutes
after a push, in a log the contributor had to go and find.

That is the defect this file exists to close. None of those four checks needs a
runner — they read the local repository and a Git config. Discovering them on
push rather than before it is a choice the project was making by omission, and
it spent a new contributor's goodwill on process rather than on the change they
came to make.

**It runs the same code CI runs.** The sign-off, scope and status checks are
`tools/check_dco.py`, `tools/check_slice_scope.py` and
`tools/render_roadmap.py --check` — invoked, not reimplemented. A local
preflight that agrees with CI only by convention is worse than none: it earns
trust and then spends it the one time the two have drifted apart.

**What it deliberately does not run:** `ruff`, `mypy`, `pytest`, `lint-imports`.
Those are in CONTRIBUTING.md's quickstart, they say what is wrong in their own
words, and wrapping them here would only put a second layer between a
contributor and a message that is already clear.

**Being behind `main` is reported and is not a failure.** `main` requires
branches to be up to date before merging, so every merge to trunk leaves every
open pull request behind. Making that a contributor's problem means asking
people to rebase on someone else's schedule; a maintainer presses "Update
branch". See CONTRIBUTING.md, "What a maintainer does for you".
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parent.parent

#: The prefixes `.github/workflows/ci.yml` runs on push, and the two that
#: `check_slice_scope.py` reads a slice id out of. A branch named anything else
#: still gets CI on the pull request, but not before it — which is a surprise
#: worth one line of output rather than a discovery.
SLICE_PREFIXES = ("feat/", "fix/")
HOUSEKEEPING_PREFIXES = ("docs/", "chore/")

SLICE_ID_PATTERN = re.compile(r"[A-Z][A-Z0-9]*-S\d{3}")

#: Names that are a template's suggestion rather than anyone's name. The address
#: side of this is `check_dco.address_problem`, imported below rather than
#: repeated — one placeholder list, in the file whose failure prints it.
PLACEHOLDER_NAME = re.compile(
    r"^(your[\s._-]?name|first[\s._-]?last|user(name)?|me|todo|changeme)$",
    re.IGNORECASE,
)

OK, FAIL, NOTE, SKIP = "ok", "FAIL", "note", "skip"


@dataclass(frozen=True)
class Result:
    """One check's verdict. `fix` is a command, not advice."""

    name: str
    status: str
    detail: str
    fix: str = ""

    @property
    def failed(self) -> bool:
        return self.status == FAIL


def git(*args: str) -> tuple[int, str]:
    """`(exit code, output)`. stderr is kept: it is where git explains itself."""
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


def run_tool(script: str, *args: str, env: dict[str, str] | None = None) -> tuple[int, str]:
    """Run one of this repository's own gates, exactly as CI does."""
    result = subprocess.run(  # noqa: S603 — this interpreter, a path we own
        [sys.executable, str(REPO_ROOT / "tools" / script), *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
        env={**os.environ, **(env or {})},
    )
    return result.returncode, (result.stdout + result.stderr).strip()


def load_dco() -> ModuleType:
    """`tools/check_dco.py` ships as a script, so it is loaded by path."""
    path = REPO_ROOT / "tools" / "check_dco.py"
    spec = importlib.util.spec_from_file_location("secondsign_check_dco", path)
    if spec is None or spec.loader is None:  # pragma: no cover — unreachable for a real file
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def current_branch() -> str:
    _, name = git("rev-parse", "--abbrev-ref", "HEAD")
    return name


# ── the checks ───────────────────────────────────────────────────────────────


def check_identity() -> Result:
    """The name and address every commit you make from here will assert.

    Checked before you commit rather than after, because the fix afterwards is a
    rebase over every commit on the branch, and a rebase is the step that turns
    a five-minute contribution into an afternoon.
    """
    name_code, name = git("config", "--get", "user.name")
    email_code, email = git("config", "--get", "user.email")

    setup = (
        'git config user.name  "Ada Lovelace"\n'
        "  git config user.email <the address on your GitHub account>\n\n"
        "  GitHub's privacy address works and keeps your own out of the log:\n"
        "  github.com/settings/emails → Keep my email addresses private, then\n"
        "  use the ID+USERNAME@users.noreply.github.com it shows you."
    )

    if name_code != 0 or not name:
        return Result("identity", FAIL, "git has no user.name", setup)
    if email_code != 0 or not email:
        return Result("identity", FAIL, "git has no user.email", setup)
    if PLACEHOLDER_NAME.match(name):
        return Result("identity", FAIL, f"{name!r} is a template's suggestion, not a name", setup)

    problem = load_dco().address_problem(email)
    if problem is not None:
        return Result("identity", FAIL, problem, setup)

    return Result("identity", OK, f"{name} <{email}>")


def check_branch(branch: str) -> Result:
    """That CI can read this branch, and that a slice branch names its slice."""
    if branch in {"", "HEAD"}:
        return Result("branch", SKIP, "detached HEAD; nothing to read a slice id out of")
    if branch == "main":
        return Result(
            "branch",
            FAIL,
            "you are on main, which is protected and takes no direct commits",
            "git checkout -b docs/<what-you-are-changing>",
        )

    if branch.startswith(SLICE_PREFIXES):
        match = SLICE_ID_PATTERN.search(branch)
        if match is None:
            return Result(
                "branch",
                FAIL,
                f"{branch} touches src/ but names no slice, so CI cannot check its scope",
                "git branch -m feat/<SLICE-ID>/<slug>      # the issue names the id",
            )
        return Result("branch", OK, f"{branch} — slice {match.group(0)}")

    if branch.startswith(HOUSEKEEPING_PREFIXES):
        return Result("branch", OK, f"{branch} — housekeeping, no slice needed")

    return Result(
        "branch",
        FAIL,
        f"{branch} matches no prefix CI runs on, so nothing runs until you open a PR",
        "git branch -m docs/<slug>        # or chore/, or feat/<SLICE-ID>/, or fix/<SLICE-ID>/",
    )


def check_sign_off(base: str | None) -> Result:
    """`tools/check_dco.py` over exactly the commits the pull request will carry."""
    if base is None:
        return Result("sign-off", SKIP, "no main branch to take a commit range from")

    code, output = run_tool("check_dco.py", f"{base}..HEAD")
    if code == 0:
        return Result("sign-off", OK, output.splitlines()[-1] if output else "every commit")

    return Result(
        "sign-off",
        FAIL,
        first_failure(output),
        "git rebase --exec 'git commit --amend --no-edit --reset-author -s' " + base,
    )


def check_scope(branch: str) -> Result:
    """`tools/check_slice_scope.py`, which exits 0 for a branch carrying no slice."""
    code, output = run_tool("check_slice_scope.py")
    if code == 0:
        return Result("scope", OK, output.splitlines()[-1] if output else "in scope")

    if not branch.startswith(SLICE_PREFIXES):  # pragma: no cover — the tool exits 0 here
        return Result("scope", FAIL, first_failure(output))

    return Result(
        "scope",
        FAIL,
        first_failure(output),
        "widen `scope:` in the manifest, in its own commit — or move the file's\n"
        "  change to its own branch. Scope is a promise, so changing it is a commit.",
    )


def check_roadmap_status() -> Result:
    """That the roadmap validates and `STATUS.md` still matches what it derives."""
    code, output = run_tool("validate_slice.py", "docs/slices/roadmap.yaml")
    if code != 0:
        return Result("roadmap", FAIL, first_failure(output))

    code, output = run_tool("render_roadmap.py", "--check")
    if code == 0:
        return Result("roadmap", OK, "roadmap validates, STATUS.md matches it")

    # A shallow clone cannot attribute any slice, and the tool refuses to judge
    # staleness rather than reporting everything unbuilt. That refusal is correct
    # and it is not this contributor's problem.
    if "no slice is attributable" in output:
        return Result(
            "roadmap",
            NOTE,
            "history too shallow to judge STATUS.md; CI deepens it and will",
            "git fetch --no-tags --depth=200 origin main:refs/remotes/origin/main",
        )

    return Result(
        "roadmap",
        FAIL,
        first_failure(output),
        "python tools/render_roadmap.py && git add docs/slices/STATUS.md\n"
        "  STATUS.md is derived from the roadmap and Git. Never edit it by hand.",
    )


def check_up_to_date(base: str | None) -> Result:
    """How far behind trunk this branch is — reported, never failed.

    `main` requires branches to be up to date, so every merge to trunk leaves
    every open pull request behind. A maintainer presses "Update branch"; asking
    contributors to rebase on trunk's schedule is how a small change acquires an
    afternoon of Git.
    """
    if base is None:
        return Result("vs main", SKIP, "no main branch to compare against")

    code, output = git("rev-list", "--count", f"HEAD..{base}")
    if code != 0:
        return Result("vs main", SKIP, f"cannot compare against {base}")

    behind = int(output or 0)
    if behind == 0:
        return Result("vs main", OK, f"up to date with {base}")

    return Result(
        "vs main",
        NOTE,
        f"{behind} commit(s) behind {base} — a maintainer presses Update branch",
        f"git merge {base}      # only if you want the gates run against trunk as it is now",
    )


# ── plumbing ─────────────────────────────────────────────────────────────────


def first_failure(output: str) -> str:
    """The line a gate failed on, not the whole essay it prints afterwards.

    Each of these tools ends with a `── How to fix this ──` block written for
    someone reading a CI log with no other context. Here there is other context —
    a fix line of our own, two lines down — so quoting the whole block twice
    would bury the one line that says what is actually wrong.
    """
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith(("FAIL", "error", "ERROR")):
            return stripped
    return output.splitlines()[0].strip() if output else "failed with no output"


def resolve_base() -> str | None:
    for candidate in ("origin/main", "main"):
        if git("rev-parse", "--verify", "--quiet", candidate)[0] == 0:
            return candidate
    return None


def collect(branch: str, base: str | None) -> list[Result]:
    return [
        check_identity(),
        check_branch(branch),
        check_sign_off(base),
        check_scope(branch),
        check_roadmap_status(),
        check_up_to_date(base),
    ]


def report(branch: str, results: list[Result]) -> str:
    width = max(len(result.name) for result in results)
    lines = [f"SecondSign contributor check — {branch or 'detached HEAD'}", ""]
    for result in results:
        lines.append(f"  {result.status:<5} {result.name:<{width}}  {result.detail}")
        if result.fix:
            for index, fix_line in enumerate(result.fix.splitlines()):
                lines.append(f"        {'└ ' if index == 0 else '  '}{fix_line}")
            lines.append("")

    failures = [result for result in results if result.failed]
    lines.append("")
    if failures:
        named = ", ".join(result.name for result in failures)
        lines.append(f"{len(failures)} of {len(results)} checks would fail in CI: {named}")
        lines.append("Fix these and CI has nothing left to say about the protocol.")
    else:
        lines.append("Nothing here will fail in CI. Run the gates, then push:")
        lines.append("  ruff check . && ruff format --check . && mypy src && pytest")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--offline",
        action="store_true",
        help="skip the fetch; compare against origin/main as your clone last saw it",
    )
    args = parser.parse_args(argv[1:])

    if not args.offline:
        git("fetch", "--quiet", "--no-tags", "origin", "main")

    branch = current_branch()
    results = collect(branch, resolve_base())
    print(report(branch, results))
    return 1 if any(result.failed for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
