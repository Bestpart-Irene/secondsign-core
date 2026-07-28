#!/usr/bin/env python3
# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Check that every commit in a range carries a sign-off that names someone.

The gate this replaces asserted one thing: that a line beginning
`Signed-off-by:` existed somewhere in the message. A pull request arrived whose
five commits all read `Signed-off-by: Elmar <твой_email@gmail.com>` — the
placeholder from a template, meaning *your_email* — and it passed, green.

That is the whole argument for this file. A Developer Certificate of Origin is a
statement by an identifiable person that they have the right to submit the work.
A check that only looks for the shape of the statement is enforcing a formatting
convention and calling it provenance, which is worse than enforcing nothing: the
project then makes a claim about its record that its own gate does not support.

Three rules, and each exists because of a specific way the trailer stops meaning
anything:

1. **A trailer must be present.** The original rule, kept.
2. **A trailer must name the commit's author or its committer.** Otherwise the
   assertion is about somebody who never made the commit — including the case
   where a trailer is copied wholesale from another project's history.
   Both identities are accepted because DCO 1.1 §(c) covers passing along work
   received from someone else: there, the author is the original person and the
   trailer belongs to whoever submitted it.
3. **The address has to be one an address could be.** ASCII, one `@`, a dotted
   domain, and not a reserved example domain or a known template value.

**Rule 3 is a heuristic and cannot be complete.** It raises the cost of signing
off carelessly; it does not verify that anyone exists. Nothing in a repository
can — verifying an address means sending mail to it. Stating that here rather
than letting the gate imply otherwise is the point.

Bot authors are exempt from rule 2. GitHub's automation signs off with a
different address than it authors with — Dependabot authors as
`…@users.noreply.github.com` and certifies as `support@github.com` — and a
machine account is not the identity this rule protects. Rules 1 and 3 still
apply to it.

Merge commits are skipped. A merge carries no authored content to certify, and
the commits it brings in are each checked on their own. It is also not optional:
`main` requires branches to be up to date, so the merge GitHub writes for
"Update branch" has no sign-off and no way to acquire one.

    python tools/check_dco.py <base>..<head>
    BASE_SHA=… HEAD_SHA=… python tools/check_dco.py
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys

#: `Signed-off-by: Real Name <address>`, leading whitespace tolerated because
#: some editors indent trailers, case-insensitive because Git itself is.
TRAILER = re.compile(r"^\s*signed-off-by:\s*(?P<name>.*?)\s*<(?P<email>[^>]*)>\s*$", re.IGNORECASE)

#: Deliberately loose. This is a plausibility check, not RFC 5322 — the goal is
#: to catch a value nobody could receive mail at, not to adjudicate exotic but
#: legal addresses.
ADDRESS = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

#: RFC 2606 reserves these precisely so they can never belong to anyone, which
#: makes them the one class of address a check can reject without guessing.
RESERVED_DOMAINS = ("example.com", "example.net", "example.org")
RESERVED_SUFFIXES = (".example", ".invalid", ".test", ".localhost")

#: Template values seen in the wild. Necessarily incomplete — see the module
#: docstring. `твой_email` is the one that got through.
PLACEHOLDER_LOCAL = re.compile(
    r"^(your[._-]?e?mail|youremail|e?mail|твой[._-]?email|changeme|user|username|todo)$",
    re.IGNORECASE,
)

FIX = """
── How to fix this ──────────────────────────────────────────────────

Every commit needs a `Signed-off-by:` line naming you, with the name and
address you actually use. It certifies that you have the right to submit
the work under Apache-2.0; it is not a copyright assignment, and it gives
no one a right to relicense your contribution. See CONTRIBUTING.md.

    git config user.name  "Your Name"
    git config user.email "you@example.com"      # your real address

    git rebase origin/main --exec 'git commit --amend --no-edit --reset-author -s'
    git push --force-with-lease

If your commits already carry a placeholder trailer, drop it while
rebasing — `git rebase -i origin/main`, mark each commit `reword`, and
delete the old line. Two trailers, one of them fictional, is not better
than one.

─────────────────────────────────────────────────────────────────────
"""


def git(*args: str) -> tuple[bool, str]:
    """`(succeeded, output)` — never output alone.

    Swallowing the exit code here would make every failure of this gate look
    like a clean run: a bad range, a shallow checkout that cannot resolve the
    base, or a wrong working directory each produce no commits, and no commits
    reads as "nothing to complain about". A provenance gate that reports green
    when it could not see the commits is worse than no gate.
    """
    executable = shutil.which("git")
    if executable is None:
        raise RuntimeError("git executable not found")
    result = subprocess.run(  # noqa: S603 — resolved executable, fixed arguments
        [executable, *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0, result.stdout if result.returncode == 0 else result.stderr


def is_bot(name: str, email: str) -> bool:
    return name.endswith("[bot]") or "[bot]@" in email


def address_problem(email: str) -> str | None:
    """Why this address could not be one, or None if it plausibly could."""
    if not email:
        return "the sign-off has no address"
    if not email.isascii():
        # Internationalized addresses are legal and this rejects them. It is
        # also what catches a Cyrillic template value, and every address GitHub
        # will attach to a commit is ASCII. Open an issue if this is wrong for
        # you — it is a trade, not a judgement about names.
        return f"{email!r} is not an ASCII address"
    if not ADDRESS.match(email):
        return f"{email!r} is not shaped like an address"
    local, _, domain = email.rpartition("@")
    domain = domain.lower()
    if domain in RESERVED_DOMAINS or domain.endswith(RESERVED_SUFFIXES):
        return f"{email!r} uses a reserved example domain, so it reaches nobody"
    if PLACEHOLDER_LOCAL.match(local):
        return f"{email!r} looks like the placeholder from a template"
    return None


def identity(name: str, email: str) -> tuple[str, str]:
    return name.strip().casefold(), email.strip().casefold()


def check_commit(sha: str, record: str) -> list[str]:
    """Every reason this commit's sign-off does not certify anything."""
    author_name, author_email, committer_name, committer_email, subject, body = record.split(
        "\x00", 5
    )
    trailers = [
        (match.group("name"), match.group("email"))
        for line in body.splitlines()
        if (match := TRAILER.match(line))
    ]

    label = f"{sha[:9]} {subject}"
    if not trailers:
        return [f"{label}\n    no Signed-off-by line"]

    problems = [
        f"{label}\n    {problem}"
        for _, email in trailers
        if (problem := address_problem(email)) is not None
    ]

    if is_bot(author_name, author_email):
        return problems

    accepted = {identity(author_name, author_email), identity(committer_name, committer_email)}
    if not any(identity(name, email) in accepted for name, email in trailers):
        signed = ", ".join(f"{name} <{email}>" for name, email in trailers)
        problems.append(
            f"{label}\n"
            f"    signed off by {signed}\n"
            f"    but authored by {author_name} <{author_email}>\n"
            f"    a sign-off has to name the person who made the commit"
        )
    return problems


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("range", nargs="?", help="commit range, e.g. origin/main..HEAD")
    args = parser.parse_args(argv[1:])

    commit_range = args.range
    if not commit_range:
        base, head = os.environ.get("BASE_SHA", ""), os.environ.get("HEAD_SHA", "")
        if not base or not head:
            print("not a pull request; skipping")
            return 0
        commit_range = f"{base}..{head}"

    resolved, log = git(
        "log",
        "--no-merges",
        "--format=%H%x00%aN%x00%aE%x00%cN%x00%cE%x00%s%x00%b%x01",
        commit_range,
    )
    if not resolved:
        print(f"FAIL: cannot read {commit_range} from this checkout.\n\n  {log.strip()}")
        return 1

    problems: list[str] = []
    for entry in log.split("\x01"):
        entry = entry.strip("\n")
        if not entry:
            continue
        sha, _, record = entry.partition("\x00")
        problems.extend(check_commit(sha, record))

    if problems:
        print("FAIL: these commits carry no sign-off that names anyone.\n")
        for problem in problems:
            print(f"  {problem}\n")
        print(FIX)
        return 1

    print("ok: every commit is signed off by its author")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
