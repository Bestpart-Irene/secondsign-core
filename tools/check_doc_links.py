#!/usr/bin/env python3
# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""Check that every relative link in tracked Markdown resolves to a real path.

The documentation is heavily cross-linked — the README indexes the other
documents, `INVARIANTS.md` names test files, the contribution protocol and the
roadmap point at each other. A renamed file breaks those links silently, and a
broken link in a security document reads as an unmaintained project.

What is checked: inline links and images, and reference-style definitions, in
every tracked `*.md` file. A target with a heading anchor resolves if the file
before the `#` exists; a same-file `#anchor` always resolves. Links inside
fenced code blocks and inline code spans are examples, not links, and are
ignored.

What is deliberately not checked: external `http(s)` targets. A gate that
depends on someone else's uptime fails for reasons unrelated to this
repository, and gets switched off within a month.

    python tools/check_doc_links.py            # every tracked *.md
    python tools/check_doc_links.py README.md  # just these files

Exits non-zero on the first pass that finds a broken link, printing the file
and line of each.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple
from urllib.parse import unquote

REPO_ROOT = Path(__file__).resolve().parent.parent

# Schemes whose targets are not files in this repository.
EXTERNAL = ("http://", "https://", "mailto:", "tel:")

INLINE_LINK = re.compile(r"!?\[[^\]]*\]\(\s*(<[^>]*>|[^)\s]+)[^)]*\)")
REFERENCE_DEFINITION = re.compile(r"^\s{0,3}\[[^\]]+\]:\s+(<[^>]*>|\S+)")
CODE_SPAN = re.compile(r"`[^`]*`")
FENCE = re.compile(r"^\s*(```|~~~)")


class BrokenLink(NamedTuple):
    file: Path
    line: int
    target: str


def targets_in(text: str) -> list[tuple[int, str]]:
    """Every link target with its 1-indexed line, code blocks excluded."""
    found: list[tuple[int, str]] = []
    in_fence = False
    for number, line in enumerate(text.splitlines(), start=1):
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        stripped = CODE_SPAN.sub("", line)
        definition = REFERENCE_DEFINITION.match(stripped)
        if definition:
            found.append((number, definition.group(1)))
            continue
        for match in INLINE_LINK.finditer(stripped):
            found.append((number, match.group(1)))
    return found


def resolve(target: str, markdown_file: Path) -> bool:
    """Whether a target names something that exists in the working tree."""
    cleaned = target.strip().strip("<>")
    path_part = cleaned.split("#", 1)[0]
    if not path_part:  # a same-file `#anchor` resolves to the file itself
        return True
    path_part = unquote(path_part)
    if path_part.startswith("/"):
        candidate = REPO_ROOT / path_part.lstrip("/")
    else:
        candidate = markdown_file.parent / path_part
    return candidate.exists()


def broken_links(files: list[Path]) -> list[BrokenLink]:
    broken: list[BrokenLink] = []
    for markdown_file in files:
        text = markdown_file.read_text(encoding="utf-8")
        for line, target in targets_in(text):
            cleaned = target.strip().strip("<>")
            if not cleaned or cleaned.lower().startswith(EXTERNAL):
                continue
            if not resolve(target, markdown_file):
                broken.append(BrokenLink(markdown_file, line, cleaned))
    return broken


def tracked_markdown() -> list[Path]:
    executable = shutil.which("git")
    if executable is None:
        raise RuntimeError("git executable not found")
    result = subprocess.run(  # noqa: S603 — resolved executable, fixed arguments
        [executable, "-C", str(REPO_ROOT), "ls-files", "--", "*.md"],
        capture_output=True,
        text=True,
        check=True,
    )
    return [REPO_ROOT / line for line in result.stdout.splitlines() if line.strip()]


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        files = [Path(argument).resolve() for argument in argv[1:]]
    else:
        files = tracked_markdown()

    broken = broken_links(files)
    if broken:
        print(f"FAIL: {len(broken)} broken link(s):")
        for item in broken:
            try:
                shown = item.file.relative_to(REPO_ROOT)
            except ValueError:
                shown = item.file
            print(f"  {shown}:{item.line}: {item.target}")
        print(
            "\nEither the target moved and the link did not, or the link is\n"
            "wrong. External http(s) targets are not checked here."
        )
        return 1

    print(f"ok: every relative link in {len(files)} Markdown file(s) resolves")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
