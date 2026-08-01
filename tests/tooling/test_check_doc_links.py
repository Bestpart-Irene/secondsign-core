# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The documentation link gate's own guarantees.

Two properties carry the weight, the same two the sign-off gate holds itself
to. *It fails on what it claims to catch*: a relative link whose target does
not exist, in prose, in either inline or reference form. *It does not fail on
what it must not*: external targets it promised never to fetch, examples
inside code fences and code spans, and same-file heading anchors — each of
which would page someone about somebody else's uptime or about text that was
never a link.

The last case runs the gate over this repository's own tracked Markdown, so a
broken cross-reference fails the suite as well as the CI step.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_checker():
    path = REPO_ROOT / "tools" / "check_doc_links.py"
    spec = importlib.util.spec_from_file_location("secondsign_check_doc_links", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECKER = _load_checker()


def _write(tmp_path: Path, name: str, text: str) -> Path:
    file = tmp_path / name
    file.write_text(text, encoding="utf-8")
    return file


class TestItFailsOnWhatItClaimsToCatch:
    def test_a_broken_relative_link_is_reported_with_its_line(self, tmp_path: Path) -> None:
        page = _write(tmp_path, "page.md", "intro\n\nsee [the spec](missing.md).\n")
        broken = CHECKER.broken_links([page])
        assert [(item.file, item.line, item.target) for item in broken] == [(page, 3, "missing.md")]

    def test_a_broken_image_is_reported(self, tmp_path: Path) -> None:
        page = _write(tmp_path, "page.md", "![logo](assets/logo.svg)\n")
        assert len(CHECKER.broken_links([page])) == 1

    def test_a_broken_reference_definition_is_reported(self, tmp_path: Path) -> None:
        page = _write(tmp_path, "page.md", "[spec][1]\n\n[1]: gone/spec.md\n")
        broken = CHECKER.broken_links([page])
        assert [(item.line, item.target) for item in broken] == [(3, "gone/spec.md")]

    def test_an_anchor_does_not_rescue_a_missing_file(self, tmp_path: Path) -> None:
        page = _write(tmp_path, "page.md", "[gone](missing.md#section)\n")
        assert len(CHECKER.broken_links([page])) == 1

    def test_the_gate_exits_nonzero_and_prints_file_and_line(self, tmp_path: Path, capsys) -> None:
        page = _write(tmp_path, "page.md", "[gone](missing.md)\n")
        code = CHECKER.main(["check_doc_links.py", str(page)])
        printed = capsys.readouterr().out
        assert code == 1
        assert "page.md:1" in printed
        assert "missing.md" in printed


class TestItDoesNotFailOnWhatItMustNot:
    def test_a_valid_relative_link_resolves(self, tmp_path: Path) -> None:
        _write(tmp_path, "other.md", "content\n")
        page = _write(tmp_path, "page.md", "[other](other.md) and [dir](sub/)\n")
        (tmp_path / "sub").mkdir()
        assert CHECKER.broken_links([page]) == []

    def test_external_targets_are_never_checked(self, tmp_path: Path) -> None:
        page = _write(
            tmp_path,
            "page.md",
            "[a](https://example.invalid/gone) [b](http://example.invalid)\n"
            "[c](mailto:nobody@example.invalid)\n"
            "[badge]: https://example.invalid/badge.svg\n",
        )
        assert CHECKER.broken_links([page]) == []

    def test_a_same_file_anchor_resolves_to_the_file_itself(self, tmp_path: Path) -> None:
        _write(tmp_path, "other.md", "# section\n")
        page = _write(tmp_path, "page.md", "[here](#local) [there](other.md#section)\n")
        assert CHECKER.broken_links([page]) == []

    def test_code_fences_and_code_spans_are_examples_not_links(self, tmp_path: Path) -> None:
        page = _write(
            tmp_path,
            "page.md",
            "```markdown\n[example](does-not-exist.md)\n```\n"
            "and `[inline](also-missing.md)` in a span\n",
        )
        assert CHECKER.broken_links([page]) == []

    def test_the_gate_passes_a_clean_file_with_exit_zero(self, tmp_path: Path) -> None:
        page = _write(tmp_path, "page.md", "no links here\n")
        assert CHECKER.main(["check_doc_links.py", str(page)]) == 0


class TestThisRepositoryIsClean:
    def test_every_tracked_markdown_link_resolves(self) -> None:
        broken = CHECKER.broken_links(CHECKER.tracked_markdown())
        assert broken == [], "\n".join(f"{item.file}:{item.line}: {item.target}" for item in broken)

    def test_the_parser_is_not_vacuous_over_this_repository(self) -> None:
        """A checker that parses zero links out of a cross-linked repository
        is broken in the fail-open direction, and every other case here would
        still pass."""
        count = sum(
            len(CHECKER.targets_in(file.read_text(encoding="utf-8")))
            for file in CHECKER.tracked_markdown()
        )
        assert count >= 50, f"only {count} link targets parsed from tracked Markdown"
