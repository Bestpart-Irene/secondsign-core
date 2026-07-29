# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The contributor renderer's own guarantees.

`CONTRIBUTORS.md` is a claim about people rather than about code, and it is the
file an outsider reads to decide whether contributing here goes anywhere. Three
properties carry that weight:

*Nobody is dropped and nobody is doubled.* A contributor who changed machines
has two Git identities and must still appear once; a contributor whose only
commit is old must still appear at all. Both failures are silent — the file
still renders, it is just wrong about a person.

*Bots are not people.* Dependabot signs off its commits, so the sign-off cannot
be what separates them. If the separation ever broke, the list that a licensing
question is asked about would name a machine account.

*The output is stable under ordinary commits.* The list is ordered by first
appearance and carries no counts, so it changes when someone arrives and at no
other time. That is what lets it be refreshed automatically without a diff on
every merge — and what stops a freshness check from failing on a pull request
that has nothing to do with it.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_renderer():
    """Load tools/render_contributors.py, which ships as a script rather than a package."""
    path = REPO_ROOT / "tools" / "render_contributors.py"
    spec = importlib.util.spec_from_file_location("secondsign_render_contributors", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


renderer = _load_renderer()


def _log(*entries: tuple[str, str]) -> str:
    """The `--format=%aN%x00%aE --reverse` output the tool parses, oldest first."""
    return "".join(f"{name}\x00{email}\n" for name, email in entries)


def _with_log(monkeypatch, text: str) -> None:
    monkeypatch.setattr(renderer, "git", lambda *args: text)


class TestWhoCounts:
    def test_order_is_first_commit_not_volume(self, monkeypatch) -> None:
        """The one ordering that does not move when someone commits again.

        Ordering by commit count would reshuffle the file whenever anyone
        worked, which is the property that makes an automatically refreshed
        list unusable.
        """
        _with_log(
            monkeypatch,
            _log(
                ("First", "first@example.com"),
                ("Second", "second@example.com"),
                ("First", "first@example.com"),
                ("First", "first@example.com"),
            ),
        )

        assert renderer.contributors("HEAD") == [
            ("First", "first@example.com"),
            ("Second", "second@example.com"),
        ]

    def test_one_person_is_listed_once(self, monkeypatch) -> None:
        _with_log(
            monkeypatch,
            _log(("Ada", "ada@example.com"), ("Ada", "ada@example.com")),
        )

        assert renderer.contributors("HEAD") == [("Ada", "ada@example.com")]

    def test_the_same_address_in_a_different_case_is_the_same_person(self, monkeypatch) -> None:
        """Addresses are case-insensitive, and Git will happily record both."""
        _with_log(
            monkeypatch,
            _log(("Ada", "Ada@Example.com"), ("Ada", "ada@example.com")),
        )

        assert renderer.contributors("HEAD") == [("Ada", "Ada@Example.com")]

    def test_a_second_identity_is_folded_by_mailmap_not_by_this_tool(self, monkeypatch) -> None:
        """Two addresses are two people here, and that is correct.

        The tool reads `%aN`/`%aE`, which Git has already resolved through
        `.mailmap`. Guessing that two addresses are one person — by matching
        display names, say — would merge two genuine contributors who share a
        common name, and merging people in a copyright record is the expensive
        direction of that error.
        """
        _with_log(
            monkeypatch,
            _log(("Ada", "ada@work.example"), ("Ada", "ada@home.example")),
        )

        assert len(renderer.contributors("HEAD")) == 2

    def test_an_author_with_no_name_is_skipped(self, monkeypatch) -> None:
        _with_log(monkeypatch, _log(("", "anonymous@example.com"), ("Ada", "ada@example.com")))

        assert renderer.contributors("HEAD") == [("Ada", "ada@example.com")]


class TestBotsAreNotPeople:
    def test_a_github_app_account_is_excluded(self) -> None:
        assert renderer.is_bot(
            "dependabot[bot]", "49699333+dependabot[bot]@users.noreply.github.com"
        )

    def test_the_actions_bot_is_excluded(self) -> None:
        assert renderer.is_bot(
            "github-actions[bot]", "41898282+github-actions[bot]@users.noreply.github.com"
        )

    def test_a_person_whose_name_contains_bot_is_not_excluded(self) -> None:
        """`Botond` is a name. A substring match over "bot" would delete him."""
        assert not renderer.is_bot("Botond Nagy", "botond@example.com")

    def test_bots_do_not_reach_the_rendered_list(self, monkeypatch) -> None:
        _with_log(
            monkeypatch,
            _log(
                ("Ada", "ada@example.com"),
                ("dependabot[bot]", "49699333+dependabot[bot]@users.noreply.github.com"),
            ),
        )

        assert renderer.contributors("HEAD") == [("Ada", "ada@example.com")]


class TestTheRenderedFile:
    def test_the_count_matches_the_list(self, monkeypatch) -> None:
        rendered = renderer.render([("Ada", "a@example.com"), ("Grace", "g@example.com")])

        assert "Everyone who has landed a commit (2)" in rendered
        assert "- Ada" in rendered
        assert "- Grace" in rendered

    def test_no_email_address_is_published(self) -> None:
        """A contributor list is a durable, indexed page. Their address is not ours to post."""
        rendered = renderer.render([("Ada", "ada@example.com")])

        assert "ada@example.com" not in rendered

    def test_the_same_history_renders_identical_bytes(self) -> None:
        people = [("Ada", "a@example.com"), ("Grace", "g@example.com")]

        assert renderer.render(people) == renderer.render(people)

    def test_an_empty_history_still_renders(self) -> None:
        """Only reachable on a fresh repository, but it must not produce a broken page."""
        assert "Nobody yet." in renderer.render([])

    def test_the_maintainer_is_stated_not_derived(self) -> None:
        """Who can merge is not a fact any commit records."""
        rendered = renderer.render([("Ada", "a@example.com")])

        assert "## Maintainer" in rendered
        assert "@Bestpart-Irene" in rendered


class TestTheCheckCanFail:
    def test_check_fails_when_the_committed_copy_drifts(self, monkeypatch, tmp_path: Path) -> None:
        stale = tmp_path / "CONTRIBUTORS.md"
        stale.write_text("# Contributors\n", encoding="utf-8")
        monkeypatch.setattr(renderer, "CONTRIBUTORS", stale)
        _with_log(
            monkeypatch,
            _log(("Ada", "a@example.com"), ("Grace", "g@example.com")),
        )

        assert renderer.main(["render_contributors.py", "--check"]) == 1

    def test_check_passes_on_a_current_copy(self, monkeypatch, tmp_path: Path) -> None:
        people = [("Ada", "a@example.com"), ("Grace", "g@example.com")]
        current = tmp_path / "CONTRIBUTORS.md"
        current.write_text(renderer.render(people), encoding="utf-8")
        monkeypatch.setattr(renderer, "CONTRIBUTORS", current)
        _with_log(monkeypatch, _log(*people))

        assert renderer.main(["render_contributors.py", "--check"]) == 0

    def test_check_refuses_a_history_it_cannot_see(self, monkeypatch, tmp_path: Path) -> None:
        """A shallow clone shows one author. Reporting the file stale on that
        basis would be a check failing on the environment, and the fix people
        learn for such a check is to stop reading it."""
        current = tmp_path / "CONTRIBUTORS.md"
        current.write_text("anything", encoding="utf-8")
        monkeypatch.setattr(renderer, "CONTRIBUTORS", current)
        _with_log(monkeypatch, _log(("Ada", "a@example.com")))

        assert renderer.main(["render_contributors.py", "--check"]) == 1

    def test_stdout_writes_no_file(self, monkeypatch, tmp_path: Path) -> None:
        absent = tmp_path / "CONTRIBUTORS.md"
        monkeypatch.setattr(renderer, "CONTRIBUTORS", absent)
        _with_log(monkeypatch, _log(("Ada", "a@example.com")))

        assert renderer.main(["render_contributors.py", "--stdout"]) == 0
        assert not absent.exists()

    def test_writing_produces_a_copy_that_checks_clean(self, monkeypatch, tmp_path: Path) -> None:
        target = tmp_path / "CONTRIBUTORS.md"
        monkeypatch.setattr(renderer, "CONTRIBUTORS", target)
        _with_log(
            monkeypatch,
            _log(("Ada", "a@example.com"), ("Grace", "g@example.com")),
        )

        assert renderer.main(["render_contributors.py"]) == 0
        assert renderer.main(["render_contributors.py", "--check"]) == 0


class TestTheCommittedCopy:
    def test_the_committed_copy_is_generated_by_this_tool(self) -> None:
        """The header is what tells the next person not to edit it by hand."""
        committed = (REPO_ROOT / "CONTRIBUTORS.md").read_text(encoding="utf-8")

        assert committed.startswith("<!-- Generated by tools/render_contributors.py.")

    def test_the_committed_copy_names_no_bot(self) -> None:
        committed = (REPO_ROOT / "CONTRIBUTORS.md").read_text(encoding="utf-8")

        assert "[bot]" not in committed
