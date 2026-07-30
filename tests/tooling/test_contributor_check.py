# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The local preflight's own guarantees.

This tool's whole value is that a contributor can believe it. Two properties
carry that, and they pull in opposite directions:

*It fails on what CI fails on.* Every check here has a counterpart on a runner,
and a preflight that says "clean" before a red build has done more damage than
no preflight — it taught someone to skip the log.

*It does not fail on what CI tolerates.* Being behind `main` is the case that
matters: trunk moves, every open branch falls behind, and `main` requires
branches to be up to date. If that were a failure here, the tool would tell
every contributor their work is broken every time somebody else merges.

The gates themselves are stubbed. `check_dco.py`, `check_slice_scope.py` and
`render_roadmap.py` have their own suites; what is under test here is the
translation from their exit codes into something worth acting on.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_checker():
    """Load tools/contributor_check.py, which ships as a script, not a package.

    Registered in `sys.modules` before it executes: `@dataclass` resolves its
    own module to decide what a field annotation means, and a module loaded by
    path that is not registered resolves to `None`.
    """
    name = "secondsign_contributor_check"
    path = REPO_ROOT / "tools" / "contributor_check.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


checker = _load_checker()


def _with_config(monkeypatch, **values: str) -> None:
    """Stand in for `git config --get <key>`; a missing key exits 1, as git does."""

    def fake_git(*args: str) -> tuple[int, str]:
        if args[:2] == ("config", "--get"):
            value = values.get(args[2], "")
            return (0, value) if value else (1, "")
        raise AssertionError(f"unexpected git call: {args}")

    monkeypatch.setattr(checker, "git", fake_git)


def _with_tool(monkeypatch, **results: tuple[int, str]) -> None:
    """Stand in for the repository's own gates, keyed by script name."""

    def fake_run_tool(script: str, *args: str, env=None) -> tuple[int, str]:
        assert script in results, f"unexpected gate: {script}"
        return results[script]

    monkeypatch.setattr(checker, "run_tool", fake_run_tool)


class TestIdentityIsCheckedBeforeItIsCommittedTo:
    """The fix after committing is a rebase, which is the expensive outcome."""

    def test_a_configured_identity_passes(self, monkeypatch) -> None:
        _with_config(monkeypatch, **{"user.name": "Ada Lovelace", "user.email": "ada@lovelace.dev"})

        result = checker.check_identity()

        assert result.status == checker.OK
        assert "Ada Lovelace <ada@lovelace.dev>" in result.detail

    def test_no_name_fails(self, monkeypatch) -> None:
        _with_config(monkeypatch, **{"user.email": "ada@lovelace.dev"})

        result = checker.check_identity()

        assert result.failed
        assert "user.name" in result.detail

    def test_no_email_fails(self, monkeypatch) -> None:
        _with_config(monkeypatch, **{"user.name": "Ada Lovelace"})

        result = checker.check_identity()

        assert result.failed
        assert "user.email" in result.detail

    def test_a_template_name_fails(self, monkeypatch) -> None:
        _with_config(monkeypatch, **{"user.name": "Your Name", "user.email": "ada@lovelace.dev"})

        result = checker.check_identity()

        assert result.failed
        assert "not a name" in result.detail

    def test_the_address_rule_is_the_ones_CI_uses(self, monkeypatch) -> None:
        """Not a second placeholder list. `check_dco.address_problem`, imported.

        A local check that disagrees with the runner about what an address is
        would be discovered exactly once — on the push it failed to predict.
        """
        _with_config(monkeypatch, **{"user.name": "Ada Lovelace", "user.email": "ada@example.com"})

        result = checker.check_identity()

        assert result.failed
        assert "reaches nobody" in result.detail

    def test_the_fix_offers_the_github_privacy_address(self, monkeypatch) -> None:
        """CONTRIBUTING.md used to hand out a copyable address the gate rejects."""
        _with_config(monkeypatch, **{"user.name": "Ada Lovelace"})

        assert "users.noreply.github.com" in checker.check_identity().fix


class TestTheBranchNameCIHasToRead:
    def test_a_slice_branch_naming_its_slice_passes(self) -> None:
        result = checker.check_branch("feat/CORE-S021/gateway-retry")

        assert result.status == checker.OK
        assert "CORE-S021" in result.detail

    def test_a_slice_branch_with_no_slice_id_fails(self) -> None:
        result = checker.check_branch("feat/gateway-retry")

        assert result.failed
        assert "names no slice" in result.detail
        assert "git branch -m" in result.fix

    def test_housekeeping_needs_no_slice(self) -> None:
        assert checker.check_branch("docs/fix-a-typo").status == checker.OK
        assert checker.check_branch("chore/bump-ruff").status == checker.OK

    def test_being_on_main_fails(self) -> None:
        """Protected, and a commit here is a `git checkout -b` away from being lost."""
        result = checker.check_branch("main")

        assert result.failed
        assert "protected" in result.detail

    def test_an_unrecognised_prefix_fails(self) -> None:
        """CI's push triggers name four prefixes; anything else runs nothing."""
        result = checker.check_branch("elmar-patch-1")

        assert result.failed
        assert "nothing runs until you open a PR" in result.detail

    def test_a_detached_head_is_skipped_not_failed(self) -> None:
        assert checker.check_branch("HEAD").status == checker.SKIP
        assert checker.check_branch("").status == checker.SKIP


class TestTheGatesAreInvokedNotReimplemented:
    def test_a_green_dco_run_passes(self, monkeypatch) -> None:
        _with_tool(monkeypatch, **{"check_dco.py": (0, "ok: every commit is signed off")})

        result = checker.check_sign_off("origin/main")

        assert result.status == checker.OK

    def test_a_red_dco_run_names_the_range_in_its_fix(self, monkeypatch) -> None:
        """The rebase has to start from the same base the check used."""
        _with_tool(monkeypatch, **{"check_dco.py": (1, "FAIL: no sign-off\n\n── How to fix ──")})

        result = checker.check_sign_off("origin/main")

        assert result.failed
        assert result.detail == "FAIL: no sign-off"
        assert result.fix.endswith("origin/main")

    def test_no_trunk_means_no_range_to_check(self) -> None:
        assert checker.check_sign_off(None).status == checker.SKIP

    def test_a_scope_violation_says_the_manifest_is_the_place_to_fix_it(self, monkeypatch) -> None:
        """Widening scope in the same commit as the code defeats the point of scope."""
        _with_tool(monkeypatch, **{"check_slice_scope.py": (1, "FAIL: changed outside scope")})

        result = checker.check_scope("feat/CORE-S021/gateway-retry")

        assert result.failed
        assert "its own commit" in result.fix

    def test_scope_passes_when_the_gate_does(self, monkeypatch) -> None:
        _with_tool(monkeypatch, **{"check_slice_scope.py": (0, "ok: every changed file is")})

        assert checker.check_scope("feat/CORE-S021/x").status == checker.OK


class TestTheDerivedStatusTable:
    def test_both_gates_green_passes(self, monkeypatch) -> None:
        _with_tool(
            monkeypatch,
            **{"validate_slice.py": (0, "ok"), "render_roadmap.py": (0, "ok: STATUS.md matches")},
        )

        assert checker.check_roadmap_status().status == checker.OK

    def test_an_invalid_manifest_fails_before_the_status_table_is_consulted(
        self, monkeypatch
    ) -> None:
        _with_tool(monkeypatch, **{"validate_slice.py": (1, "FAIL: CORE-S021 has no scope")})

        result = checker.check_roadmap_status()

        assert result.failed
        assert "CORE-S021" in result.detail

    def test_a_stale_status_table_is_regenerated_never_edited(self, monkeypatch) -> None:
        _with_tool(
            monkeypatch,
            **{
                "validate_slice.py": (0, "ok"),
                "render_roadmap.py": (1, "FAIL: docs/slices/STATUS.md is stale."),
            },
        )

        result = checker.check_roadmap_status()

        assert result.failed
        assert "python tools/render_roadmap.py" in result.fix
        assert "Never edit it by hand" in result.fix

    def test_a_shallow_clone_is_a_note_not_a_failure(self, monkeypatch) -> None:
        """The renderer refuses to judge staleness it cannot see. Correct, and
        not something a contributor did wrong."""
        _with_tool(
            monkeypatch,
            **{
                "validate_slice.py": (0, "ok"),
                "render_roadmap.py": (1, "FAIL: no slice is attributable from this checkout"),
            },
        )

        result = checker.check_roadmap_status()

        assert result.status == checker.NOTE
        assert not result.failed
        assert "--depth=200" in result.fix


class TestBeingBehindTrunkIsNotTheContributorsFailure:
    """`main` is strict, so every merge to trunk leaves every open branch behind.

    Failing on this would mean telling contributors their branch is broken
    whenever somebody else's work merges — which is a maintainer's click, and is
    the single loudest source of false alarm a preflight could produce.
    """

    def test_being_behind_reports_and_does_not_fail(self, monkeypatch) -> None:
        monkeypatch.setattr(checker, "git", lambda *args: (0, "3"))

        result = checker.check_up_to_date("origin/main")

        assert result.status == checker.NOTE
        assert not result.failed
        assert "Update branch" in result.detail

    def test_being_current_passes(self, monkeypatch) -> None:
        monkeypatch.setattr(checker, "git", lambda *args: (0, "0"))

        assert checker.check_up_to_date("origin/main").status == checker.OK

    def test_an_unreadable_comparison_is_skipped(self, monkeypatch) -> None:
        monkeypatch.setattr(checker, "git", lambda *args: (128, "bad revision"))

        assert checker.check_up_to_date("origin/main").status == checker.SKIP

    def test_no_trunk_is_skipped(self) -> None:
        assert checker.check_up_to_date(None).status == checker.SKIP


class TestWhatTheContributorActuallyReads:
    def test_a_failing_gates_essay_is_reduced_to_the_line_that_says_why(self) -> None:
        """Each gate ends with a fix block written for a bare CI log. Here there
        is a fix line two rows down, so printing both buries the diagnosis."""
        output = "CORE-S021: 4 changed file(s)\nFAIL: changed outside scope\n── How to fix ──\n..."

        assert checker.first_failure(output) == "FAIL: changed outside scope"

    def test_output_with_no_FAIL_line_still_says_something(self) -> None:
        """A gate that crashed prints a traceback, not a diagnosis. Show it anyway."""
        crash = "Traceback (most recent call last):\n  File ...\nyaml.scanner.ScannerError"

        assert checker.first_failure(crash) == "Traceback (most recent call last):"

    def test_silence_from_a_failing_gate_is_reported_as_such(self) -> None:
        assert checker.first_failure("") == "failed with no output"

    def test_the_report_names_every_failing_check(self) -> None:
        results = [
            checker.Result("identity", checker.FAIL, "no user.name", "git config user.name"),
            checker.Result("branch", checker.OK, "docs/x"),
            checker.Result("scope", checker.FAIL, "outside scope"),
        ]

        text = checker.report("docs/x", results)

        assert "2 of 3 checks would fail in CI: identity, scope" in text
        assert "git config user.name" in text

    def test_a_clean_report_says_what_to_run_next(self) -> None:
        results = [checker.Result("identity", checker.OK, "Ada <ada@lovelace.dev>")]

        text = checker.report("docs/x", results)

        assert "Nothing here will fail in CI" in text
        assert "ruff check ." in text

    def test_notes_do_not_make_the_report_a_failure(self) -> None:
        results = [checker.Result("vs main", checker.NOTE, "3 commits behind", "git merge")]

        assert "Nothing here will fail in CI" in checker.report("docs/x", results)


class TestTheExitCode:
    """What a contributor's shell, and any hook they wire this into, reads."""

    def test_a_failing_check_exits_one(self, monkeypatch) -> None:
        monkeypatch.setattr(checker, "git", lambda *args: (0, ""))
        monkeypatch.setattr(checker, "resolve_base", lambda: None)
        monkeypatch.setattr(
            checker, "collect", lambda *_: [checker.Result("identity", checker.FAIL, "no name")]
        )

        assert checker.main(["contributor_check.py", "--offline"]) == 1

    def test_a_clean_run_exits_zero(self, monkeypatch) -> None:
        monkeypatch.setattr(checker, "git", lambda *args: (0, "docs/x"))
        monkeypatch.setattr(checker, "resolve_base", lambda: None)
        monkeypatch.setattr(
            checker, "collect", lambda *_: [checker.Result("branch", checker.OK, "docs/x")]
        )

        assert checker.main(["contributor_check.py", "--offline"]) == 0

    def test_it_fetches_unless_told_not_to(self, monkeypatch) -> None:
        """Comparing against a week-old `origin/main` answers the wrong question."""
        calls: list[tuple[str, ...]] = []

        def fake_git(*args: str) -> tuple[int, str]:
            calls.append(args)
            return 0, "docs/x"

        monkeypatch.setattr(checker, "git", fake_git)
        monkeypatch.setattr(checker, "resolve_base", lambda: None)
        monkeypatch.setattr(checker, "collect", lambda *_: [])
        monkeypatch.setattr(checker, "report", lambda *_: "")

        checker.main(["contributor_check.py"])
        assert ("fetch", "--quiet", "--no-tags", "origin", "main") in calls

        calls.clear()
        checker.main(["contributor_check.py", "--offline"])
        assert not any(call[0] == "fetch" for call in calls)


class TestItRunsAgainstThisRepository:
    """The stubs above prove the translation. This proves the wiring."""

    def test_every_gate_it_names_exists(self) -> None:
        for script in ("check_dco.py", "check_slice_scope.py", "render_roadmap.py"):
            assert (REPO_ROOT / "tools" / script).exists()

    def test_it_produces_a_verdict_for_the_real_checkout(self) -> None:
        results = checker.collect(checker.current_branch(), checker.resolve_base())

        assert [result.name for result in results] == [
            "identity",
            "branch",
            "sign-off",
            "scope",
            "roadmap",
            "vs main",
        ]
        assert all(
            result.status in {checker.OK, checker.FAIL, checker.NOTE, checker.SKIP}
            for result in results
        )

    def test_the_report_renders_for_the_real_checkout(self) -> None:
        results = checker.collect(checker.current_branch(), checker.resolve_base())

        assert "SecondSign contributor check" in checker.report("docs/x", results)


@pytest.mark.parametrize(
    "name", ["Your Name", "your name", "First Last", "username", "TODO", "changeme"]
)
def test_placeholder_names_are_caught(name: str) -> None:
    assert checker.PLACEHOLDER_NAME.match(name)


@pytest.mark.parametrize("name", ["Ada Lovelace", "Elmar", "Yousef Nameer", "Mary-Anne O'User"])
def test_real_names_are_not(name: str) -> None:
    """`user` as a whole name is a placeholder; a name containing it is not."""
    assert not checker.PLACEHOLDER_NAME.match(name)
