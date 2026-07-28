# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The status renderer's own guarantees.

`STATUS.md` is the one document in this repository that reports what is built.
If it can be wrong, it is worse than absent — a status table nobody trusts still
gets quoted. Three properties carry that weight:

*Dependency closure is sound, not decorative.* It is what attributes the slices
built before the branch-naming convention existed. If it stopped working, the
project's own foundation would render as unbuilt while everything above it
rendered as done, which is exactly the kind of visible nonsense that teaches a
reader to ignore the file.

*Ready and blocked are decided by unmet dependencies alone.* A slice with every
dependency complete is available to pick up; one waiting on anything is not, and
the table has to name what it is waiting on or it is not actionable.

*`--check` actually fails on drift.* The committed copy is only trustworthy
because CI refuses a stale one. A check that passes regardless is not a check —
the same reason the Solidity gate proves it can fail.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_renderer():
    """Load tools/render_roadmap.py, which ships as a script rather than a package."""
    path = REPO_ROOT / "tools" / "render_roadmap.py"
    spec = importlib.util.spec_from_file_location("secondsign_render_roadmap", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


renderer = _load_renderer()


def _slices(*pairs: tuple[str, list[str]]) -> dict[str, dict[str, object]]:
    return {
        slice_id: {"id": slice_id, "title": slice_id, "depends_on": list(dependencies)}
        for slice_id, dependencies in pairs
    }


class TestDependencyClosure:
    def test_a_dependency_of_a_complete_slice_is_complete(self) -> None:
        """The inference that attributes the pre-convention slices.

        CORE-S001 through CORE-S003 carry no slice id in any commit message, so
        Git cannot attribute them directly. They are reachable only because
        CORE-S004, which Git can attribute, depends on them transitively.
        """
        slices = _slices(("S1", []), ("S2", ["S1"]), ("S3", ["S2"]), ("S4", ["S3"]))

        complete = renderer.close_over_dependencies({"S4"}, slices)

        assert complete == {"S1", "S2", "S3", "S4"}

    def test_closure_does_not_walk_upward(self) -> None:
        """A completed dependency says nothing about what depends on it."""
        slices = _slices(("S1", []), ("S2", ["S1"]))

        assert renderer.close_over_dependencies({"S1"}, slices) == {"S1"}

    def test_a_dependency_cycle_terminates(self) -> None:
        """The validator rejects cycles, but this must not hang if one arrives."""
        slices = _slices(("S1", ["S2"]), ("S2", ["S1"]))

        assert renderer.close_over_dependencies({"S1"}, slices) == {"S1", "S2"}

    def test_an_unknown_dependency_is_ignored_rather_than_invented(self) -> None:
        slices = _slices(("S1", ["MISSING-S999"]))

        assert renderer.close_over_dependencies({"S1"}, slices) == {"S1"}


class TestClassification:
    def test_every_dependency_complete_means_ready(self) -> None:
        slices = _slices(("S1", []), ("S2", ["S1"]))

        status = renderer.classify(slices, complete={"S1"})

        assert status == {"S1": "complete", "S2": "ready"}

    def test_one_unmet_dependency_means_blocked(self) -> None:
        slices = _slices(("S1", []), ("S2", ["S1"]), ("S3", ["S1", "S2"]))

        status = renderer.classify(slices, complete={"S1"})

        assert status["S2"] == "ready"
        assert status["S3"] == "blocked"

    def test_a_blocked_row_names_what_it_waits_on(self) -> None:
        slices = _slices(("S1", []), ("S2", ["S1"]))
        status = renderer.classify(slices, complete=set())

        rendered = renderer.row(slices["S2"], status)

        assert "S1" in rendered

    def test_a_ready_row_waits_on_nothing(self) -> None:
        slices = _slices(("S1", []))
        status = renderer.classify(slices, complete=set())

        assert "—" in renderer.row(slices["S1"], status)


class TestGitAttribution:
    def test_both_merge_conventions_are_recognised(self) -> None:
        """The trunk carries two, and dropping either loses real slices."""
        subjects = (
            "Merge pull request #29 from Bestpart-Irene/feat/CORE-S017/control-plane-isolation",
            "Merge slice CORE-S004: structured findings and canonical ordering",
            "Merge pull request #2 from someone/fix/CORE-S099/a-repair",
        )
        found = {
            match
            for pattern in renderer.MERGE_PATTERNS
            for subject in subjects
            for match in pattern.findall(subject)
        }

        assert found == {"CORE-S017", "CORE-S004", "CORE-S099"}

    def test_a_chore_branch_attributes_nothing(self) -> None:
        subject = "Merge pull request #30 from Bestpart-Irene/chore/onchain-drop-peer-dependencies"

        found = [match for pattern in renderer.MERGE_PATTERNS for match in pattern.findall(subject)]

        assert found == []


class TestRenderedTextIsEnvironmentIndependent:
    """The output must depend on the repository, and on nothing else.

    An earlier draft printed which ref the history was read from. That made a
    developer's checkout (`origin/main`) and a shallow CI one (`HEAD`) produce
    different bytes from identical content, so `--check` failed on the
    environment. A gate that fails for reasons unrelated to what it guards is
    one people learn to re-run rather than read.
    """

    def test_no_ref_name_or_timestamp_leaks_into_the_output(self) -> None:
        slices = _slices(("S1", []), ("S2", ["S1"]))

        rendered = renderer.render(slices, renderer.classify(slices, complete={"S1"}))

        for leak in ("origin/main", "HEAD", "refs/"):
            assert leak not in rendered

    def test_the_same_inputs_render_identically(self) -> None:
        slices = _slices(("S1", []), ("S2", ["S1"]))
        status = renderer.classify(slices, complete={"S1"})

        assert renderer.render(slices, status) == renderer.render(slices, status)


class TestCheckRefusesRatherThanGuessing:
    """`--check` is the gate; these are the two ways it must not go quietly green.

    Freshness against the real repository is asserted by the CI step, which
    deepens the history first. Asserting it here as well would make this suite
    fail on a shallow clone — the exact environment-dependence above.
    """

    def test_check_fails_when_the_committed_copy_drifts(self, tmp_path: Path) -> None:
        """A gate that cannot fail is not a gate."""
        original = renderer.STATUS
        stale = tmp_path / "STATUS.md"
        stale.write_text("# not what the tool produces\n", encoding="utf-8")
        try:
            renderer.STATUS = stale
            assert renderer.main(["render_roadmap.py", "--check"]) == 1
        finally:
            renderer.STATUS = original

    def test_check_refuses_when_no_slice_is_attributable(self, monkeypatch) -> None:
        """A shallow checkout must not be read as "nothing has been built".

        Rendering every slice as unbuilt and then reporting the committed file
        as stale would be the fail-open form of this gate: it answers from a
        history it cannot see.
        """
        monkeypatch.setattr(renderer, "attributed_to_git", lambda ref: set())

        assert renderer.main(["render_roadmap.py", "--check"]) == 1

    def test_the_committed_copy_covers_every_slice(self) -> None:
        """Independent of Git: every queued slice appears somewhere in the table."""
        import yaml

        document = yaml.safe_load(renderer.ROADMAP.read_text(encoding="utf-8"))
        rendered = renderer.STATUS.read_text(encoding="utf-8")

        for entry in document["slices"]:
            assert f"`{entry['id']}`" in rendered
