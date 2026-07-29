# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""That a gate which should have run cannot quietly not run.

Skipping the on-chain job on a change that touches no Solidity is obviously
right, and it buys the one failure mode worth being afraid of here: a gate that
should have run and silently did not. A skipped job renders as a grey tick.
Nothing in a workflow `if:` expression is tested, nothing reports when it
evaluates wrongly, and a required check that quietly stops running looks exactly
like one that passes.

So two things are under test, and the second matters more than the first:

*The decision.* Paths and the branch's slice manifest, either of which alone
fails open — and every uncertainty running the job, because "the tool got
confused" and "the change was irrelevant" must not produce the same silent skip.

*That the decision was honoured.* `verify` sees every job's result at the end
and refuses any skip that `decide` did not sanction, any failure, any
cancellation, and any job that never reported at all.

The last class in this file is the one that stops the two drifting apart: it
reads `.github/workflows/ci.yml` and asserts the job ids the tool reasons about
are the job ids that exist.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def _load_gates():
    """Load tools/ci_gates.py, which ships as a script, not a package.

    Registered in `sys.modules` before it executes: `@dataclass` resolves its
    own module to decide what a field annotation means, and a module loaded by
    path that is not registered resolves to `None`.
    """
    name = "secondsign_ci_gates"
    path = REPO_ROOT / "tools" / "ci_gates.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gates = _load_gates()


def _needs(**results: str) -> dict[str, dict[str, object]]:
    """The `needs` context as GitHub serialises it."""
    return {name: {"result": result, "outputs": {}} for name, result in results.items()}


def _all_green(**overrides: str) -> dict[str, dict[str, object]]:
    every = dict.fromkeys(
        (*gates.UNCONDITIONAL, *(job.job for job in gates.CONDITIONAL)), "success"
    )
    return _needs(**{**every, **overrides})


class TestTheDecisionFailsTowardsRunning:
    """Not knowing and not needing it must not produce the same answer."""

    def test_an_undeterminable_diff_runs_everything(self) -> None:
        decision = gates.decide(None, [], "CORE-S019")["onchain"]

        assert decision.run
        assert "could not be determined" in decision.reason

    def test_a_slice_whose_manifest_cannot_be_found_runs_everything(self) -> None:
        """The manifest is half the evidence. Missing it is an unknown, not a no."""
        decision = gates.decide([], None, "CORE-S999 has no manifest in the roadmap")["onchain"]

        assert decision.run
        assert "no manifest" in decision.reason

    def test_a_slice_branch_naming_no_slice_runs_everything(self) -> None:
        result, reason = gates.manifest_gates("feat/gateway-retry")

        assert result is None
        assert gates.decide([], result, reason)["onchain"].run


class TestTheTwoTriggers:
    """Either alone fails open, which is why there are two."""

    def test_a_changed_solidity_path_runs_it(self) -> None:
        """A `chore/` branch carries no slice, so paths are the only signal."""
        decision = gates.decide(
            ["onchain/test/topology/PinnedReleases.t.sol"], [], "this branch carries no slice"
        )["onchain"]

        assert decision.run
        assert "PinnedReleases" in decision.reason

    def test_a_declared_forge_gate_runs_it_with_no_solidity_touched_yet(self) -> None:
        """A slice's first commit is its manifest. Paths alone would skip here."""
        decision = gates.decide(["docs/slices/roadmap.yaml"], ["forge_test"], "CORE-S020")[
            "onchain"
        ]

        assert decision.run
        assert "declares forge_test" in decision.reason

    def test_neither_trigger_skips_it(self) -> None:
        decision = gates.decide(
            ["src/secondsign/policy/amount.py"], ["ruff_check", "pytest"], "CORE-S009"
        )["onchain"]

        assert not decision.run

    def test_a_change_touching_nothing_skips_it(self) -> None:
        assert not gates.decide([], [], "this branch carries no slice")["onchain"].run


class TestTheDeploymentGateHasTheSameTwoTriggers:
    """The containerised gate is conditional on the same terms as the Solidity
    one, and for the same reason: it builds three images, and a change that
    cannot affect what runs inside them should not pay for that."""

    def test_a_changed_compose_topology_runs_it(self) -> None:
        decision = gates.decide(
            ["deploy/reference/compose.yaml"], [], "this branch carries no slice"
        )["deployment"]

        assert decision.run
        assert "compose.yaml" in decision.reason

    def test_a_changed_policy_module_runs_it_too(self) -> None:
        """Wider than the gateway package on purpose: the gateway's answer is
        the decision path's answer, so a policy change changes what the assembled
        system asserts."""
        assert gates.decide(
            ["src/secondsign/policy/amount.py"], [], "this branch carries no slice"
        )["deployment"].run

    def test_a_declared_gate_runs_it_with_no_deployment_file_touched_yet(self) -> None:
        decision = gates.decide(
            ["docs/slices/roadmap.yaml"], ["deployment_topology"], "CORE-S019"
        )["deployment"]

        assert decision.run
        assert "declares deployment_topology" in decision.reason

    def test_a_documentation_change_skips_it(self) -> None:
        assert not gates.decide(["README.md"], ["ruff_check"], "CORE-S005")["deployment"].run

    def test_an_undeterminable_diff_runs_it(self) -> None:
        """Not knowing and not needing it must not produce the same answer."""
        assert gates.decide(None, [], "CORE-S019")["deployment"].run


class TestReadingTheManifest:
    def test_a_housekeeping_branch_declares_no_gates(self) -> None:
        assert gates.manifest_gates("chore/bump-ruff") == ([], "this branch carries no slice")

    def test_an_unknown_slice_id_is_an_unknown(self) -> None:
        result, reason = gates.manifest_gates("feat/CORE-S999/nothing")

        assert result is None
        assert "CORE-S999" in reason

    def test_a_real_slice_returns_the_gates_its_manifest_declares(self) -> None:
        """Against the committed roadmap, not a fixture — the file is the contract."""
        result, reason = gates.manifest_gates("feat/CORE-S001/plugin-contract")

        assert reason == "CORE-S001"
        assert result is not None
        assert "ruff_check" in result


class TestVerifyRefusesAnythingItCannotAccountFor:
    def test_all_green_passes(self) -> None:
        assert gates.verify(_all_green(), {"onchain": True}) == []

    def test_no_results_at_all_is_a_failure(self) -> None:
        """An empty `needs` context means nothing ran, or nothing was reported.
        Either way this build has not been shown to be anything."""
        problems = gates.verify({}, {"onchain": False})

        assert len(problems) == 1
        assert "nothing has been verified" in problems[0]

    def test_a_failed_job_is_a_failure(self) -> None:
        problems = gates.verify(_all_green(tests="failure"), {"onchain": True})

        assert problems == ["tests: failure"]

    def test_a_cancelled_job_is_a_failure(self) -> None:
        """Cancellation is not a pass. It is an absence of evidence."""
        problems = gates.verify(_all_green(package="cancelled"), {"onchain": True})

        assert problems == ["package: cancelled"]

    def test_a_missing_job_is_a_failure(self) -> None:
        """A job renamed in the workflow and not re-listed stops being checked,
        and nothing else would notice."""
        needs = _all_green()
        del needs["independence"]

        problems = gates.verify(needs, {"onchain": True})

        assert problems == ["independence: no result reported — was the job renamed or removed?"]

    def test_an_unconditional_job_may_not_be_skipped(self) -> None:
        problems = gates.verify(_all_green(tests="skipped"), {"onchain": True})

        assert problems == ["tests: skipped, and it is not a job that may be skipped"]


class TestVerifyHonoursTheDecisionAndNothingElse:
    def test_a_sanctioned_skip_passes(self) -> None:
        assert gates.verify(_all_green(onchain="skipped"), {"onchain": False}) == []

    def test_a_skip_the_decision_forbade_is_a_failure(self) -> None:
        """The whole point. `decide` said run; the job did not; the build fails."""
        problems = gates.verify(_all_green(onchain="skipped"), {"onchain": True})

        assert problems == ["onchain: skipped, but it was required to run"]

    def test_a_skip_with_no_decision_behind_it_is_a_failure(self) -> None:
        """Preflight failing takes its outputs with it. A skip nobody sanctioned
        is not made acceptable by the sanction being unavailable."""
        problems = gates.verify(_all_green(onchain="skipped"), {})

        assert problems == ["onchain: skipped, but no decision was recorded for it"]

    def test_running_a_job_the_decision_did_not_require_is_fine(self) -> None:
        """Over-running costs runner minutes. Under-running costs the guarantee."""
        assert gates.verify(_all_green(onchain="success"), {"onchain": False}) == []

    def test_every_problem_is_reported_not_just_the_first(self) -> None:
        problems = gates.verify(
            _all_green(tests="failure", package="cancelled", onchain="skipped"),
            {"onchain": True},
        )

        assert len(problems) == 3


class TestTheToolAndTheWorkflowDescribeTheSameBuild:
    """Two files that must agree, with a test that says so.

    Every constant in `ci_gates.py` names a job id in `ci.yml`. Rename one
    without the other and the tool reasons about a build that does not exist —
    which, for the conditional job, means silently sanctioning a skip forever.
    """

    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))

    def test_every_job_the_tool_names_exists(self) -> None:
        defined = set(self.workflow["jobs"])

        assert set(gates.UNCONDITIONAL) <= defined
        assert {job.job for job in gates.CONDITIONAL} <= defined

    def test_every_job_the_workflow_defines_is_accounted_for(self) -> None:
        """A new job that the tool does not know about is a job `CI gate` would
        not require, which is the fail-open direction."""
        known = {*gates.UNCONDITIONAL, *(job.job for job in gates.CONDITIONAL), "gate"}

        assert set(self.workflow["jobs"]) == known

    def test_the_gate_depends_on_every_job_it_judges(self) -> None:
        """`verify` can only see results for jobs listed in `needs`."""
        gate = self.workflow["jobs"]["gate"]

        assert set(gate["needs"]) == {*gates.UNCONDITIONAL, *(j.job for j in gates.CONDITIONAL)}

    def test_the_gate_runs_even_when_something_failed(self) -> None:
        """Without this it is skipped whenever a dependency fails, and a check
        that disappears when the build breaks reports nothing at all."""
        assert self.workflow["jobs"]["gate"]["if"] == "always()"

    def test_the_conditional_jobs_if_expression_carries_no_logic_of_its_own(self) -> None:
        """It reads the recorded decision. Logic here would be logic with no test."""
        for job in gates.CONDITIONAL:
            condition = self.workflow["jobs"][job.job]["if"]

            assert condition == f"fromJSON(needs.preflight.outputs.decisions).{job.job}"
            assert self.workflow["jobs"][job.job]["needs"] == "preflight"

    def test_preflight_publishes_the_decision(self) -> None:
        assert self.workflow["jobs"]["preflight"]["outputs"] == {
            "decisions": "${{ steps.gates.outputs.decisions }}"
        }
