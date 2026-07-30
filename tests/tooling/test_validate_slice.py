# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The slice validator's own guarantees.

The validator is what stops a manifest promising coverage it cannot name. Two
properties matter enough to test rather than assume:

*It resolves each threat prefix against the model that defines it.* On-chain
threats are numbered C1 upward in a separate document from the financial A and B
threats. A widened pattern that accepted any C id without resolving it would let
a manifest cite coverage no document describes.

*It fails closed when a threat model is unavailable.* A missing or empty model
means the validator cannot tell whether an id is real. The safe answer is to
reject, not to accept every well-formed id — the same fail-closed rule the
runtime follows when a dependency is unavailable.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_validator():
    """Load tools/validate_slice.py, which ships as a script rather than a package."""
    path = REPO_ROOT / "tools" / "validate_slice.py"
    spec = importlib.util.spec_from_file_location("secondsign_validate_slice", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validator = _load_validator()


def _manifest(tmp_path: Path, threats: list[str]) -> Path:
    entry = {
        "id": "TEST-S001",
        "title": "A slice under test",
        "depends_on": [],
        "threats": threats,
        "scope": ["src/secondsign/**"],
        "acceptance": ["something a test can check"],
        "gates": ["pytest"],
        "stop_for_human": False,
    }
    path = tmp_path / "slice.yaml"
    path.write_text(yaml.safe_dump({"schema_version": 1, "slices": [entry]}), encoding="utf-8")
    return path


def _write_model(path: Path, ids: list[str]) -> None:
    body = "\n\n".join(f"### {threat}\n**A defect.**\n\n*Answer:* handled." for threat in ids)
    path.write_text(f"# Model\n\n{body}\n", encoding="utf-8")


@pytest.fixture
def models(tmp_path, monkeypatch):
    """Point the validator at throwaway threat models it can be tested against."""
    financial = tmp_path / "THREAT_MODEL.md"
    onchain = tmp_path / "ONCHAIN_THREAT_MODEL.md"
    _write_model(financial, ["A1", "A9"])
    _write_model(onchain, ["C1", "C11", "C14"])
    monkeypatch.setattr(
        validator,
        "THREAT_MODEL_SOURCES",
        {"A": financial, "B": financial, "C": onchain},
    )
    return {"financial": financial, "onchain": onchain}


def test_a_defined_onchain_threat_validates(models, tmp_path):
    assert validator.validate(_manifest(tmp_path, ["C11"])) == []


def test_a_defined_financial_threat_still_validates(models, tmp_path):
    assert validator.validate(_manifest(tmp_path, ["A9"])) == []


def test_an_undefined_onchain_threat_is_rejected(models, tmp_path):
    problems = validator.validate(_manifest(tmp_path, ["C7"]))
    assert problems, "an id the on-chain model does not define must not validate"
    assert "C7" in problems[0]


def test_an_out_of_range_number_is_rejected(models, tmp_path):
    assert validator.validate(_manifest(tmp_path, ["C143"])) != []


def test_a_misspelled_prefix_is_rejected(models, tmp_path):
    assert validator.validate(_manifest(tmp_path, ["D1"])) != []
    assert validator.validate(_manifest(tmp_path, ["c1"])) != []


def test_a_prefix_resolves_only_against_its_own_model(models, tmp_path):
    """C ids live in the on-chain model; an A id must not be satisfied by it."""
    assert validator.validate(_manifest(tmp_path, ["C1"])) == []
    assert validator.validate(_manifest(tmp_path, ["A11"])) != []


def test_a_missing_threat_model_fails_closed(models, tmp_path):
    models["onchain"].unlink()
    problems = validator.validate(_manifest(tmp_path, ["C11"]))
    assert problems, "a well-formed id must not be accepted when its model is gone"


def test_an_empty_threat_model_fails_closed(models, tmp_path):
    models["onchain"].write_text("# Model\n\nNo threats defined yet.\n", encoding="utf-8")
    problems = validator.validate(_manifest(tmp_path, ["C11"]))
    assert problems, "a model that defines nothing cannot license anything"


def test_the_onchain_gates_and_test_category_are_declarable():
    """CORE-S020 introduces a Solidity toolchain; manifests must be able to name it."""
    assert {"forge_fmt", "forge_test"} <= validator.KNOWN_GATES
    assert "onchain_topology" in validator.KNOWN_TEST_CATEGORIES


def test_the_deployment_topology_gate_and_category_are_declarable():
    """CORE-S019 introduces a containerised topology gate; manifests must name it.

    It is separate from `redteam` deliberately. A red-team case attacks the
    engine from inside the test process, which means it assumes the very
    environment the deployment gate exists to falsify — that the agent has no
    route to the rail. A category that conflated the two would let a slice claim
    topology coverage from a suite that never left the process.
    """
    assert "deployment_topology" in validator.KNOWN_GATES
    assert "deployment_topology" in validator.KNOWN_TEST_CATEGORIES


def test_an_unregistered_test_category_is_rejected(tmp_path):
    """The queue must not be able to cite a gate that does not run.

    This is the property that makes the registry worth having: a manifest naming
    `container_escape_proof` would otherwise validate, and the slice would read
    as covered by a suite nobody wrote.
    """
    manifest = tmp_path / "slice.yaml"
    manifest.write_text(
        "schema_version: 1\n"
        "slices:\n"
        "  - id: CORE-S999\n"
        "    title: A slice naming a category nobody registered\n"
        "    depends_on: []\n"
        "    threats: []\n"
        "    scope: ['docs/**']\n"
        "    forbidden: []\n"
        "    acceptance: ['it validates']\n"
        "    required_tests: [not_a_real_category]\n"
        "    gates: [pytest]\n"
        "    stop_for_human: false\n",
        encoding="utf-8",
    )

    problems = validator.validate(manifest)

    assert any("not_a_real_category" in problem for problem in problems)


def test_the_shipped_roadmap_validates():
    """The queue itself is the validator's first user."""
    assert validator.validate(REPO_ROOT / "docs" / "slices" / "roadmap.yaml") == []
