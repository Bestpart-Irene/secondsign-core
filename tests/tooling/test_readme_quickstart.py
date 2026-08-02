# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The README quickstart is executable, and its claimed output is true.

The quickstart is the first code anyone runs, and until now it was verified by
nobody — a rename in `secondsign.policy` would have broken it on the front page
of the repository, and the project would have found out from a stranger.

The block is *extracted* from `README.md`, never copied here. A copy is a
second thing to keep in sync, and it would drift; what these cases execute is
whatever the README says today. The claimed output is read from the block's
own trailing comment for the same reason — the claim and the assertion must be
one fact, so editing either without the other fails loudly.
"""

from __future__ import annotations

import contextlib
import io
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
README = REPO_ROOT / "README.md"

DOCUMENTED_VERDICT = "DENY ['value_band_exceeded']"


def _first_python_block(markdown: str) -> str:
    """The first fenced ```python block, exactly as the reader would copy it."""
    match = re.search(r"^```python\n(.*?)^```", markdown, flags=re.DOTALL | re.MULTILINE)
    assert match is not None, "README.md no longer contains a ```python block"
    return match.group(1)


def _claimed_output(block: str) -> str:
    """The output the README promises, from the comment after the print call."""
    lines = [line.strip() for line in block.strip().splitlines()]
    last = lines[-1]
    assert last.startswith("# "), (
        "the quickstart's last line is expected to be a comment stating the "
        f"printed output, found: {last!r}"
    )
    return last.removeprefix("# ")


def _run(block: str) -> str:
    """Execute the block in a fresh namespace and return what it printed."""
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        exec(compile(block, str(README), "exec"), {"__name__": "__quickstart__"})  # noqa: S102 — executing our own README is the point of this test
    return stdout.getvalue()


class TestTheQuickstartRuns:
    def test_the_block_prints_what_the_readme_claims(self) -> None:
        block = _first_python_block(README.read_text(encoding="utf-8"))
        printed = _run(block).strip().splitlines()
        assert printed, "the quickstart printed nothing"
        assert printed[-1] == _claimed_output(block)

    def test_the_claim_is_the_documented_denial(self) -> None:
        """The verdict the README teaches first is a refusal, by design.

        If the claimed output ever changes, this states the old promise so the
        change is a decision rather than a drift.
        """
        block = _first_python_block(README.read_text(encoding="utf-8"))
        assert _claimed_output(block) == DOCUMENTED_VERDICT


class TestTheTestIsNotVacuous:
    """A test that cannot fail is not a test.

    The mutation drops the payment under the policy's limit, is verified to
    have taken effect, and must produce output the README's claim no longer
    matches — which is exactly the failure the real case would report.
    """

    def test_a_snippet_with_a_different_outcome_would_fail(self) -> None:
        block = _first_python_block(README.read_text(encoding="utf-8"))
        mutated = block.replace("amount_minor=250_000", "amount_minor=50_000")
        assert mutated != block, "the mutation did not take effect"
        printed = _run(mutated).strip().splitlines()
        assert printed[-1] != _claimed_output(block)
