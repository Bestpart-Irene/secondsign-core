# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The sign-off gate's own guarantees.

The gate this replaces passed a pull request whose every commit was signed
`Elmar <твой_email@gmail.com>` — a template placeholder meaning *your_email*.
It looked for the shape of a certification and found one. That is the failure
these cases exist to keep fixed.

Two properties carry the weight:

*It fails on the things it claims to catch.* A gate that cannot fail is not a
gate, and this repository already applies that rule to its Solidity suite. The
placeholder that got through has its own case here, by name.

*It does not fail on the things it must not.* Dependabot certifies its commits
with an address it did not author them with, and a legitimate pass-along under
DCO 1.1 §(c) is signed by the committer rather than the author. Both are correct
and both would be broken by the obvious strict reading of "the sign-off must
match".
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _init_repo(path: Path) -> None:
    """A repository with one commit, owned by the test rather than the runner.

    `git` is resolved to an absolute path the way the checker resolves it, and
    the identity is set locally so the test does not depend on the machine
    having one configured.
    """
    executable = shutil.which("git")
    assert executable is not None, "git executable not found"
    for args in (
        ("init", "-q", "-b", "main"),
        ("config", "user.name", "Test Runner"),
        ("config", "user.email", "runner@secondsign.invalid"),
        ("commit", "-q", "--allow-empty", "-m", "root", "--no-gpg-sign"),
    ):
        subprocess.run(  # noqa: S603 — resolved executable, fixed arguments
            [executable, *args], cwd=path, check=True, capture_output=True
        )


def _load_checker():
    """Load tools/check_dco.py, which ships as a script rather than a package."""
    path = REPO_ROOT / "tools" / "check_dco.py"
    spec = importlib.util.spec_from_file_location("secondsign_check_dco", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = _load_checker()

AUTHOR = ("Ada Lovelace", "ada@example.dev")


def _commit(
    *,
    author: tuple[str, str] = AUTHOR,
    committer: tuple[str, str] | None = None,
    subject: str = "feat: a change",
    body: str = "",
) -> str:
    """The `%aN\\0%aE\\0%cN\\0%cE\\0%s\\0%b` record the checker parses."""
    committer = committer or author
    return "\x00".join([*author, *committer, subject, body])


def _signed(*trailers: tuple[str, str], **kwargs) -> str:
    body = "\n".join(f"Signed-off-by: {name} <{email}>" for name, email in trailers)
    return _commit(body=body, **kwargs)


class TestTheTrailerMustExist:
    def test_no_trailer_fails(self) -> None:
        problems = checker.check_commit("4f2a1c9", _commit())

        assert len(problems) == 1
        assert "no Signed-off-by line" in problems[0]

    def test_a_matching_trailer_passes(self) -> None:
        assert checker.check_commit("4f2a1c9", _signed(AUTHOR)) == []

    def test_the_trailer_is_case_insensitive(self) -> None:
        """Git writes `Signed-off-by`, people write other things."""
        record = _commit(body="signed-off-by: Ada Lovelace <ada@example.dev>")

        assert checker.check_commit("4f2a1c9", record) == []


class TestTheTrailerMustNameSomeoneReal:
    def test_the_placeholder_that_got_through_is_caught(self) -> None:
        """The case this whole gate exists for. Cyrillic for `your_email`."""
        record = _signed(
            ("Elmar", "твой_email@gmail.com"), author=("Elmar", "твой_email@gmail.com")
        )

        problems = checker.check_commit("4f2a1c9", record)

        assert len(problems) == 1
        assert "not an ASCII address" in problems[0]

    def test_a_reserved_example_domain_is_caught(self) -> None:
        """RFC 2606 reserves these so they can belong to nobody, ever."""
        signer = ("Ada Lovelace", "ada@example.com")

        problems = checker.check_commit("4f2a1c9", _signed(signer, author=signer))

        assert len(problems) == 1
        assert "reaches nobody" in problems[0]

    def test_a_template_local_part_is_caught(self) -> None:
        signer = ("Ada Lovelace", "your_email@gmail.com")

        problems = checker.check_commit("4f2a1c9", _signed(signer, author=signer))

        assert "placeholder" in problems[0]

    def test_something_that_is_not_an_address_is_caught(self) -> None:
        signer = ("Ada Lovelace", "ada")

        assert (
            "shaped like an address"
            in checker.check_commit("4f2a1c9", _signed(signer, author=signer))[0]
        )

    def test_an_ordinary_address_is_left_alone(self) -> None:
        """A gate that rejects real addresses teaches people to route around it."""
        for email in ("a@b.co", "first.last+tag@sub.domain.dev", "x_y-z@mail.gmail.com"):
            assert checker.address_problem(email) is None, email


class TestTheTrailerMustNameThisCommitsPerson:
    def test_a_stranger_fails(self) -> None:
        record = _signed(("Grace Hopper", "grace@example.dev"))

        problems = checker.check_commit("4f2a1c9", record)

        assert len(problems) == 1
        assert "has to name the person who made the commit" in problems[0]

    def test_the_committer_may_sign_for_the_author(self) -> None:
        """DCO 1.1 §(c): passing along work received from someone else.

        The author is the original person; the trailer belongs to whoever
        submitted it. Requiring the author's own trailer would forbid the one
        case the certificate explicitly provides for.
        """
        submitter = ("Grace Hopper", "grace@example.dev")
        record = _signed(submitter, author=AUTHOR, committer=submitter)

        assert checker.check_commit("4f2a1c9", record) == []

    def test_one_matching_trailer_among_several_is_enough(self) -> None:
        record = _signed(("Grace Hopper", "grace@example.dev"), AUTHOR)

        assert checker.check_commit("4f2a1c9", record) == []

    def test_case_and_spacing_do_not_make_a_stranger(self) -> None:
        record = _signed(("  ada lovelace ", "ADA@example.dev"))

        assert checker.check_commit("4f2a1c9", record) == []


class TestBots:
    def test_dependabot_signs_with_an_address_it_did_not_author_with(self) -> None:
        """Real values from this repository's history. Strict matching breaks it."""
        author = ("dependabot[bot]", "49699333+dependabot[bot]@users.noreply.github.com")
        record = _signed(("dependabot[bot]", "support@github.com"), author=author)

        assert checker.check_commit("4f2a1c9", record) == []

    def test_a_bot_still_needs_a_trailer(self) -> None:
        author = ("dependabot[bot]", "49699333+dependabot[bot]@users.noreply.github.com")

        assert checker.check_commit("4f2a1c9", _commit(author=author)) != []

    def test_a_bot_may_not_sign_with_a_placeholder(self) -> None:
        author = ("some[bot]", "some[bot]@users.noreply.github.com")
        record = _signed(("some[bot]", "bot@example.com"), author=author)

        assert "reaches nobody" in checker.check_commit("4f2a1c9", record)[0]

    def test_a_person_is_not_a_bot(self) -> None:
        assert not checker.is_bot("Botond Nagy", "botond@example.dev")


class TestTheRangeItReads:
    def test_no_range_and_no_environment_is_not_a_failure(self, monkeypatch, capsys) -> None:
        """Pushes are not pull requests, and the pull request is the gate."""
        monkeypatch.delenv("BASE_SHA", raising=False)
        monkeypatch.delenv("HEAD_SHA", raising=False)

        assert checker.main(["check_dco.py"]) == 0
        assert "skipping" in capsys.readouterr().out

    def test_an_empty_range_passes(self, capsys, monkeypatch, tmp_path) -> None:
        """A range with no commits is not a violation, and must not read as one.

        The repository it reads is built here rather than inherited from the
        working directory. Run inside an unpacked source distribution there is
        no `.git`, and this test then asserted the *next* case down — a range it
        cannot read — while still reporting itself as the empty-range one.
        """
        _init_repo(tmp_path)
        monkeypatch.chdir(tmp_path)

        assert checker.main(["check_dco.py", "HEAD..HEAD"]) == 0
        assert "ok" in capsys.readouterr().out

    def test_a_range_it_cannot_read_fails_rather_than_passes(self, capsys) -> None:
        """The fail-open this gate would otherwise have.

        A bad range, a shallow checkout, or the wrong working directory each
        yield no commits — and no commits reads as nothing to complain about.
        """
        assert checker.main(["check_dco.py", "no-such-ref..also-not-a-ref"]) == 1
        assert "cannot read" in capsys.readouterr().out

    def test_the_failure_prints_what_to_type(self, monkeypatch, capsys) -> None:
        """The reason this file exists at all is the message, not the verdict."""
        monkeypatch.setattr(
            checker, "git", lambda *args: (True, "4f2a1c9\x00" + _commit() + "\x01")
        )

        assert checker.main(["check_dco.py", "a..b"]) == 1
        output = capsys.readouterr().out
        assert "no Signed-off-by line" in output
        assert "git rebase origin/main --exec" in output
