# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""What the built artefact is, asserted against the built artefact.

ADR 0003's first constraint — `secondsign-client` depends on `pydantic` and
nothing else — is a property of the **wheel**, so it is read out of the wheel's
metadata rather than out of a requirements list someone keeps adjacent to the
truth. And the manifest's `ModuleNotFoundError` criterion is asserted by
**executing the import in a virtual environment that has only the client
installed** — not by inspecting a package list, because the claim is about what
a process in that environment can reach, and the only honest way to ask a
process what it can import is to have it try.

These cases build a wheel and a venv once per session. That is slower than the
rest of the suite and it is the acceptance criterion, verbatim; a faster proxy
would be a different claim.
"""

from __future__ import annotations

import subprocess
import sys
import venv
import zipfile
from email.parser import Parser
from pathlib import Path

import pytest

from tests.client.conftest import CLIENT_DIR

#: The five module families a client-only environment must not contain
#: (CORE-S019 acceptance). One term of no-bypass, never the boundary itself.
CONTROL_PLANE_MODULES = (
    "secondsign.gateway",
    "secondsign.rails",
    "secondsign.approval",
    "secondsign.audit",
    "secondsign.policy",
)


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory) -> Path:
    """The client wheel, built from `client/` exactly as a release would."""
    out = tmp_path_factory.mktemp("client-wheel")
    result = subprocess.run(  # noqa: S603 — fixed command, paths from this repo
        [sys.executable, "-m", "pip", "wheel", str(CLIENT_DIR), "--no-deps", "-w", str(out)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"could not build the client wheel:\n{result.stderr}"
    wheels = list(out.glob("secondsign_client-*.whl"))
    assert len(wheels) == 1, f"expected exactly one wheel, found {wheels}"
    return wheels[0]


@pytest.fixture(scope="module")
def client_only_venv(tmp_path_factory, built_wheel) -> Path:
    """A virtual environment holding the client wheel and its dependencies —
    which is to say, pydantic — and nothing else."""
    root = tmp_path_factory.mktemp("client-venv")
    venv.create(root, with_pip=True)
    python = root / ("Scripts" if sys.platform == "win32" else "bin") / "python"
    result = subprocess.run(  # noqa: S603 — fixed command, isolated venv
        [str(python), "-m", "pip", "install", "--quiet", str(built_wheel)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"could not install the client wheel:\n{result.stderr}"
    return python


def _wheel_metadata(wheel: Path) -> dict[str, list[str]]:
    with zipfile.ZipFile(wheel) as archive:
        name = next(n for n in archive.namelist() if n.endswith(".dist-info/METADATA"))
        message = Parser().parsestr(archive.read(name).decode())
    fields: dict[str, list[str]] = {}
    for key, value in message.items():
        fields.setdefault(key, []).append(value)
    return fields


class TestTheWheel:
    def test_it_declares_pydantic_and_nothing_else(self, built_wheel) -> None:
        """The constraint from ADR 0003, read from the artefact. If the client
        ever needs a fact the published outcome does not carry, that is a core
        change with a threat analysis — not a new dependency here."""
        requires = _wheel_metadata(built_wheel).get("Requires-Dist", [])

        bare_names = sorted(
            {entry.split(";")[0].split(" ")[0].split(">=")[0] for entry in requires}
        )
        assert bare_names == ["pydantic"], (
            f"the client wheel declares {requires!r}; pydantic alone is the contract"
        )

    def test_it_is_named_secondsign_client(self, built_wheel) -> None:
        assert _wheel_metadata(built_wheel)["Name"] == ["secondsign-client"]


class TestAClientOnlyEnvironment:
    """The traceback ADR 0003 shows, produced for real."""

    def test_the_client_imports(self, client_only_venv) -> None:
        result = subprocess.run(  # noqa: S603 — fixed command, isolated venv
            [str(client_only_venv), "-c", "import secondsign_client"],
            capture_output=True,
            text=True,
            check=False,
        )

        assert result.returncode == 0, f"the client itself does not import:\n{result.stderr}"

    @pytest.mark.parametrize("module", CONTROL_PLANE_MODULES)
    def test_the_control_plane_does_not(self, client_only_venv, module) -> None:
        """Asserted by executing the import and requiring ModuleNotFoundError —
        recorded as one term of no-bypass, never as the boundary itself."""
        probe = (
            "import sys\n"
            "try:\n"
            f"    import {module}\n"
            "except ModuleNotFoundError:\n"
            "    sys.exit(42)\n"
            "sys.exit(0)\n"
        )

        result = subprocess.run(  # noqa: S603 — fixed command, isolated venv
            [str(client_only_venv), "-c", probe],
            capture_output=True,
            text=True,
            check=False,
        )

        assert result.returncode == 42, (
            f"`import {module}` did not raise ModuleNotFoundError in a client-only "
            f"environment (exit={result.returncode}); the agent host is carrying code "
            "it must not hold"
        )

    def test_the_secondsign_namespace_does_not_exist_at_all(self, client_only_venv) -> None:
        """ADR 0003's traceback says `No module named 'secondsign'` — the client
        deliberately lives at `secondsign_client`, sharing no namespace with
        core, so installing it can never partially materialise `secondsign.*`."""
        probe = (
            "import sys\n"
            "try:\n"
            "    import secondsign\n"
            "except ModuleNotFoundError:\n"
            "    sys.exit(42)\n"
            "sys.exit(0)\n"
        )

        result = subprocess.run(  # noqa: S603 — fixed command, isolated venv
            [str(client_only_venv), "-c", probe],
            capture_output=True,
            text=True,
            check=False,
        )

        assert result.returncode == 42


class TestTheSourceReachesForNothing:
    """The wheel proves the declared dependencies; this proves the imports.

    A wheel that declares pydantic alone but whose source does `import
    secondsign` would fail at runtime on the agent host — later, quietly, in
    production. The AST is checked here so it fails now, loudly, in CI.
    """

    def test_no_client_module_imports_core_or_anything_beyond_stdlib_and_pydantic(self) -> None:
        import ast

        allowed_top_level = {"pydantic", "secondsign_client"}
        offences: list[str] = []
        for path in sorted((CLIENT_DIR / "src").rglob("*.py")):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    names = [node.module]
                for name in names:
                    top = name.split(".")[0]
                    if top in allowed_top_level or top in sys.stdlib_module_names:
                        continue
                    offences.append(f"{path.name}: {name}")

        assert offences == [], f"the client imports beyond its contract: {offences}"
