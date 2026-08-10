# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The experimental on-chain package must stay quarantined from v1.

Two properties keep the candidate surface from leaking into the frozen contract:
it is not re-exported from the top level, and nothing in v1 imports it. The
second is discovered by parsing every v1 source file, so a new module that
imports the on-chain package fails here rather than silently coupling the frozen
surface to an unfrozen one.
"""

import ast
import pathlib

import secondsign
import secondsign.contracts


def test_the_onchain_package_is_not_exported_from_the_top_level():
    assert not any("Onchain" in name for name in getattr(secondsign, "__all__", []))
    assert not hasattr(secondsign, "OnchainVerdict")
    # And it never enters the frozen v1 contract surface.
    assert not any("nchain" in name.lower() for name in secondsign.contracts.__all__)


def _imports_onchain(source: str) -> bool:
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if (node.module or "").startswith("secondsign.onchain"):
                return True
        elif isinstance(node, ast.Import):
            if any(alias.name.startswith("secondsign.onchain") for alias in node.names):
                return True
    return False


#: The deliberate on-chain *integration* modules — on-chain code placed
#: control-plane-side for key custody, whose whole purpose is to couple to the
#: on-chain package. An **explicit allowlist**, not a name-substring exemption: a
#: substring test (``"onchain" not in path.stem``) would silently exempt any
#: future ``contracts/onchain_fields.py`` or ``decision/onchain_limits.py`` and
#: let it couple the frozen surface to the unfrozen one with no CI signal. Every
#: entry here is a relative path under the package root, reviewed one by one.
_ONCHAIN_INTEGRATION_MODULES: frozenset[str] = frozenset(
    {
        "gateway/onchain_cosigner.py",
    }
)


def test_no_v1_module_imports_the_experimental_onchain_package():
    """No frozen fiat module may couple to the unfrozen on-chain surface.

    The concern is the frozen contract and the fiat decision path taking a
    dependency on types that may still be renamed. The on-chain package itself may
    import itself, and the reviewed integration modules in
    ``_ONCHAIN_INTEGRATION_MODULES`` may couple to it by design. Everything else
    stays decoupled, which is what the frozen surface needs.
    """
    root = pathlib.Path(secondsign.__file__).parent
    offenders = []
    for path in root.rglob("*.py"):
        relative = path.relative_to(root)
        if "onchain" in relative.parts[:-1]:
            continue  # the on-chain package itself may import itself
        if relative.as_posix() in _ONCHAIN_INTEGRATION_MODULES:
            continue  # a reviewed integration module, allowed by design
        if _imports_onchain(path.read_text(encoding="utf-8")):
            offenders.append(relative.as_posix())
    assert not offenders, (
        f"a frozen fiat module imports the experimental on-chain package: {offenders}"
    )


def test_the_onchain_deciding_module_is_control_plane():
    """The deciding half of the on-chain path is control plane, like fiat `policy`.

    An agent that could import the decision engine could answer its own judgement;
    the boundary vocabulary and adapter beside it stay shared.
    """
    from secondsign.isolation import Side, classify

    assert classify("secondsign.onchain.policy") is Side.control_plane
    assert classify("secondsign.onchain.types") is Side.shared
    assert classify("secondsign.onchain.effect") is Side.shared


def test_the_quarantine_exemption_is_an_allowlist_not_a_name_substring():
    """A future v1 module merely *named* onchain is not silently exempt.

    The earlier `"onchain" not in path.stem` test would have exempted a
    `contracts/onchain_fields.py` or `decision/onchain_limits.py` — coupling the
    frozen surface to the unfrozen one with no CI signal. Only the reviewed
    integration modules are exempt now.
    """
    import pathlib

    assert _ONCHAIN_INTEGRATION_MODULES == frozenset({"gateway/onchain_cosigner.py"})
    for hypothetical in ("contracts/onchain_fields.py", "decision/onchain_limits.py"):
        relative = pathlib.PurePosixPath(hypothetical)
        exempt = (
            "onchain" in relative.parts[:-1] or relative.as_posix() in _ONCHAIN_INTEGRATION_MODULES
        )
        assert not exempt, f"{hypothetical} must not be exempt from the quarantine"
