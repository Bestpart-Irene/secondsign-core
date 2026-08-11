# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The live cast-backed ChainStateReader (ONCHAIN-S008).

Two layers. The **unit tests** mock ``cast`` and run in the default gate — they
pin the parsing and the exact reads (both guard *slots*, not getters; the resolved
token implementation; the code hash). The **live test** (`onchain_live`, deselected
by default) deploys a real Safe 1.5.0 on a local Anvil and proves the reader
produces a ``SafeChainState``/``TokenIdentity`` the co-signer's ``ExpectedSafeConfig``
accepts, and that a divergence is caught — it skips when the Foundry tooling is
absent, because the reader's logic is already covered by the mocked layer.
"""

import importlib.util
import shutil
import socket
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from secondsign.onchain.chain_state import ExpectedSafeConfig, SafeChainState, TokenIdentity
from secondsign.onchain.types import OnchainReasonCode

_READER_PATH = Path(__file__).parents[2] / "deploy" / "reference" / "chain_reader.py"


def _load_reader():
    spec = importlib.util.spec_from_file_location("chain_reader", _READER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_reader_mod = _load_reader()
CastChainStateReader = _reader_mod.CastChainStateReader

_SAFE = "0x2e234DAe75C793f67A35089C9d99245E1C58470b"
_OWNER_A = "0x1111111111111111111111111111111111111111"
_OWNER_B = "0x2222222222222222222222222222222222222222"
_ASSET = "0x3333333333333333333333333333333333333333"
_IMPL = "0x4444444444444444444444444444444444444444"
_CODE_HASH = "0x" + "ab" * 32
_ZERO = "0x" + "00" * 20


# --- unit layer: cast is mocked ---


def _word(address: str) -> str:
    return "0x" + address.removeprefix("0x").rjust(64, "0")


def _fake_cast(canned: dict[tuple[str, ...], str]):
    """A subprocess.run stand-in that answers cast invocations from a table keyed
    by the meaningful arguments (everything before --rpc-url)."""

    def run(args, capture_output, text, check):
        assert args[0] == "cast"
        key = tuple(a for a in args[1:] if a != "--rpc-url" and not a.startswith("http"))
        if key not in canned:
            raise AssertionError(f"unexpected cast call: {key}")
        return SimpleNamespace(stdout=canned[key] + "\n", returncode=0)

    return run


def _safe_table() -> dict[tuple[str, ...], str]:
    return {
        ("call", _SAFE, "nonce()(uint256)"): "7",
        ("call", _SAFE, "getOwners()(address[])"): f"[{_OWNER_A}, {_OWNER_B}]",
        ("call", _SAFE, "getThreshold()(uint256)"): "2",
        ("storage", _SAFE, _reader_mod._GUARD_SLOT): _ZERO,
        ("storage", _SAFE, _reader_mod._MODULE_GUARD_SLOT): _ZERO,
        ("chain-id",): "8453",
        ("call", _SAFE, "VERSION()(string)"): '"1.5.0"',
    }


def test_read_safe_parses_every_field(monkeypatch):
    monkeypatch.setattr(_reader_mod.subprocess, "run", _fake_cast(_safe_table()))
    reader = CastChainStateReader("http://localhost:8545")
    state = reader.read_safe(_SAFE)
    assert state == SafeChainState(
        nonce=7,
        owners=(_OWNER_A, _OWNER_B),
        threshold=2,
        transaction_guard=_ZERO,
        module_guard=_ZERO,
        chain_id=8453,
        safe_version="1.5.0",
    )


def test_read_safe_surfaces_an_installed_guard_from_its_slot(monkeypatch):
    guard = "0xc3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"
    table = _safe_table()
    table[("storage", _SAFE, _reader_mod._GUARD_SLOT)] = _word(guard)
    monkeypatch.setattr(_reader_mod.subprocess, "run", _fake_cast(table))
    state = CastChainStateReader("http://localhost:8545").read_safe(_SAFE)
    assert state.transaction_guard == guard


def test_token_identity_resolves_the_implementation_and_code_hash(monkeypatch):
    slot = _reader_mod._EIP1967_IMPL_SLOT
    table = {
        ("storage", _ASSET, slot): _word(_IMPL),
        ("code", _IMPL): "0x60806040",
        ("keccak", "0x60806040"): _CODE_HASH,
    }
    monkeypatch.setattr(_reader_mod.subprocess, "run", _fake_cast(table))
    identity = CastChainStateReader("http://localhost:8545").token_identity(_ASSET)
    assert identity == TokenIdentity(implementation=_IMPL, code_hash=_CODE_HASH)


def test_a_configured_token_slot_is_used(monkeypatch):
    # USDC's proxy uses a non-EIP-1967 slot; the reader is configured with it.
    slot = "0x0000000000000000000000000000000000000000000000000000000000000000"
    table = {
        ("storage", _ASSET, slot): _word(_IMPL),
        ("code", _IMPL): "0x00",
        ("keccak", "0x00"): _CODE_HASH,
    }
    monkeypatch.setattr(_reader_mod.subprocess, "run", _fake_cast(table))
    reader = CastChainStateReader("http://localhost:8545", implementation_slot=slot)
    assert reader.token_identity(_ASSET).implementation == _IMPL


def test_the_word_and_address_list_parsers():
    assert _reader_mod._address_from_word(_ZERO) == _ZERO
    assert _reader_mod._address_from_word(_word(_OWNER_A)) == _OWNER_A
    assert _reader_mod._parse_addresses("[]") == ()
    assert _reader_mod._parse_addresses(f"[{_OWNER_A}]") == (_OWNER_A,)
    assert _reader_mod._parse_addresses(f"[{_OWNER_A}, {_OWNER_B}]") == (_OWNER_A, _OWNER_B)


def test_a_read_failure_raises_rather_than_returning_a_silent_value(monkeypatch):
    def boom(args, capture_output, text, check):
        raise subprocess.CalledProcessError(1, args, stderr="rpc down")

    monkeypatch.setattr(_reader_mod.subprocess, "run", boom)
    with pytest.raises(subprocess.CalledProcessError):
        CastChainStateReader("http://localhost:8545").read_safe(_SAFE)


# --- live layer: a real Safe on a local Anvil ---

_TOOLS = ("anvil", "forge", "cast")
# Anvil's default account 0 — a public, unlocked dev address. Using `--unlocked`
# (Anvil signs) keeps any private key out of the repository entirely.
_ANVIL_ACCOUNT = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
_SAFE_PKG = "node_modules/@safe-global/safe-smart-account/contracts"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _resolve_tools() -> dict[str, str]:
    """The dev tools as absolute paths, or a skip. Resolving avoids a partial
    executable path — the same reason the deployment conftest resolves ``docker``."""
    resolved: dict[str, str] = {}
    for tool in _TOOLS:
        found = shutil.which(tool)
        if found is None:
            pytest.skip(f"{tool} not on PATH; the reader's logic is covered by the mocked tests")
        resolved[tool] = found
    return resolved


@pytest.fixture
def anvil_safe():
    tools = _resolve_tools()
    onchain = Path(__file__).parents[2] / "onchain"
    port = _free_port()
    rpc = f"http://127.0.0.1:{port}"
    anvil = subprocess.Popen(  # noqa: S603 — resolved anvil binary, fixed arguments
        [tools["anvil"], "--port", str(port), "--silent"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for_rpc(tools["cast"], rpc)
        singleton = _forge_create(tools["forge"], onchain, rpc, f"{_SAFE_PKG}/Safe.sol:Safe")
        proxy = _forge_create(
            tools["forge"],
            onchain,
            rpc,
            f"{_SAFE_PKG}/proxies/SafeProxy.sol:SafeProxy",
            [singleton],
        )
        subprocess.run(  # noqa: S603 — resolved cast binary, fixed arguments
            [
                tools["cast"],
                "send",
                proxy,
                "setup(address[],uint256,address,bytes,address,address,uint256,address)",
                f"[{_OWNER_A},{_OWNER_B}]",
                "2",
                _ZERO,
                "0x",
                _ZERO,
                _ZERO,
                "0",
                _ZERO,
                "--rpc-url",
                rpc,
                "--from",
                _ANVIL_ACCOUNT,
                "--unlocked",
            ],
            cwd=onchain,
            capture_output=True,
            text=True,
            check=True,
        )
        yield SimpleNamespace(rpc=rpc, safe=proxy, singleton=singleton, cast_bin=tools["cast"])
    finally:
        anvil.terminate()
        anvil.wait(timeout=10)


def _wait_for_rpc(cast_bin: str, rpc: str, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = subprocess.run(  # noqa: S603 — resolved cast binary, fixed arguments
            [cast_bin, "chain-id", "--rpc-url", rpc], capture_output=True, text=True
        )
        if result.returncode == 0:
            return
        time.sleep(0.2)
    raise RuntimeError("anvil did not become reachable")


def _forge_create(
    forge_bin: str, cwd: Path, rpc: str, contract: str, args: list[str] | None = None
) -> str:
    command = [forge_bin, "create", contract, "--rpc-url", rpc, "--from", _ANVIL_ACCOUNT]
    command += ["--unlocked", "--broadcast"]
    if args:
        command += ["--constructor-args", *args]
    out = subprocess.run(  # noqa: S603 — resolved forge binary, fixed arguments
        command, cwd=cwd, capture_output=True, text=True, check=True
    ).stdout
    for line in out.splitlines():
        if line.startswith("Deployed to:"):
            return line.split()[-1]
    raise RuntimeError(f"no deployment address in forge output:\n{out}")


@pytest.mark.onchain_live
def test_the_reader_reads_a_real_safe_and_catches_drift(anvil_safe):
    # The token proxy is a second SafeProxy: its implementation sits at slot 0.
    reader = CastChainStateReader(
        anvil_safe.rpc, cast_bin=anvil_safe.cast_bin, implementation_slot="0x0"
    )
    state = reader.read_safe(anvil_safe.safe)
    assert state.threshold == 2
    assert state.safe_version == "1.5.0"
    assert {o.lower() for o in state.owners} == {_OWNER_A, _OWNER_B}
    assert state.transaction_guard.lower() == _ZERO

    token = reader.token_identity(anvil_safe.safe)  # the proxy's impl is the singleton
    assert token.implementation.lower() == anvil_safe.singleton.lower()

    # An ExpectedSafeConfig built from what was read has no mismatch...
    expected = ExpectedSafeConfig(
        chain_id=state.chain_id,
        safe_version=state.safe_version,
        owners=frozenset(o.lower() for o in state.owners),
        threshold=state.threshold,
        transaction_guard=state.transaction_guard,
        module_guard=state.module_guard,
        token=anvil_safe.safe,
        token_identity=token,
    )
    assert expected.mismatches(state, token) == ()

    # ...and a divergence from it is caught against the real read state.
    drifted = expected.model_copy(update={"threshold": 3})
    assert OnchainReasonCode.structural_change in drifted.mismatches(state, token)
    moved = token.model_copy(update={"code_hash": "0x" + "ff" * 32})
    assert expected.mismatches(state, moved) == (OnchainReasonCode.implementation_moved,)
