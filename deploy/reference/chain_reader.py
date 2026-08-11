# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""A live ChainStateReader backed by Foundry's ``cast`` (ONCHAIN-S008).

Deployment tooling, **not core**. Core defines the ``ChainStateReader`` protocol
and a deterministic double (ONCHAIN-S007); this is the live implementation a
deployment points at a Base RPC. It reads through ``cast`` — the Foundry tool the
on-chain workspace already requires — so it needs no Python RPC dependency, and it
lives in ``deploy/`` so core keeps its no-RPC, deterministic-kernel discipline
(ADR 0001 / 0006): the decision over the read state stays a pure function; the
reading is the deployment's.

What it reads, per the protocol:

- the Safe's ``nonce()``, ``getOwners()``, ``getThreshold()`` and ``VERSION()``
  through ``cast call``;
- both guards from their fixed storage slots (Safe 1.5.0's
  ``GUARD_STORAGE_SLOT`` and ``MODULE_GUARD_STORAGE_SLOT``) through
  ``cast storage`` — a getter would be absorbed by the fallback and read nothing
  (the S001 lesson);
- the chain id through ``cast chain-id``;
- a token proxy's implementation from a configured slot, and that
  implementation's code hash through ``cast code`` + ``cast keccak`` — because
  canonical USDC is a proxy, the identity bound is the resolved implementation
  (C4), not the proxy's own code.

A read that fails (RPC down, tooling absent) raises: reading is trusted
control-plane infrastructure, and a failure is an operational error for the
deployment to surface, not a silent value.
"""

import subprocess

from secondsign.onchain.chain_state import SafeChainState, TokenIdentity

#: Safe 1.5.0's guard storage slots — keccak256("guard_manager.guard.address") and
#: keccak256("module_manager.module_guard.address"), read from the source.
_GUARD_SLOT = "0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8"
_MODULE_GUARD_SLOT = "0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947"
#: The EIP-1967 implementation slot — the default for a standard proxy. A token
#: whose proxy uses another standard (USDC's FiatTokenProxy uses the Zeppelin
#: unstructured slot) is configured with its own slot.
_EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"


def _address_from_word(word: str) -> str:
    """The low 20 bytes of a 32-byte storage word, as a ``0x`` address (the zero
    address for an empty slot)."""
    body = word.removeprefix("0x").rjust(64, "0")
    return "0x" + body[-40:]


def _parse_addresses(rendered: str) -> tuple[str, ...]:
    """``cast``'s ``address[]`` rendering, e.g. ``[0xabc.., 0xdef..]``."""
    inner = rendered.strip().removeprefix("[").removesuffix("]").strip()
    if not inner:
        return ()
    return tuple(part.strip() for part in inner.split(","))


class CastChainStateReader:
    """Reads a Safe and a token's identity through ``cast``. Implements the core
    ``ChainStateReader`` protocol without core taking on any RPC dependency."""

    def __init__(
        self,
        rpc_url: str,
        *,
        cast_bin: str = "cast",
        implementation_slot: str = _EIP1967_IMPL_SLOT,
    ) -> None:
        self._rpc_url = rpc_url
        self._cast = cast_bin
        self._implementation_slot = implementation_slot

    def read_safe(self, safe_address: str) -> SafeChainState:
        return SafeChainState(
            nonce=int(self._call(safe_address, "nonce()(uint256)")),
            owners=_parse_addresses(self._call(safe_address, "getOwners()(address[])")),
            threshold=int(self._call(safe_address, "getThreshold()(uint256)")),
            transaction_guard=_address_from_word(self._storage(safe_address, _GUARD_SLOT)),
            module_guard=_address_from_word(self._storage(safe_address, _MODULE_GUARD_SLOT)),
            chain_id=int(self._rpc("chain-id")),
            safe_version=self._call(safe_address, "VERSION()(string)").strip('"'),
        )

    def token_identity(self, token_address: str) -> TokenIdentity:
        implementation = _address_from_word(self._storage(token_address, self._implementation_slot))
        code = self._rpc("code", implementation)
        return TokenIdentity(implementation=implementation, code_hash=self._run("keccak", code))

    # --- cast plumbing ---

    def _call(self, address: str, signature: str) -> str:
        return self._rpc("call", address, signature)

    def _storage(self, address: str, slot: str) -> str:
        return self._rpc("storage", address, slot)

    def _rpc(self, *args: str) -> str:
        """A ``cast`` subcommand that hits the chain (``--rpc-url`` appended)."""
        return self._run(*args, "--rpc-url", self._rpc_url)

    def _run(self, *args: str) -> str:
        completed = subprocess.run(  # noqa: S603 — resolved cast binary, fixed arguments
            [self._cast, *args],
            capture_output=True,
            text=True,
            check=True,
        )
        return completed.stdout.strip()
