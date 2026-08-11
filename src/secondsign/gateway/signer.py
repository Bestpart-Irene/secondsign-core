# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""The signing capability the co-signer holds — a provider contract, not a key.

Control-plane. The co-signer signs the Safe transaction hash through a
:class:`SignerProvider`: an address and a hash-signer, and nothing that yields the
key (ONCHAIN-S009, threat C11, ADR 0007). Core ships :class:`LocalSigner` as the
reference, using the optional ``eth_account``; a production KMS/HSM-backed provider
implements the same contract in the enterprise plane and is never pulled into core.

Extending INV-12 to the *form* of the key: a raw key in application config is a
key in memory, in a config store, and one log line from disclosure. Behind a
provider it can sit in an HSM, be rotated and versioned, and never be exported —
the contract has no method that returns it.
"""

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class SignerProvider(Protocol):
    """The signing capability, as a contract. Exactly an address and a hash-signer.

    A deployment implements it against a KMS/HSM; core ships :class:`LocalSigner`.
    The contract yields a signature and the signer's address, and nothing else —
    in particular, no way to read or export the key.
    """

    @property
    def address(self) -> str: ...

    def sign_hash(self, tx_hash: bytes) -> str: ...


def _load_account() -> Any:
    """The optional ``eth_account``, or a clear message pointing at the extra."""
    try:
        from eth_account import Account
    except ImportError as exc:  # pragma: no cover - the message is asserted, not the import
        raise RuntimeError(
            "local signing needs the optional dependency: pip install 'secondsign[onchain]'"
        ) from exc
    return Account


class LocalSigner:
    """The reference provider: an in-process key via ``eth_account``.

    The reference, not what a deployment runs — a production signer keeps the key
    in a KMS/HSM behind the same contract. It holds a key to sign locally, but
    exposes no way to read or export it: the public surface is ``address`` and
    ``sign_hash`` only.
    """

    def __init__(self, private_key: bytes) -> None:
        account_cls = _load_account()
        # Bound to a private attribute and never surfaced; the class exposes no
        # accessor that returns it.
        self.__account = account_cls.from_key(private_key)

    @property
    def address(self) -> str:
        return str(self.__account.address)

    def sign_hash(self, tx_hash: bytes) -> str:
        return "0x" + self.__account.unsafe_sign_hash(tx_hash).signature.hex()
